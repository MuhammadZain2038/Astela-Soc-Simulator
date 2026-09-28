"""
astela_pipeline.py - end-to-end ASTELA pipeline: reads log lines, runs
Tier 1 (signature) and Tier 2 (behavioral) detection, scores alerts with
the LLM, and pushes the results to OpenSearch for the dashboard.

Repeat-offender tracking: every alert is recorded in Redis against the
source IP and the specific threat (malware family for Tier 1, MITRE rule
for Tier 2). The first alert for an IP + threat pair goes through the LLM
as normal and its scoring is cached. If the same IP triggers the same
threat again inside the tracking window, the LLM is skipped, the cached
scoring is reused, and a fixed escalation message carrying the offense
count replaces the recommendation.
"""

import os
import json
import time
import uuid
import redis
from urllib.parse import urlparse
from dotenv import load_dotenv
from opensearchpy import OpenSearch
from tier1_bouncer import Tier1Bouncer
from tier2_csp import Tier2DeepInspector

from ai_scoring import score_log_with_llm

load_dotenv()

# Repeat-offender tracking settings. It uses its own Redis database (not
# db 0) so these short-lived keys never mix with the threat-intel data that
# sync_threat_intel.py manages and verifies in db 0.
REPEAT_REDIS_DB = int(os.getenv("REPEAT_REDIS_DB", 1))
REPEAT_TTL_SECONDS = int(os.getenv("REPEAT_TTL_SECONDS", 3600))
REPEAT_RESET_ON_START = os.getenv("REPEAT_RESET_ON_START", "false").strip().lower() == "true"
REPEAT_KEY_PREFIX = "offense"

# Same variables the launcher reads, so changing a port in .env applies to
# the whole stack and not just the launcher.
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://localhost:9200")
REDIS_PORT = int(os.getenv("REDIS_DOCKER_PORT", "6379"))


def setup_opensearch():
    print("[*] Connecting to OpenSearch...")
    parsed = urlparse(OPENSEARCH_URL)
    # No credentials are sent: the compose file runs OpenSearch with the
    # security plugin disabled, so there is nothing to authenticate against.
    client = OpenSearch(
        hosts=[{'host': parsed.hostname or 'localhost', 'port': parsed.port or 9200}],
        use_ssl=(parsed.scheme == "https"),
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False
    )
    return client


def push_to_dashboard(os_client, ai_summary, detection_info):
    document = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ai_summary": ai_summary,
        "detection": detection_info
    }
    try:
        response = os_client.index(
            index="logs",
            body=document,
            refresh=True
        )
        print(f"   [+] Successfully pushed to OpenSearch Dashboard! (Doc ID: {response['_id']})")
    except Exception as e:
        print(f"   [-] Failed to push to OpenSearch: {e}")


def extract_family(reason: str) -> str:
    if not reason:
        return "Unknown Threat"

    # Extract if formatted string exists
    if "Family:" in reason:
        try:
            family = reason.split("Family:")[1].split("|")[0].strip()
        except:
            family = reason
    else:
        family = reason.strip()

    # Normalize bad values
    if not family or family.lower() in ["n/a", "na", "none", "unknown", "-"]:
        return "Unknown Threat"

    return family


# ---------------------------------------------------------------------
# REPEAT-OFFENDER TRACKING
# ---------------------------------------------------------------------
def _utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _format_duration(seconds):
    if seconds % 3600 == 0:
        hours = seconds // 3600
        return f"{hours} hour{'s' if hours != 1 else ''}"
    if seconds % 60 == 0:
        minutes = seconds // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    return f"{seconds} seconds"


def setup_repeat_tracker():
    """Connects to the Redis database used for repeat-offender tracking.
    Returns None if Redis is unavailable, in which case the pipeline runs
    exactly as it did before, with every alert going through the LLM."""
    try:
        client = redis.Redis(host="localhost", port=REDIS_PORT, db=REPEAT_REDIS_DB, decode_responses=True)
        client.ping()

        if REPEAT_RESET_ON_START:
            removed = 0
            for key in client.scan_iter(match=f"{REPEAT_KEY_PREFIX}:*"):
                client.delete(key)
                removed += 1
            print(f"[*] Cleared {removed} repeat-offender record(s) from a previous run.")
    except Exception as e:
        print(f"[-] Repeat-offender tracking disabled, Redis unavailable: {e}")
        return None

    print(f"[+] Repeat-offender tracking enabled "
          f"(window: {_format_duration(REPEAT_TTL_SECONDS)}, Redis db {REPEAT_REDIS_DB}).")
    return client


def _valid_ip(ip):
    return bool(ip) and str(ip).strip().lower() not in ("-", "n/a", "unknown", "unknown ip")


def record_offense(tracker, ip, threat):
    """Records one offense for this IP + threat pair and returns
    {"key", "count", "first_seen", "cached"}, or None if tracking is
    unavailable or the alert has no usable IP or threat name.

    Each pair is one Redis hash (count, first_seen, last_seen, summary).
    The TTL restarts on every offense, so an IP that keeps attacking stays
    tracked, and one that goes quiet for the full window starts over.
    Any Redis error returns None so the alert simply takes the normal path."""
    if tracker is None or not _valid_ip(ip) or not threat:
        return None

    key = f"{REPEAT_KEY_PREFIX}:{str(ip).strip().lower()}:{str(threat).strip().lower()}"
    now = _utc_now()

    try:
        pipe = tracker.pipeline()
        pipe.hincrby(key, "count", 1)
        pipe.hsetnx(key, "first_seen", now)
        pipe.hset(key, "last_seen", now)
        pipe.expire(key, REPEAT_TTL_SECONDS)
        pipe.hmget(key, "first_seen", "summary")
        results = pipe.execute()

        first_seen, summary_json = results[4]
        return {
            "key": key,
            "count": int(results[0]),
            "first_seen": first_seen,
            "cached": json.loads(summary_json) if summary_json else None,
        }
    except Exception as e:
        print(f"   [-] Repeat tracking error (continuing normally): {e}")
        return None


def cache_summary(tracker, offense, ai_summary):
    """Stores the LLM scoring from the first alert so repeats can reuse it.
    Scoring failures are never cached, so a temporary API error cannot turn
    into a permanent bad answer for that IP + threat pair."""
    if tracker is None or offense is None or not isinstance(ai_summary, dict):
        return
    if ai_summary.get("malware_family") == "Scoring Error":
        return

    try:
        tracker.hset(offense["key"], "summary", json.dumps(ai_summary))
    except Exception as e:
        print(f"   [-] Could not cache scoring (continuing normally): {e}")


def build_repeat_message(ip, threat, count, first_seen, original):
    """Fixed escalation text, no LLM involved. The wording escalates with
    the offense count: repeat (2), persistent (3-4), sustained (5+)."""
    window = _format_duration(REPEAT_TTL_SECONDS)
    header = (f"Offense #{count}: source IP {ip} has triggered '{threat}' "
              f"{count} times inside the {window} tracking window (first seen {first_seen}).")

    if count >= 5:
        action = ("This is a sustained campaign. Block this IP at the firewall or WAF now, "
                  "hunt for persistence on every system it reached, and consider reporting "
                  "it to the network owner.")
    elif count >= 3:
        action = ("This is persistent, deliberate activity. Block this IP at the firewall or WAF, "
                  "confirm the original remediation was actually applied, and review everything "
                  "else this IP has touched.")
    else:
        action = ("The same attack from the same source is not a coincidence. Apply the original "
                  "remediation and block this IP at the firewall or WAF so it cannot reach the "
                  "system again.")

    message = f"{header} {action}"
    if original:
        message += f" Original guidance for this threat: {original}"
    return message


def build_repeat_summary(offense, ip, threat, name, file_hash):
    """Builds the ai_summary for a repeat alert. Family, type and threat
    score come from the cached first-alert scoring; only the target, hash,
    source IP and recommendation are replaced."""
    summary = dict(offense["cached"])
    summary["name"] = name
    summary["file_hash"] = file_hash
    summary["src_ip"] = ip
    summary["recommendation"] = build_repeat_message(
        ip, threat, offense["count"], offense["first_seen"],
        offense["cached"].get("recommendation", "")
    )
    return summary


def _behavior_target(matched_logs, fallback="unknown_target"):
    """Unique action names from the logs that tripped a Tier 2 rule."""
    actions = []
    for entry in matched_logs:
        action = entry.get("action")
        if action and action not in actions:
            actions.append(action)
    return ", ".join(actions) if actions else fallback


def main():
    print("="*60)
    print("   ASTELA: Full End-to-End Pipeline Initializing")
    print("="*60)

    bouncer = Tier1Bouncer()
    inspector = Tier2DeepInspector()
    os_client = setup_opensearch()
    tracker = setup_repeat_tracker()

    # This file lives at logparser/pipeline/, and sample_logs.txt lives at
    # logparser/tests/ - one level up, then into tests/. Resolved relative
    # to this file so it works regardless of the working directory the
    # pipeline is launched from.
    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_file_path = os.path.join(base_dir, '..', 'tests', 'sample_logs.txt')
    print(f"[*] Opening log stream from: {log_file_path}\n")

    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                clean_line = line.strip()
                if not clean_line:
                    continue

                parts = clean_line.split(" ")
                if len(parts) < 3:
                    continue

                log = {
                    "timestamp": f"{parts[0]} {parts[1]}",
                    "event_type": parts[2],
                    "log_id": str(uuid.uuid4())[:8]
                }

                for item in parts[3:]:
                    if "=" in item:
                        k, v = item.split("=", 1)
                        log[k] = v

                print(f"[>] Ingesting Log ID: {log['log_id']} | Action: {log.get('action', 'Unknown')}")

                # ---------------- TIER 1 ----------------
                t1_result = bouncer.check_log(log, clean_line)

                if t1_result["status"] == "ALERT":
                    print(f"   [!!!] TIER 1 ALERT CAUGHT: {t1_result['reason']}")

                    clean_family = extract_family(t1_result["reason"])

                    enrichment_data = {
                        "hash": {
                            "malware_family": clean_family,
                            "intel_source": t1_result.get('source', 'Tier 1 Engine')
                        },
                        "ip": {}
                    }

                    t1_result["log"]["malware_family"] = clean_family

                    detection_info = {
                        "tier": 1,
                        "type": "signature",
                        "reason": t1_result['reason'],
                        "source": t1_result.get('source', 'Unknown')
                    }

                    # Unidentified threats are not tracked: unrelated unknown
                    # detections would otherwise be merged under one name.
                    src_ip = log.get("src_ip")
                    threat_id = None if clean_family == "Unknown Threat" else clean_family
                    offense = record_offense(tracker, src_ip, threat_id)

                    if offense and offense["count"] >= 2 and offense["cached"]:
                        print(f"   [!] REPEAT OFFENDER: {src_ip} triggered '{threat_id}' again "
                              f"(offense #{offense['count']}). Reusing cached scoring, skipping LLM.")

                        ai_summary = build_repeat_summary(
                            offense, src_ip, threat_id,
                            name=log.get("file_name") or log.get("user") or "unknown_target",
                            file_hash=log.get("file_hash") or "-"
                        )
                        detection_info["repeat"] = True
                        detection_info["offense_count"] = offense["count"]

                        push_to_dashboard(os_client, ai_summary, detection_info)
                        continue

                    print("   [*] Pushing log and Threat Intel data to DeepSeek LLM for summary...")
                    ai_summary = score_log_with_llm(
                        log_entry=t1_result["log"],
                        enrichment=enrichment_data
                    )

                    if offense:
                        cache_summary(tracker, offense, ai_summary)
                        detection_info["repeat"] = offense["count"] >= 2
                        detection_info["offense_count"] = offense["count"]

                    push_to_dashboard(os_client, ai_summary, detection_info)

                    time.sleep(2)
                    continue

                # ---------------- TIER 2 ----------------
                print("   [-] Tier 1 Clean. Passing to Tier 2 AI Engine...")
                t2_result = inspector.add_log_and_evaluate(log)

                if t2_result["status"] == "BEHAVIOR_ALERT":
                    print(f"   [!!!] TIER 2 BEHAVIOR CAUGHT: {t2_result['reason']}")

                    src_ip = log.get("src_ip")
                    offense = record_offense(tracker, src_ip, t2_result["reason"])

                    # Attach the actual matched raw log lines that triggered
                    # this MITRE rule as evidence, so the dashboard's "Attack
                    # Evidence" panel has something real to show. Strip the
                    # internal "_ingest_time" field tier2_csp.py adds, since
                    # it is an epoch float used only for its own time-window
                    # math, not something useful to show as proof.
                    evidence_logs = [
                        {k: v for k, v in matched_log.items() if k != "_ingest_time"}
                        for matched_log in t2_result.get("logs", [])
                    ]

                    detection_info = {
                        "tier": 2,
                        "type": "behavior",
                        "reason": t2_result['reason'],
                        "evidence": evidence_logs
                    }

                    if offense and offense["count"] >= 2 and offense["cached"]:
                        print(f"   [!] REPEAT OFFENDER: {src_ip} triggered '{t2_result['reason']}' again "
                              f"(offense #{offense['count']}). Reusing cached scoring, skipping LLM.")

                        ai_summary = build_repeat_summary(
                            offense, src_ip, t2_result["reason"],
                            name=_behavior_target(
                                t2_result.get("logs", []),
                                fallback=offense["cached"].get("name", "unknown_target")
                            ),
                            file_hash="-"
                        )
                        detection_info["repeat"] = True
                        detection_info["offense_count"] = offense["count"]

                        push_to_dashboard(os_client, ai_summary, detection_info)
                    else:
                        print("   [*] Pushing validated threat sequence to DeepSeek LLM...")

                        behavioral_log_bundle = {
                            "behavioral_sequence": t2_result["logs"],
                            "attack_type": t2_result['reason'],
                            "src_ip": log.get("src_ip", "Unknown IP")
                        }

                        enrichment_data = {
                            "ip": {
                                "malware_family": f"Tier 2 Behavioral Flag ({t2_result['reason']})",
                                "intel_score": 9.0
                            }
                        }

                        ai_summary = score_log_with_llm(
                            log_entry=behavioral_log_bundle,
                            enrichment=enrichment_data
                        )

                        if offense:
                            cache_summary(tracker, offense, ai_summary)
                            detection_info["repeat"] = offense["count"] >= 2
                            detection_info["offense_count"] = offense["count"]

                        push_to_dashboard(os_client, ai_summary, detection_info)

                print("-" * 50)
                time.sleep(1)

    except FileNotFoundError:
        print(f"[!] Error: Could not find {log_file_path}.")


if __name__ == "__main__":
    main()