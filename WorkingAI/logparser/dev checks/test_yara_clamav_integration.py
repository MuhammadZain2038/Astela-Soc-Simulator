"""
test_yara_clamav_integration.py - standalone check that the YARA and
ClamAV engines tier1_bouncer.py relies on are working, independent of
Redis, the pipeline, or any log file.

This file is expected to sit at the same depth as tier1_bouncer.py
(e.g. logparser/pipeline/), since it resolves yara_rules/ the same way:
two levels up, alongside logparser/. Move this file and update
rules_path if that changes.

Run it directly: python test_yara_clamav_integration.py
"""

import os
import yara
import pyclamd
from dotenv import load_dotenv

load_dotenv()

CLAMD_PORT = int(os.getenv("CLAMD_DOCKER_PORT", "3310"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
YARA_RULES_PATH = os.path.join(BASE_DIR, "..", "..", "yara_rules", "malicious_rules.yar")

# One EICAR string and one line that should trip a basic YARA rule.
# EICAR is a standard, harmless test string every antivirus engine
# recognizes - it is not real malware.
TEST_LOGS = [
    "GET /evil HTTP/1.1",
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
]


def yara_scan(rules, text):
    matches = rules.match(data=text)
    if matches:
        return True, matches[0].rule
    return False, None


def clamav_scan(client, text):
    result = client.scan_stream(text.encode())
    if result:
        # result looks like: {"stream": ("FOUND", "Eicar-Test-Signature")}
        family = list(result.values())[0][1]
        return True, family
    return False, None


def main():
    try:
        rules = yara.compile(filepath=YARA_RULES_PATH)
        print(f"[+] Loaded YARA rules from {YARA_RULES_PATH}")
    except Exception as e:
        print(f"[!] Could not load YARA rules: {e}")
        rules = None

    try:
        clamav_client = pyclamd.ClamdNetworkSocket(host="127.0.0.1", port=CLAMD_PORT)
        clamav_client.ping()
        print(f"[+] Connected to ClamAV on port {CLAMD_PORT}")
    except Exception as e:
        print(f"[!] Could not connect to ClamAV: {e}")
        clamav_client = None

    for log in TEST_LOGS:
        hit, family = (False, None)

        if rules:
            hit, family = yara_scan(rules, log)

        if not hit and clamav_client:
            hit, family = clamav_scan(clamav_client, log)

        print(f"Log: {log[:50]}...")
        print(f"Signature Hit: {hit}, Malware Family: {family}\n")


if __name__ == "__main__":
    main()