import os
import redis
import requests
import yara
import pyclamd
from dotenv import load_dotenv

load_dotenv()
MALWARE_BAZAAR_KEY = os.getenv("MALWARE_BAZAAR_KEY")

class Tier1Bouncer:
    def __init__(self):
        print("[*] Initializing Tier 1 Bouncer...")
        # 1. Connect to local Redis
        try:
            self.r = redis.Redis(host='localhost', port=int(os.getenv('REDIS_DOCKER_PORT', '6379')), db=0, decode_responses=True)
            self.r.ping()
            print("[+] Redis connected. Fast-path cache enabled.")
        except redis.ConnectionError:
            self.r = None
            print("[-] Redis not found, skipping fast-path cache.")
        
        # 2. Connect to ClamAV Daemon
        try:
            self.cd = pyclamd.ClamdNetworkSocket(port=int(os.getenv('CLAMD_DOCKER_PORT', '3310')))
            if self.cd.ping():
                print("[+] ClamAV connected successfully.")
                self.use_clamav = True
            else:
                self.use_clamav = False
        except Exception as e:
            print(f"[-] ClamAV not responding: {e}")
            self.use_clamav = False

        # 3. Load YARA rules — resolved relative to this file, not the
        # working directory, so this works no matter where the pipeline
        # is launched from. This file lives at logparser/pipeline/, and
        # yara_rules/ sits two levels up, alongside logparser/.
        base_dir = os.path.dirname(os.path.abspath(__file__))
        yara_rules_path = os.path.join(base_dir, '..', '..', 'yara_rules', 'malicious_rules.yar')
        try:
            self.yara_rules = yara.compile(filepath=yara_rules_path)
            print(f"[+] Loaded YARA rules from {yara_rules_path}")
        except Exception as e:
            print(f"[!] Warning: Could not load YARA rules. Error: {e}")
            self.yara_rules = None

    def query_malwarebazaar(self, file_hash):
        """Fallback API query when the hash is NOT in our local Redis."""
        url = "https://mb-api.abuse.ch/api/v1/"
        payload = {'query': 'get_info', 'hash': file_hash}
        
        try:
            # MalwareBazaar requires an Auth-Key header. If no key is
            # configured, send the request without one, as before.
            headers = {"Auth-Key": MALWARE_BAZAAR_KEY} if MALWARE_BAZAAR_KEY else {}
            response = requests.post(url, data=payload, headers=headers, timeout=10)
            if response.status_code == 200:
                json_data = response.json()
                
                if json_data.get('query_status') == 'hash_found':
                    data = json_data.get('data', [{}])[0]
                    
                    signature = data.get('signature')
                    reporter = data.get('reporter')
                    
                    # Pick the best family name available
                    family = signature if signature and signature != "n/a" else data.get('file_type_guess')
                    if not family or family == "n/a":
                        family = "Unknown_Malware"

                    # Strictly return strings, never None
                    return {
                        "family": str(family),
                        "reporter": str(reporter) if reporter else "api_fallback"
                    }

        except Exception as e:
            print(f"[!] API Fallback Error: {e}")
            
        return None

    def check_log(self, log_entry, raw_text=""):
        file_hash = log_entry.get("file_hash")

        if file_hash:
            clean_hash = str(file_hash).strip().lower()
            
            # Hash is wrapped in literal quotes to match the Redis schema
            redis_key = f'malware:"{clean_hash}"'

            # ==========================================
            # PHASE 1: REDIS FAST-PATH
            # ==========================================
            if self.r:
                data = self.r.hgetall(redis_key)

                if data:
                    # Strip the literal quotes off the returned database values
                    family = data.get("family", "Unknown_Family").replace('"', '')
                    reporter = data.get("reporter", "Unknown_Reporter").replace('"', '')

                    print(f"[+] CACHE HIT: {clean_hash[:8]}... | Family: {family} | Reporter: {reporter}")

                    return {
                        "status": "ALERT", 
                        "source": "Local Redis Intel",
                        "reason": f"Known Malware -> Family: {family} | Reporter: {reporter}", 
                        "log": log_entry
                    }

            # ==========================================
            # PHASE 2: EXTERNAL API FALLBACK
            # ==========================================
            print(f"[*] Cache Miss. Querying External API for {clean_hash[:8]}...")
            api_result = self.query_malwarebazaar(clean_hash)
            
            if api_result:
                print(f"[+] API HIT: MalwareBazaar identified hash as {api_result['family']}")
                
                if self.r:
                    # Write back using the same schema as sync_threat_intel.py
                    # (literal quotes around every value), and update all three
                    # structures in one pipeline so the sync script's
                    # consistency check stays accurate after an API hit.
                    try:
                        quoted_hash = f'"{clean_hash}"'
                        quoted_family = f'"{api_result["family"]}"'
                        pipe = self.r.pipeline()
                        pipe.sadd("malware:hashes", quoted_hash)
                        pipe.hset(redis_key, mapping={
                            "family": quoted_family,
                            "reporter": f'"{api_result["reporter"]}"'
                        })
                        pipe.hset("known_bad_hashes", quoted_hash, quoted_family)
                        pipe.execute()
                        print(f"[*] Saved new threat to Redis: {clean_hash[:8]}...")
                    except redis.RedisError as e:
                        # The alert is still valid; only the local cache write failed.
                        print(f"[!] Could not save API result to Redis: {e}")

                return {
                    "status": "ALERT", 
                    "source": "External API (MalwareBazaar)",
                    "reason": f"Known Malware -> Family: {api_result['family']} | Reporter: {api_result['reporter']}", 
                    "log": log_entry
                }

        # ==========================================
        # PHASE 3: STATIC ANALYSIS
        # ==========================================
        if getattr(self, 'yara_rules', None):
            matches = self.yara_rules.match(data=raw_text)
            if matches:
                return {
                    "status": "ALERT",
                    "source": "YARA Engine",
                    "reason": f"Rule Match: {matches[0].rule}",
                    "log": log_entry
                }

        if getattr(self, 'use_clamav', False) and getattr(self, 'cd', None):
            result = self.cd.scan_stream(raw_text.encode())
            if result:
                family = list(result.values())[0][1]
                return {
                    "status": "ALERT",
                    "source": "ClamAV Engine",
                    "reason": f"Signature: {family}",
                    "log": log_entry
                }

        return {"status": "CLEAN", "log": log_entry}