import time
import json
import os
from collections import defaultdict

class Tier2DeepInspector:
    def __init__(self):
        print("[*] Initializing Tier 2 CSP Engine (Behavioral Analysis)...")
        self.memory = defaultdict(list)
        self.rules = self._load_rules()
        # Tracks the last time each (rule_name, entity_key) pair fired, so a
        # single ongoing incident (e.g. one 20-event upload burst) doesn't
        # re-alert every time it crosses the threshold again — see the
        # cooldown check in add_log_and_evaluate().
        self.last_alert_time = {}

    def _load_rules(self):
        # This file lives at logparser/pipeline/, and csp_rules.json lives
        # at WorkingAI/csp_rules/csp_rules.json — two levels up, then into
        # the csp_rules folder.
        base_dir = os.path.dirname(os.path.abspath(__file__))
        rule_path = os.path.join(base_dir, '..', '..', 'csp_rules', 'csp_rules.json')
        try:
            with open(rule_path, 'r') as f:
                rules = json.load(f)
                print(f"[+] Loaded {len(rules)} behavioral CSP rules.")
                return rules
        except FileNotFoundError:
            print(f"[-] Warning: csp_rules.json not found at {rule_path}. Tier 2 will have no behavioral constraints.")
            return {}

    def _clean_old_logs(self, current_time):
        """Removes logs older than the maximum time window across all rules to save RAM."""
        max_window = max([rule.get("time_window_seconds", 300) for rule in self.rules.values()] + [0])
        for entity, logs in self.memory.items():
            self.memory[entity] = [log for log in logs if (current_time - log.get("_ingest_time", current_time)) <= max_window]

    def add_log_and_evaluate(self, log_entry):
        # Add an internal timestamp to track the time window
        current_time = time.time()
        log_entry["_ingest_time"] = current_time
        
        action = log_entry.get("action")
        src_ip = log_entry.get("src_ip")
        user = log_entry.get("user")
        
        if not action:
            return {"status": "CLEAN"}

        # Track by both IP and User independently
        if src_ip: self.memory[f"ip:{src_ip}"].append(log_entry)
        if user: self.memory[f"user:{user}"].append(log_entry)

        self._clean_old_logs(current_time)

        # Evaluate CSP Rules
        for rule_name, rule in self.rules.items():
            target_field = rule["target_field"]
            entity_val = log_entry.get(target_field)
            
            if not entity_val:
                continue
                
            entity_key = f"{'ip' if target_field == 'src_ip' else 'user'}:{entity_val}"
            entity_logs = self.memory.get(entity_key, [])
            
            # Constraint 1: Does the sequence match?
            matching_logs = [l for l in entity_logs if l.get("action") in rule["sequence"]]
            
            # Constraint 2 & 3: Does it meet the threshold within the time window?
            # Every action listed in the rule's sequence must also be present,
            # so e.g. two "download" events alone cannot satisfy a rule that
            # needs "email_click" followed by "download". This checks presence
            # only, not order.
            seen_actions = {l.get("action") for l in matching_logs}
            if len(matching_logs) >= rule["threshold"] and set(rule["sequence"]) <= seen_actions:
                cooldown_key = (rule_name, entity_key)
                window = rule.get("time_window_seconds", 300)
                last_fired = self.last_alert_time.get(cooldown_key, 0)

                if current_time - last_fired < window:
                    # This rule already fired for this exact entity within
                    # its own time window — this is continued activity from
                    # the same ongoing incident (e.g. upload #7 of a 20-file
                    # exfil burst), not a new one. Clear the matched logs so
                    # they don't pile up, but don't alert again.
                    self.memory[entity_key] = []
                    continue

                # Clear memory for this entity to prevent duplicate alerts
                self.memory[entity_key] = []
                self.last_alert_time[cooldown_key] = current_time

                return {
                    "status": "BEHAVIOR_ALERT",
                    "reason": f"MITRE {rule['mitre_id']} - {rule_name}",
                    "logs": matching_logs
                }

        return {"status": "CLEAN"}