import subprocess
import json
import os
import yaml

class VulnScanner:
    def __init__(self, confidence_dir="plugins/confidence"):
        self.confidence_dir = confidence_dir
        self.rules = self._load_rules()

    def _load_rules(self):
        rules = []
        if not os.path.isdir(self.confidence_dir):
            return rules
        for fname in os.listdir(self.confidence_dir):
            if fname.endswith(".yaml") or fname.endswith(".yml"):
                with open(os.path.join(self.confidence_dir, fname)) as f:
                    rules.append(yaml.safe_load(f))
        return rules

    def scan(self, targets):
        if not targets:
            return []
        results = []
        for target in targets:
            cmd = ["nuclei", "-u", target, "-json", "-silent", "-severity", "critical,high"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if proc.returncode != 0:
                continue
            for line in proc.stdout.splitlines():
                try:
                    finding = json.loads(line)
                    finding["confidence"] = self._evaluate_confidence(finding)
                    results.append(finding)
                except json.JSONDecodeError:
                    pass
        return results

    def _evaluate_confidence(self, finding):
        for rule in self.rules:
            if self._match_rule(rule, finding):
                return rule.get("confidence", "medium")
        return "medium"

    def _match_rule(self, rule, finding):
        conditions = rule.get("match", {})
        for key, expected in conditions.items():
            value = finding.get(key)
            if key == "template-id" and expected not in value:
                return False
            if key == "status_code" and value != expected:
                return False
        return True
