import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RULES_DIR = Path(__file__).parent / "rules"


class DetectionRule:
    def __init__(self, data: dict):
        self.rule_id: str = data["rule_id"]
        self.name: str = data["name"]
        self.severity: str = data["severity"]
        self.mitre_technique: str = data.get("mitre_technique", "")
        self.mitre_tactic: str = data.get("mitre_tactic", "")
        self.pattern: dict = data["pattern"]
        self.score: float = data["score"]

    def matches(self, log_data: dict, context: dict | None = None) -> bool:
        for field, matcher in self.pattern.items():
            if isinstance(matcher, str):
                if log_data.get(field) != matcher:
                    return False
            elif isinstance(matcher, dict):
                if not self._match_complex(field, matcher, log_data, context):
                    return False
            else:
                return False
        return True

    def _match_complex(self, field: str, matcher: dict, log_data: dict, context: dict | None) -> bool:
        if "min" in matcher:
            val = (context or {}).get(field, log_data.get(field, 0))
            try:
                return float(val) >= float(matcher["min"])
            except (TypeError, ValueError):
                return False

        if "contains" in matcher:
            val = str(log_data.get(field, ""))
            for substr in matcher["contains"]:
                if substr in val:
                    return True
            return False

        if "suspicious_tlds" in matcher:
            domain = str(log_data.get(field, ""))
            for tld in matcher["suspicious_tlds"]:
                if domain.endswith(tld):
                    return True
            return False

        if "regex" in matcher:
            val = str(log_data.get(field, ""))
            try:
                return bool(re.search(matcher["regex"], val))
            except re.error:
                return False

        return True


class DetectionEngine:
    def __init__(self):
        self.rules: list[DetectionRule] = []
        self._load_rules()

    def _load_rules(self):
        if not RULES_DIR.exists():
            return
        for fpath in sorted(RULES_DIR.glob("*.json")):
            try:
                with open(fpath) as f:
                    data = json.load(f)
                self.rules.append(DetectionRule(data))
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Failed to load rule {fpath}: {e}")

    async def evaluate(self, log_event) -> list[dict]:
        log_data = log_event.parsed_data if hasattr(log_event, "parsed_data") else {}
        if isinstance(log_data, str):
            try:
                log_data = json.loads(log_data)
            except (json.JSONDecodeError, TypeError):
                log_data = {"raw": log_data}

        raw = log_event.raw_content if hasattr(log_event, "raw_content") else ""
        source = log_event.source if hasattr(log_event, "source") else "unknown"
        log_type = log_event.log_type if hasattr(log_event, "log_type") else "generic"

        merged = dict(log_data)
        if "source" not in merged:
            merged["source"] = source
        if "event_type" not in merged:
            merged["event_type"] = log_type
        if "raw_content" not in merged:
            merged["raw_content"] = raw

        threats = []
        for rule in self.rules:
            if rule.matches(merged):
                threats.append(self._build_threat(rule, merged, source))
        return threats

    def _build_threat(self, rule: DetectionRule, log_data: dict, source: str) -> dict:
        now = datetime.now(timezone.utc)
        return {
            "source_ip": source if source != "unknown" else log_data.get("source_ip", "0.0.0.0"),
            "event_type": log_data.get("event_type", rule.rule_id.lower()),
            "severity": rule.severity,
            "title": f"{rule.name}",
            "description": f"Detection rule {rule.rule_id} triggered by {source}",
            "raw_log": log_data,
            "mitre_technique_id": rule.mitre_technique,
            "mitre_tactic": rule.mitre_tactic,
            "risk_score": rule.score,
            "status": "new",
            "detected_at": now.isoformat(),
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
        }

    def reload_rules(self):
        self.rules.clear()
        self._load_rules()
