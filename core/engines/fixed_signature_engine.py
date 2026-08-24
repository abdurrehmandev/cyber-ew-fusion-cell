"""
FIXED Signature Detection Engine
Has all required methods that pipeline expects
"""
import logging
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import re

logger = logging.getLogger(__name__)

class FixedSignatureEngine:
    """Fixed Signature Engine with all required methods"""
    
    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = Path(rules_dir) if rules_dir else Path("data/signatures")
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        
        # Statistics (match original structure)
        self.stats = {
            "total_rules": 0,
            "enabled_rules": 0,
            "matches": 0,
            "last_scan": None,
            "yara_available": False,
            "categories": {}
        }
        
        # Try to import YARA
        try:
            import yara
            self.yara_available = True
            logger.info("YARA is available")
        except ImportError:
            self.yara_available = False
            logger.warning("YARA not available - using fallback detection")
        
        # Load rules
        self.rules = self._load_rules()
        self.stats["total_rules"] = len(self.rules)
        self.stats["enabled_rules"] = sum(1 for r in self.rules if r.get("enabled", True))
        
        logger.info(f"Fixed Signature Engine initialized with {self.stats['total_rules']} rules")
    
    def _load_rules(self) -> List[Dict]:
        """Load rules from directory"""
        rules = []
        
        # Default rule for testing
        default_rule = {
            "id": "default_001",
            "name": "Default Malicious Domain",
            "description": "Detects known malicious domain",
            "severity": "high",
            "category": "malware",
            "enabled": True,
            "conditions": [
                {
                    "type": "contains",
                    "field": "details.query",
                    "value": "malicious-domain.com"
                }
            ]
        }
        rules.append(default_rule)
        
        # Load from JSON files
        for rule_file in self.rules_dir.glob("*.json"):
            try:
                with open(rule_file, 'r') as f:
                    file_rules = json.load(f)
                
                if isinstance(file_rules, list):
                    rules.extend(file_rules)
                elif isinstance(file_rules, dict):
                    rules.append(file_rules)
                    
            except Exception as e:
                logger.error(f"Error loading rules from {rule_file}: {e}")
        
        return rules
    
    def _match_rule(self, rule: Dict, event: Any) -> Optional[Dict]:
        """Match event against a single rule"""
        # Get event data
        if hasattr(event, '__dict__'):
            event_dict = event.__dict__
        elif isinstance(event, dict):
            event_dict = event
        else:
            return None
        
        # Check conditions
        for condition in rule.get("conditions", []):
            condition_type = condition.get("type")
            field = condition.get("field", "")
            value = condition.get("value", "")
            
            # Get field value
            field_value = self._get_field_value(event_dict, field)
            
            # Apply condition
            if condition_type == "contains":
                if str(value).lower() not in str(field_value).lower():
                    return None
            elif condition_type == "equals":
                if str(field_value) != str(value):
                    return None
            elif condition_type == "regex":
                try:
                    if not re.search(value, str(field_value), re.IGNORECASE):
                        return None
                except re.error:
                    return None
        
        # Rule matched
        return {
            "rule_id": rule.get("id"),
            "rule_name": rule.get("name"),
            "severity": rule.get("severity", "medium"),
            "category": rule.get("category", "general"),
            "description": rule.get("description", ""),
            "confidence": 0.9,
            "tags": rule.get("tags", [])
        }
    
    def _get_field_value(self, data: Dict, field_path: str) -> Any:
        """Get value from nested field path"""
        if '.' not in field_path:
            return data.get(field_path, "")
        
        parts = field_path.split('.')
        current = data
        
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part, "")
            else:
                return ""
        
        return current
    
    def scan_event(self, event: Any) -> List[Dict]:
        """Scan event against all rules - matches original method signature"""
        matches = []
        
        for rule in self.rules:
            if not rule.get("enabled", True):
                continue
                
            match = self._match_rule(rule, event)
            if match:
                matches.append(match)
        
        if matches:
            self.stats["matches"] += len(matches)
            self.stats["last_scan"] = datetime.utcnow()
        
        return matches
    
    def add_rule(self, rule_data: Dict) -> bool:
        """Add a new rule - required by pipeline"""
        try:
            # Add to in-memory rules
            self.rules.append(rule_data)
            
            # Save to file
            custom_file = self.rules_dir / "custom_rules.json"
            
            existing_rules = []
            if custom_file.exists():
                with open(custom_file, 'r') as f:
                    existing_rules = json.load(f)
                    if not isinstance(existing_rules, list):
                        existing_rules = [existing_rules]
            
            existing_rules.append(rule_data)
            
            with open(custom_file, 'w') as f:
                json.dump(existing_rules, f, indent=2)
            
            # Update stats
            self.stats["total_rules"] += 1
            if rule_data.get("enabled", True):
                self.stats["enabled_rules"] += 1
            
            logger.info(f"Added rule: {rule_data.get('id')}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding rule: {e}")
            return False
    
    def get_stats(self) -> Dict:
        """Get engine statistics - required by pipeline"""
        return self.stats.copy()
    
    def get_rules_by_category(self, category: str) -> List[Dict]:
        """Get rules by category (for completeness)"""
        return [r for r in self.rules if r.get("category") == category]
