"""
Signature-Based Detection Engine
Uses YARA-like rules for detecting known attack patterns
"""
import re
import json
import logging
from typing import Dict, List, Optional, Any, Pattern
from datetime import datetime, timezone
from pathlib import Path
import ipaddress
import hashlib

from config.settings import CONFIG

logger = logging.getLogger(__name__)

# Try to import YARA with graceful fallback
try:
    import yara
    YARA_AVAILABLE = True
    logger.info("YARA module loaded successfully")
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("YARA module not available. YARA rule functionality will be limited.")

class SignatureRule:
    """Detection signature rule"""
    
    def __init__(self, rule_data: Dict):
        self.id = rule_data.get("id", "")
        self.name = rule_data.get("name", "")
        self.description = rule_data.get("description", "")
        self.severity = rule_data.get("severity", "medium")  # low, medium, high, critical
        self.category = rule_data.get("category", "general")
        self.tags = rule_data.get("tags", [])
        self.enabled = rule_data.get("enabled", True)
        
        # Detection conditions
        self.conditions = rule_data.get("conditions", [])
        self.logic = rule_data.get("logic", "all")  # all, any
        
        # Metadata
        self.author = rule_data.get("author", "unknown")
        self.created = rule_data.get("created", datetime.now(timezone.utc).isoformat())
        self.updated = rule_data.get("updated", datetime.now(timezone.utc).isoformat())
        self.references = rule_data.get("references", [])
        
        # Compile regex patterns
        self.compiled_patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict[str, Pattern]:
        """Compile regex patterns for performance"""
        compiled = {}
        
        for condition in self.conditions:
            if condition.get("type") == "regex":
                pattern = condition.get("pattern", "")
                try:
                    compiled[condition["field"]] = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    logger.error(f"Invalid regex in rule {self.id}: {pattern} - {str(e)}")
        
        return compiled
    
    def match(self, event: Any) -> Optional[Dict]:
        """
        Match event against this rule
        
        Returns:
            Match details or None if no match
        """
        if not self.enabled:
            return None
        
        # Get event data
        if hasattr(event, '__dict__'):
            event_data = event.__dict__
        elif isinstance(event, dict):
            event_data = event
        else:
            return None
        
        matches = []
        match_details = []
        
        for condition in self.conditions:
            condition_type = condition.get("type")
            field = condition.get("field")
            operator = condition.get("operator")
            value = condition.get("value")

            if condition_type == "yara":
                # YARA-only rules may not define a normal event field. They are
                # handled by YARARule before falling back to standard matching.
                matches.append(False)
                logger.debug(f"YARA condition in rule {self.id} - this should be handled by YARARule")
                continue
            
            # Get field value from event
            field_value = self._get_nested_value(event_data, field)
            
            # Apply condition
            if condition_type == "equals":
                match = str(field_value) == str(value)
                matches.append(match)
                if match:
                    match_details.append(f"{field} == {value}")
            
            elif condition_type == "contains":
                match = str(value).lower() in str(field_value).lower()
                matches.append(match)
                if match:
                    match_details.append(f"{field} contains {value}")
            
            elif condition_type == "regex":
                if field in self.compiled_patterns:
                    pattern = self.compiled_patterns[field]
                    match = bool(pattern.search(str(field_value)))
                    matches.append(match)
                    if match:
                        match_details.append(f"{field} matches {pattern.pattern}")
            
            elif condition_type == "greater_than":
                try:
                    match = float(field_value) > float(value)
                    matches.append(match)
                    if match:
                        match_details.append(f"{field} > {value}")
                except (ValueError, TypeError):
                    matches.append(False)
            
            elif condition_type == "less_than":
                try:
                    match = float(field_value) < float(value)
                    matches.append(match)
                    if match:
                        match_details.append(f"{field} < {value}")
                except (ValueError, TypeError):
                    matches.append(False)
            
            elif condition_type == "in_range":
                try:
                    min_val = float(condition.get("min", 0))
                    max_val = float(condition.get("max", 0))
                    val = float(field_value)
                    match = min_val <= val <= max_val
                    matches.append(match)
                    if match:
                        match_details.append(f"{min_val} <= {field} <= {max_val}")
                except (ValueError, TypeError):
                    matches.append(False)
            
            elif condition_type == "in_list":
                value_list = condition.get("values", [])
                match = str(field_value) in value_list
                matches.append(match)
                if match:
                    match_details.append(f"{field} in {value_list}")
            
            elif condition_type == "exists":
                match = field_value is not None and field_value != ""
                matches.append(match)
                if match:
                    match_details.append(f"{field} exists")
            
            elif condition_type == "cidr":
                try:
                    ip = ipaddress.ip_address(str(field_value))
                    network = ipaddress.ip_network(str(value), strict=False)
                    match = ip in network
                    matches.append(match)
                    if match:
                        match_details.append(f"{field} in CIDR {value}")
                except (ValueError, TypeError):
                    matches.append(False)
            
            else:
                logger.warning(f"Unknown condition type in rule {self.id}: {condition_type}")
                matches.append(False)
        
        # Apply logic (all or any)
        if self.logic == "all" and all(matches):
            return {
                "rule_id": self.id,
                "rule_name": self.name,
                "severity": self.severity,
                "category": self.category,
                "description": self.description,
                "match_details": match_details,
                "confidence": 0.9,  # High confidence for signature matches
                "tags": self.tags
            }
        elif self.logic == "any" and any(matches):
            return {
                "rule_id": self.id,
                "rule_name": self.name,
                "severity": self.severity,
                "category": self.category,
                "description": self.description,
                "match_details": [d for d, m in zip(match_details, matches) if m],
                "confidence": 0.7,  # Medium confidence for "any" logic
                "tags": self.tags
            }
        
        return None
    
    def _get_nested_value(self, data: Dict, field_path: str) -> Any:
        """Get value from nested field path (e.g., details.query)"""
        if not field_path:
            return None
        if '.' not in field_path:
            return data.get(field_path)
        
        parts = field_path.split('.')
        current = data
        
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        
        return current

class YARARule(SignatureRule):
    """YARA rule implementation with fallback"""
    
    def __init__(self, rule_data: Dict):
        super().__init__(rule_data)
        self.yara_rule = None
        
        if YARA_AVAILABLE:
            self._compile_yara()
        else:
            logger.warning(f"YARA not available for rule {self.id}. Rule will use fallback detection.")
    
    def _compile_yara(self):
        """Compile YARA rule (only if YARA is available)"""
        if not YARA_AVAILABLE:
            return
            
        try:
            yara_source = ""
            # Find YARA source in conditions
            for condition in self.conditions:
                if condition.get("type") == "yara" and "yara_source" in condition:
                    yara_source = condition.get("yara_source", "")
                    break
            
            if yara_source:
                self.yara_rule = yara.compile(source=yara_source)  # type: ignore
                logger.debug(f"YARA rule compiled: {self.id}")
            else:
                logger.warning(f"No YARA source found for rule {self.id}")
                
        except Exception as e:
            if YARA_AVAILABLE and isinstance(e, yara.SyntaxError):  # type: ignore
                logger.error(f"YARA syntax error in rule {self.id}: {str(e)}")
            else:
                logger.error(f"Error compiling YARA rule {self.id}: {str(e)}")
    
    def match(self, event: Any) -> Optional[Dict]:
        """Match using YARA with fallback to parent class"""
        # If YARA is available and we have a compiled rule, try YARA matching
        if YARA_AVAILABLE and self.yara_rule:
            content = self._extract_content(event)
            if content:
                try:
                    matches = self.yara_rule.match(data=content)
                    if matches:
                        return {
                            "rule_id": self.id,
                            "rule_name": self.name,
                            "severity": self.severity,
                            "category": self.category,
                            "description": self.description,
                            "match_details": [str(m) for m in matches],
                            "confidence": 0.95,  # Very high confidence for YARA
                            "yara_matches": [m.rule for m in matches],
                            "tags": self.tags + ["yara"]
                        }
                except Exception as e:
                    logger.error(f"Error matching YARA rule {self.id}: {str(e)}")
        
        # Fallback to parent class matching (non-YARA conditions)
        return super().match(event)
    
    def _extract_content(self, event: Any) -> Optional[bytes]:
        """Extract content for YARA scanning"""
        if hasattr(event, '__dict__'):
            event_dict = event.__dict__
        elif isinstance(event, dict):
            event_dict = event
        else:
            return None
        
        # Check for file content
        if 'details' in event_dict and isinstance(event_dict['details'], dict):
            details = event_dict['details']
            
            # File content
            if 'file_content' in details and isinstance(details['file_content'], bytes):
                return details['file_content']
            
            # Network payload
            if 'payload' in details and isinstance(details['payload'], bytes):
                return details['payload']
            
            # Hex string
            if 'hex' in details and isinstance(details['hex'], str):
                try:
                    return bytes.fromhex(details['hex'])
                except ValueError:
                    pass
        
        return None

class SignatureEngine:
    """Signature-based detection engine"""
    
    def __init__(self, rules_dir: Optional[str] = None):
        self.rules: Dict[str, SignatureRule] = {}
        self.rule_categories = {}
        self.stats = {
            "total_rules": 0,
            "enabled_rules": 0,
            "matches": 0,
            "last_scan": None,
            "yara_available": YARA_AVAILABLE
        }
        
        # Load rules
        self.rules_dir = Path(rules_dir) if rules_dir else CONFIG.data_dir / "signatures"
        self._load_rules()
        
        logger.info(f"Signature Engine initialized with {self.stats['total_rules']} rules")
        if not YARA_AVAILABLE:
            logger.warning("YARA not available - YARA rules will use fallback detection")
    
    def _load_rules(self):
        """Load detection rules from directory"""
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        
        # Load from JSON files
        for rule_file in self.rules_dir.glob("*.json"):
            try:
                with open(rule_file, 'r') as f:
                    rules_data = json.load(f)
                
                if isinstance(rules_data, list):
                    for rule_data in rules_data:
                        self._add_rule(rule_data)
                elif isinstance(rules_data, dict):
                    self._add_rule(rules_data)
                
            except Exception as e:
                logger.error(f"Error loading rules from {rule_file}: {str(e)}")
        
        # Load from YARA files only if YARA is available
        if YARA_AVAILABLE:
            for yara_file in self.rules_dir.glob("*.yar"):
                try:
                    rule_data = {
                        "id": f"yara_{yara_file.stem}",
                        "name": f"YARA Rule: {yara_file.stem}",
                        "description": f"YARA rule from {yara_file.name}",
                        "severity": "high",
                        "category": "malware",
                        "tags": ["yara", "malware"],
                        "enabled": True,
                        "conditions": [
                            {
                                "type": "yara",
                                "yara_source": yara_file.read_text()
                            }
                        ]
                    }
                    
                    self._add_rule(rule_data, rule_type="yara")
                    
                except Exception as e:
                    logger.error(f"Error loading YARA rule {yara_file}: {str(e)}")
        else:
            logger.info("Skipping YARA files (.yar) because YARA is not available")
        
        logger.info(f"Loaded {self.stats['total_rules']} rules ({self.stats['enabled_rules']} enabled)")
    
    def _add_rule(self, rule_data: Dict, rule_type: str = "signature"):
        """Add a rule to the engine"""
        try:
            rule_id = rule_data.get("id", f"rule_{len(self.rules)}")
            
            # Check if this is a YARA rule (has yara conditions)
            is_yara_rule = False
            for condition in rule_data.get("conditions", []):
                if condition.get("type") == "yara":
                    is_yara_rule = True
                    break
            
            if is_yara_rule and rule_type != "yara":
                rule_type = "yara"
            
            if rule_type == "yara":
                if YARA_AVAILABLE:
                    rule = YARARule(rule_data)
                else:
                    # Convert YARA rule to regular signature rule with warning
                    logger.warning(f"YARA not available - converting YARA rule {rule_id} to regular signature rule")
                    # Replace YARA condition with a placeholder
                    for condition in rule_data.get("conditions", []):
                        if condition.get("type") == "yara":
                            condition["type"] = "regex"
                            condition["field"] = "details.message"
                            condition["pattern"] = "a^"  # Pattern that never matches
                            condition["description"] = "YARA rule placeholder (YARA not available)"
                    rule = SignatureRule(rule_data)
            else:
                rule = SignatureRule(rule_data)
            
            self.rules[rule_id] = rule
            
            # Update categories
            category = rule.category
            if category not in self.rule_categories:
                self.rule_categories[category] = []
            self.rule_categories[category].append(rule_id)
            
            # Update stats
            self.stats["total_rules"] += 1
            if rule.enabled:
                self.stats["enabled_rules"] += 1
            
        except Exception as e:
            logger.error(f"Error adding rule {rule_data.get('id', 'unknown')}: {str(e)}")
    
    def scan_event(self, event: Any) -> List[Dict]:
        """
        Scan event against all rules
        
        Returns:
            List of rule matches
        """
        matches = []
        
        for rule_id, rule in self.rules.items():
            try:
                match = rule.match(event)
                if match:
                    matches.append(match)
            except Exception as e:
                logger.error(f"Error in rule {rule_id}: {str(e)}")
        
        if matches:
            self.stats["matches"] += len(matches)
            self.stats["last_scan"] = datetime.now(timezone.utc)
        
        return matches
    
    def add_rule(self, rule_data: Dict) -> bool:
        """Add a new rule"""
        try:
            self._add_rule(rule_data)
            
            # Save to file
            rule_file = self.rules_dir / f"custom_{rule_data.get('id', 'rule')}.json"
            
            if rule_file.exists():
                with open(rule_file, 'r') as f:
                    existing_rules = json.load(f)
                
                if isinstance(existing_rules, list):
                    existing_rules.append(rule_data)
                else:
                    existing_rules = [existing_rules, rule_data]
            else:
                existing_rules = [rule_data]
            
            with open(rule_file, 'w') as f:
                json.dump(existing_rules, f, indent=2)
            
            logger.info(f"Added and saved rule: {rule_data.get('id')}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding rule: {str(e)}")
            return False
    
    def enable_rule(self, rule_id: str, enabled: bool = True) -> bool:
        """Enable or disable a rule"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = enabled
            
            # Update stats
            if enabled:
                self.stats["enabled_rules"] += 1
            else:
                self.stats["enabled_rules"] -= 1
            
            logger.info(f"{'Enabled' if enabled else 'Disabled'} rule: {rule_id}")
            return True
        
        return False
    
    def get_stats(self) -> Dict:
        """Get engine statistics"""
        stats = self.stats.copy()
        stats["categories"] = {cat: len(rules) for cat, rules in self.rule_categories.items()}
        return stats
    
    def get_rules_by_category(self, category: str) -> List[Dict]:
        """Get all rules in a category"""
        rules = []
        
        if category in self.rule_categories:
            for rule_id in self.rule_categories[category]:
                rule = self.rules[rule_id]
                rules.append({
                    "id": rule.id,
                    "name": rule.name,
                    "description": rule.description,
                    "severity": rule.severity,
                    "enabled": rule.enabled,
                    "condition_count": len(rule.conditions),
                    "type": "yara" if isinstance(rule, YARARule) else "signature"
                })
        
        return rules
    
    def test_rule(self, rule_id: str, test_event: Dict) -> Optional[Dict]:
        """Test a specific rule against a test event"""
        if rule_id not in self.rules:
            logger.error(f"Rule not found: {rule_id}")
            return None
        
        rule = self.rules[rule_id]
        return rule.match(test_event)
