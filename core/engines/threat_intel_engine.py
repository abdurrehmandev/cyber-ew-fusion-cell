"""
Threat Intelligence Engine for Cyber-EW Fusion Cell
Integrates with multiple threat intelligence feeds
"""
import logging
import json
import time
import requests
from typing import Dict, List, Optional, Set, Any
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict
import threading
from pathlib import Path
import ipaddress
import hashlib
import re

from config.settings import CONFIG

logger = logging.getLogger(__name__)

@dataclass
class IOC:
    """Indicator of Compromise"""
    value: str
    ioc_type: str  # ip, domain, url, hash, email
    threat_type: str  # malware, phishing, c2, botnet, etc.
    source: str
    confidence: float  # 0.0 to 1.0
    first_seen: datetime
    last_seen: datetime
    description: str = ""
    tags: Optional[List[str]] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        # Ensure datetimes are timezone-aware (UTC)
        if self.first_seen and self.first_seen.tzinfo is None:
            self.first_seen = self.first_seen.replace(tzinfo=timezone.utc)
        if self.last_seen and self.last_seen.tzinfo is None:
            self.last_seen = self.last_seen.replace(tzinfo=timezone.utc)

@dataclass
class ThreatFeedConfig:
    """Threat feed configuration"""
    name: str
    url: str
    enabled: bool = True
    update_interval: int = 3600  # seconds
    format: str = "json"  # json, csv, text
    api_key: Optional[str] = None
    headers: Optional[Dict] = None
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {"User-Agent": "Cyber-EW-Fusion-Cell/1.0"}

class ThreatFeed:
    """Base class for threat intelligence feeds"""
    
    def __init__(self, config: ThreatFeedConfig):
        self.config = config
        self.iocs: List[IOC] = []
        self.last_update = None
        self.update_count = 0
        
    def fetch(self) -> List[IOC]:
        """Fetch IOCs from the feed (to be implemented by subclasses)"""
        raise NotImplementedError
    
    def parse(self, data: Any) -> List[IOC]:
        """Parse feed data into IOCs (to be implemented by subclasses)"""
        raise NotImplementedError
    
    def update(self) -> bool:
        """Update feed and return success status"""
        try:
            logger.info(f"Updating threat feed: {self.config.name}")
            
            if self.config.format == "json" and self.config.url.startswith("http"):
                response = requests.get(
                    self.config.url,
                    headers=self.config.headers,
                    timeout=30
                )
                response.raise_for_status()
                new_iocs = self.parse(response.json())
            elif self.config.format == "text" and self.config.url.startswith("http"):
                response = requests.get(
                    self.config.url,
                    headers=self.config.headers,
                    timeout=30
                )
                new_iocs = self.parse(response.text)
            else:
                # Local file
                with open(self.config.url, 'r') as f:
                    if self.config.format == "json":
                        new_iocs = self.parse(json.load(f))
                    else:
                        new_iocs = self.parse(f.read())
            
            self.iocs = new_iocs
            self.last_update = datetime.now(timezone.utc)
            self.update_count += 1
            
            logger.info(f"Updated {self.config.name}: {len(new_iocs)} IOCs")
            return True
            
        except Exception as e:
            logger.error(f"Error updating threat feed {self.config.name}: {str(e)}")
            return False

class ThreatFoxFeed(ThreatFeed):
    """ThreatFox abuse.ch feed"""
    
    def parse(self, data: Any) -> List[IOC]:
        """Parse ThreatFox JSON data"""
        iocs = []
        
        if isinstance(data, dict) and "data" in data:
            for item in data["data"]:
                try:
                    # Extract IOC details
                    value = item.get("ioc", "").strip()
                    if not value:
                        continue
                    
                    ioc_type = self._detect_ioc_type(value)
                    if not ioc_type or ioc_type == "unknown":
                        # Skip IOCs with unknown types
                        logger.debug(f"Skipping IOC with unknown type: {value}")
                        continue
                    
                    threat_type = item.get("threat_type", "malware").lower()
                    malware = item.get("malware", "unknown").lower()
                    
                    # Parse timestamps with timezone awareness
                    first_seen_str = item.get("first_seen")
                    if first_seen_str:
                        try:
                            first_seen = datetime.fromisoformat(first_seen_str.replace('Z', '+00:00'))
                        except:
                            first_seen = datetime.now(timezone.utc)
                    else:
                        first_seen = datetime.now(timezone.utc)
                    
                    last_seen_str = item.get("last_seen")
                    if last_seen_str:
                        try:
                            last_seen = datetime.fromisoformat(last_seen_str.replace('Z', '+00:00'))
                        except:
                            last_seen = datetime.now(timezone.utc)
                    else:
                        last_seen = datetime.now(timezone.utc)
                    
                    ioc = IOC(
                        value=value,
                        ioc_type=ioc_type or "unknown",
                        threat_type=f"{threat_type}_{malware}",
                        source="ThreatFox",
                        confidence=0.8,  # High confidence from ThreatFox
                        first_seen=first_seen,
                        last_seen=last_seen,
                        description=f"{threat_type} - {malware}",
                        tags=[threat_type, malware, "threatfox"]
                    )
                    iocs.append(ioc)
                except Exception as e:
                    logger.debug(f"Error parsing ThreatFox IOC: {str(e)}")
        
        return iocs
    
    def _detect_ioc_type(self, value: str) -> str:
        """Detect IOC type from value"""
        # IP address
        try:
            ipaddress.ip_address(value)
            return "ip"
        except ValueError:
            pass
        
        # Domain
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return "domain"
        
        # URL
        if value.startswith(('http://', 'https://')):
            return "url"
        
        # Hash (MD5, SHA1, SHA256)
        if len(value) == 32 and re.match(r'^[a-fA-F0-9]{32}$', value):
            return "hash_md5"
        elif len(value) == 40 and re.match(r'^[a-fA-F0-9]{40}$', value):
            return "hash_sha1"
        elif len(value) == 64 and re.match(r'^[a-fA-F0-9]{64}$', value):
            return "hash_sha256"
        
        # Email
        if '@' in value and '.' in value.split('@')[1]:
            return "email"
        
        return "unknown"

class AlienVaultOTXFeed(ThreatFeed):
    """AlienVault Open Threat Exchange feed"""
    
    def parse(self, data: Any) -> List[IOC]:
        """Parse AlienVault OTX data"""
        iocs = []
        
        if isinstance(data, dict) and "indicators" in data:
            for indicator in data["indicators"]:
                try:
                    value = indicator.get("indicator", "").strip()
                    if not value:
                        continue
                    
                    ioc_type = indicator.get("type", "unknown").lower()
                    
                    # Map OTX types to our types
                    type_map = {
                        "ipv4": "ip", "ipv6": "ip",
                        "domain": "domain", "hostname": "domain",
                        "url": "url", "uri": "url",
                        "md5": "hash_md5", "sha1": "hash_sha1", "sha256": "hash_sha256",
                        "email": "email"
                    }
                    
                    ioc_type = type_map.get(ioc_type, ioc_type)
                    
                    # Parse timestamps
                    created_ts = indicator.get("created", time.time())
                    last_seen_ts = indicator.get("last_seen", time.time())
                    
                    ioc = IOC(
                        value=value,
                        ioc_type=ioc_type,
                        threat_type=indicator.get("type_title", "malware").lower(),
                        source="AlienVaultOTX",
                        confidence=float(indicator.get("pulse_info", {}).get("count", 1)) / 100.0,
                        first_seen=datetime.fromtimestamp(created_ts, tz=timezone.utc),
                        last_seen=datetime.fromtimestamp(last_seen_ts, tz=timezone.utc),
                        description=indicator.get("description", ""),
                        tags=[tag.lower() for tag in indicator.get("tags", [])]
                    )
                    iocs.append(ioc)
                except Exception as e:
                    logger.debug(f"Error parsing OTX IOC: {str(e)}")
        
        return iocs

class LocalIOCFeed(ThreatFeed):
    """Local IOC database"""
    
    def parse(self, data: Any) -> List[IOC]:
        """Parse local JSON IOCs"""
        iocs = []
        
        if isinstance(data, list):
            for item in data:
                try:
                    # Convert string timestamps to datetime with timezone
                    first_seen = item.get("first_seen")
                    if isinstance(first_seen, str):
                        try:
                            first_seen = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                        except:
                            first_seen = datetime.now(timezone.utc)
                    else:
                        first_seen = datetime.now(timezone.utc)
                    
                    last_seen = item.get("last_seen")
                    if isinstance(last_seen, str):
                        try:
                            last_seen = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                        except:
                            last_seen = datetime.now(timezone.utc)
                    else:
                        last_seen = datetime.now(timezone.utc)
                    
                    ioc = IOC(
                        value=item["value"],
                        ioc_type=item["ioc_type"],
                        threat_type=item.get("threat_type", "malware"),
                        source=item.get("source", "local"),
                        confidence=float(item.get("confidence", 0.5)),
                        first_seen=first_seen,
                        last_seen=last_seen,
                        description=item.get("description", ""),
                        tags=item.get("tags", [])
                    )
                    iocs.append(ioc)
                except Exception as e:
                    logger.error(f"Error parsing local IOC: {str(e)}")
        
        return iocs

class ThreatIntelEngine:
    """
    Threat Intelligence Engine
    Aggregates and manages multiple threat intelligence feeds
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.feeds: Dict[str, ThreatFeed] = {}
        self.ioc_cache: Dict[str, List[IOC]] = {}  # type -> [IOCs]
        self.is_running = False
        self.update_thread = None
        self.stats = {
            "total_iocs": 0,
            "feed_stats": {},
            "matches": 0,
            "last_update": None
        }
        
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Initialize feeds
        self._init_feeds()
        
        logger.info(f"Threat Intelligence Engine initialized with {len(self.feeds)} feeds")
    
    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load threat intel configuration"""
        default_config = {
            "feeds": [
                {
                    "name": "ThreatFox Malware",
                    "url": "https://threatfox.abuse.ch/export/json/recent/",
                    "enabled": True,
                    "update_interval": 3600,
                    "format": "json",
                    "type": "threatfox"
                },
                {
                    "name": "AlienVault OTX Pulses",
                    "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",  # Requires API key
                    "enabled": False,  # Disabled by default (needs API key)
                    "update_interval": 7200,
                    "format": "json",
                    "type": "alienvault",
                    "api_key": ""  # Add your API key here
                },
                {
                    "name": "Local IOCs",
                    "url": str(CONFIG.data_dir / "threat_intel" / "local_iocs.json"),
                    "enabled": True,
                    "update_interval": 86400,
                    "format": "json",
                    "type": "local"
                }
            ],
            "enable_auto_update": True,
            "cache_ttl": 300,  # 5 minutes
            "match_threshold": 0.5  # Minimum confidence for matches
        }
        
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    # Merge with defaults
                    default_config.update(user_config)
            except Exception as e:
                logger.error(f"Error loading threat intel config: {str(e)}")
        
        return default_config
    
    def _init_feeds(self):
        """Initialize threat feeds"""
        for feed_config in self.config["feeds"]:
            if not feed_config.get("enabled", True):
                continue
            
            config = ThreatFeedConfig(
                name=feed_config["name"],
                url=feed_config["url"],
                enabled=True,
                update_interval=feed_config.get("update_interval", 3600),
                format=feed_config.get("format", "json"),
                api_key=feed_config.get("api_key")
            )
            
            # Add appropriate headers for API keys
            if feed_config.get("api_key"):
                config.headers = {
                    "User-Agent": "Cyber-EW-Fusion-Cell/1.0",
                    "X-OTX-API-KEY": feed_config["api_key"]
                }
            
            feed_type = feed_config.get("type", "generic")
            
            if feed_type == "threatfox":
                feed = ThreatFoxFeed(config)
            elif feed_type == "alienvault":
                feed = AlienVaultOTXFeed(config)
            elif feed_type == "local":
                feed = LocalIOCFeed(config)
            else:
                feed = ThreatFeed(config)  # Generic feed
            
            self.feeds[feed_config["name"]] = feed
        
        logger.info(f"Initialized {len(self.feeds)} threat feeds")
    
    def start(self):
        """Start the threat intel engine"""
        if self.is_running:
            return
        
        self.is_running = True
        
        # Initial feed updates
        self.update_all_feeds()
        
        # Start auto-update thread
        if self.config.get("enable_auto_update", True):
            self.update_thread = threading.Thread(
                target=self._auto_update_loop,
                daemon=True,
                name="threat_intel_updater"
            )
            self.update_thread.start()
        
        logger.info("Threat Intelligence Engine started")
    
    def stop(self):
        """Stop the threat intel engine"""
        self.is_running = False
        
        if self.update_thread:
            self.update_thread.join(timeout=5)
        
        # Save cache
        self._save_cache()
        
        logger.info("Threat Intelligence Engine stopped")
    
    def _auto_update_loop(self):
        """Auto-update loop for threat feeds"""
        while self.is_running:
            try:
                time.sleep(60)  # Check every minute
                
                # Check each feed for updates
                for feed_name, feed in self.feeds.items():
                    if not feed.last_update or \
                       (datetime.now(timezone.utc) - feed.last_update).total_seconds() > feed.config.update_interval:
                        
                        logger.debug(f"Auto-updating feed: {feed_name}")
                        feed.update()
                        self._update_cache()
                
            except Exception as e:
                logger.error(f"Error in auto-update loop: {str(e)}")
    
    def update_all_feeds(self):
        """Update all threat feeds"""
        logger.info("Updating all threat feeds...")
        
        for feed_name, feed in self.feeds.items():
            try:
                success = feed.update()
                self.stats["feed_stats"][feed_name] = {
                    "last_update": feed.last_update.isoformat() if feed.last_update else None,
                    "ioc_count": len(feed.iocs),
                    "update_count": feed.update_count,
                    "success": success
                }
            except Exception as e:
                logger.error(f"Error updating feed {feed_name}: {str(e)}")
                self.stats["feed_stats"][feed_name] = {
                    "error": str(e),
                    "success": False
                }
        
        self._update_cache()
        self.stats["last_update"] = datetime.now(timezone.utc)
        
        logger.info(f"Updated all feeds. Total IOCs: {self.stats['total_iocs']}")
    
    def _update_cache(self):
        """Update IOC cache from all feeds"""
        self.ioc_cache.clear()
        
        for feed in self.feeds.values():
            for ioc in feed.iocs:
                if ioc.ioc_type not in self.ioc_cache:
                    self.ioc_cache[ioc.ioc_type] = []
                self.ioc_cache[ioc.ioc_type].append(ioc)
        
        # Update stats
        self.stats["total_iocs"] = sum(len(iocs) for iocs in self.ioc_cache.values())
        
        logger.debug(f"IOC cache updated: {self.stats['total_iocs']} IOCs")
    
    def _save_cache(self):
        """Save IOC cache to disk"""
        try:
            cache_dir = CONFIG.data_dir / "threat_intel" / "cache"
            cache_dir.mkdir(parents=True, exist_ok=True)
            
            cache_file = cache_dir / "ioc_cache.json"
            cache_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "iocs": [
                    {
                        "value": ioc.value,
                        "ioc_type": ioc.ioc_type,
                        "threat_type": ioc.threat_type,
                        "source": ioc.source,
                        "confidence": ioc.confidence,
                        "first_seen": ioc.first_seen.isoformat(),
                        "last_seen": ioc.last_seen.isoformat(),
                        "description": ioc.description,
                        "tags": ioc.tags
                    }
                    for iocs in self.ioc_cache.values()
                    for ioc in iocs
                ]
            }
            
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            logger.info(f"Saved IOC cache with {len(cache_data['iocs'])} IOCs")
            
        except Exception as e:
            logger.error(f"Error saving IOC cache: {str(e)}")
    
    def match_event(self, event: Any) -> List[Dict]:
        """
        Match an event against threat intelligence IOCs
        
        Args:
            event: NormalizedEvent or dict with event data
            
        Returns:
            List of IOC matches with details
        """
        matches = []
        
        try:
            # Extract indicators from event
            indicators = self._extract_indicators(event)
            
            # Match against each indicator
            for indicator_type, indicator_value in indicators:
                if indicator_type in self.ioc_cache:
                    for ioc in self.ioc_cache[indicator_type]:
                        if self._match_indicator(ioc, indicator_value):
                            match_score = self._calculate_match_score(ioc, event)
                            
                            if match_score >= self.config.get("match_threshold", 0.5):
                                matches.append({
                                    "ioc": asdict(ioc),
                                    "indicator_value": indicator_value,
                                    "indicator_type": indicator_type,
                                    "match_score": match_score,
                                    "event_field": self._get_event_field(indicator_type, event)
                                })
                                self.stats["matches"] += 1
            
            # Remove duplicate matches (same IOC, different indicators)
            unique_matches = []
            seen_iocs = set()
            
            for match in matches:
                ioc_value = match["ioc"]["value"]
                if ioc_value not in seen_iocs:
                    unique_matches.append(match)
                    seen_iocs.add(ioc_value)
            
            return unique_matches
            
        except Exception as e:
            logger.error(f"Error matching event against IOCs: {str(e)}")
            return []
    
    def _extract_indicators(self, event: Any) -> List[tuple]:
        """Extract indicators from event"""
        indicators = []
        
        # Get event data
        if hasattr(event, '__dict__'):
            event_dict = event.__dict__
        elif isinstance(event, dict):
            event_dict = event
        else:
            return indicators
        
        # IP addresses
        for field in ['source_ip', 'destination_ip', 'src_ip', 'dst_ip']:
            if field in event_dict and event_dict[field]:
                ip = str(event_dict[field])
                if self._is_valid_ip(ip):
                    indicators.append(("ip", ip))
        
        # Domains (from details or other fields)
        if 'details' in event_dict and isinstance(event_dict['details'], dict):
            details = event_dict['details']
            
            # Check for domains in various fields
            domain_fields = ['query', 'hostname', 'domain', 'url', 'server']
            for field in domain_fields:
                if field in details and details[field]:
                    value = str(details[field])
                    # Extract domain from URL if needed
                    if field == 'url' and '://' in value:
                        value = value.split('://')[1].split('/')[0]
                    
                    if self._is_valid_domain(value):
                        indicators.append(("domain", value))
        
        # Hashes (from file events)
        if 'details' in event_dict and isinstance(event_dict['details'], dict):
            details = event_dict['details']
            
            hash_fields = ['md5', 'sha1', 'sha256', 'hash']
            for field in hash_fields:
                if field in details and details[field]:
                    hash_value = str(details[field]).lower()
                    if self._is_valid_hash(hash_value):
                        hash_type = f"hash_{field}" if field in ['md5', 'sha1', 'sha256'] else "hash"
                        indicators.append((hash_type, hash_value))
        
        return indicators
    
    def _match_indicator(self, ioc: IOC, indicator_value: str) -> bool:
        """Check if IOC matches indicator value"""
        # Exact match for most types
        if ioc.ioc_type.startswith("hash_"):
            # For hashes, compare case-insensitive
            return ioc.value.lower() == indicator_value.lower()
        elif ioc.ioc_type == "ip":
            # For IPs, handle CIDR notation
            try:
                if '/' in ioc.value:
                    # CIDR block
                    network = ipaddress.ip_network(ioc.value, strict=False)
                    ip = ipaddress.ip_address(indicator_value)
                    return ip in network
                else:
                    # Single IP
                    return ioc.value == indicator_value
            except ValueError:
                return False
        else:
            # For domains, URLs, emails - exact match
            return ioc.value == indicator_value
    
    def _calculate_match_score(self, ioc: IOC, event: Any) -> float:
        """Calculate match score based on IOC confidence and event context"""
        base_score = ioc.confidence
        
        # Ensure we're using timezone-aware datetime for comparison
        current_time = datetime.now(timezone.utc)
        
        # Ensure ioc.last_seen is timezone-aware for comparison
        if ioc.last_seen.tzinfo is None:
            ioc_last_seen = ioc.last_seen.replace(tzinfo=timezone.utc)
        else:
            ioc_last_seen = ioc.last_seen
        
        # Calculate days old
        try:
            days_old = (current_time - ioc_last_seen).days
            # Increase score for recent IOCs
            if days_old < 7:  # Less than a week old
                base_score += 0.1
            elif days_old > 365:  # More than a year old
                base_score -= 0.1
        except Exception:
            # If comparison fails, use default
            pass
        
        # Increase score for high-severity threat types
        high_severity_types = ['c2', 'botnet', 'ransomware', 'apt']
        if any(ht in ioc.threat_type.lower() for ht in high_severity_types):
            base_score += 0.2
        
        # Cap score between 0 and 1
        return max(0.0, min(1.0, base_score))
    
    def _get_event_field(self, indicator_type: str, event: Any) -> str:
        """Get the event field that contained the indicator"""
        if hasattr(event, '__dict__'):
            event_dict = event.__dict__
        elif isinstance(event, dict):
            event_dict = event
        else:
            return "unknown"
        
        field_map = {
            "ip": "source_ip",
            "domain": "details.query",
            "hash_md5": "details.md5",
            "hash_sha1": "details.sha1",
            "hash_sha256": "details.sha256",
            "url": "details.url"
        }
        
        return field_map.get(indicator_type, "unknown")
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Check if string is a valid domain"""
        pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain)) and ' ' not in domain
    
    def _is_valid_hash(self, hash_str: str) -> bool:
        """Check if string is a valid hash"""
        patterns = [
            r'^[a-fA-F0-9]{32}$',  # MD5
            r'^[a-fA-F0-9]{40}$',  # SHA1
            r'^[a-fA-F0-9]{64}$',  # SHA256
        ]
        return any(re.match(pattern, hash_str) for pattern in patterns)
    
    def get_stats(self) -> Dict:
        """Get engine statistics"""
        stats = self.stats.copy()
        stats["feed_count"] = len(self.feeds)
        stats["cache_size"] = {k: len(v) for k, v in self.ioc_cache.items()}
        return stats
    
    def search_iocs(self, query: str, ioc_type: Optional[str] = None) -> List[Dict]:
        """Search IOCs by value or description"""
        results = []
        
        for iocs in self.ioc_cache.values():
            for ioc in iocs:
                if ioc_type and ioc.ioc_type != ioc_type:
                    continue
                
                if (query.lower() in ioc.value.lower() or 
                    query.lower() in ioc.description.lower() or
                    any(query.lower() in tag.lower() for tag in ioc.tags or [])):
                    
                    results.append(asdict(ioc))
        
        return results
    
    def add_local_ioc(self, ioc_data: Dict) -> bool:
        """Add a local IOC to the database"""
        try:
            # Load existing local IOCs
            local_file = CONFIG.data_dir / "threat_intel" / "local_iocs.json"
            local_file.parent.mkdir(parents=True, exist_ok=True)
            
            if local_file.exists():
                with open(local_file, 'r') as f:
                    local_iocs = json.load(f)
            else:
                local_iocs = []
            
            # Add new IOC
            local_iocs.append(ioc_data)
            
            # Save
            with open(local_file, 'w') as f:
                json.dump(local_iocs, f, indent=2)
            
            # Update local feed
            if "Local IOCs" in self.feeds:
                self.feeds["Local IOCs"].update()
                self._update_cache()
            
            logger.info(f"Added local IOC: {ioc_data.get('value', 'unknown')}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding local IOC: {str(e)}")
            return False
