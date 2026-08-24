# Save this as: utils/validators.py (replace the entire file)
"""
Validation utilities for Cyber-EW Fusion Cell
"""
import re
import ipaddress
from datetime import datetime
from typing import Optional, Union, Any
import logging

logger = logging.getLogger(__name__)

def validate_ip_address(ip_str: str) -> bool:
    """Validate IPv4 or IPv6 address"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def validate_ipv4(ip_str: str) -> bool:
    """Validate IPv4 address"""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except (ValueError, ipaddress.AddressValueError):
        return False

def validate_ipv6(ip_str: str) -> bool:
    """Validate IPv6 address"""
    try:
        ipaddress.IPv6Address(ip_str)
        return True
    except (ValueError, ipaddress.AddressValueError):
        return False

def validate_port(port: Union[str, int]) -> bool:
    """Validate port number (0-65535)"""
    try:
        port_int = int(port)
        return 0 <= port_int <= 65535
    except (ValueError, TypeError):
        return False

def validate_domain(domain: str) -> bool:
    """Validate domain name"""
    if not domain or len(domain) > 253:
        return False
    
    # Basic domain validation pattern
    pattern = r'^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    
    return bool(re.match(pattern, domain))

def validate_mac(mac: str) -> bool:
    """Validate MAC address - THIS WAS MISSING!"""
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(pattern, mac))

def validate_mac_address(mac: str) -> bool:
    """Alias for validate_mac for compatibility"""
    return validate_mac(mac)

def validate_email(email: str) -> bool:
    """Validate email address"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$'
    return bool(re.match(pattern, email))

def validate_timestamp(timestamp: Any) -> Optional[datetime]:
    """Validate and convert timestamp to datetime"""
    if timestamp is None:
        return None
    
    if isinstance(timestamp, datetime):
        return timestamp
    
    try:
        # Try parsing as ISO format string
        if isinstance(timestamp, str):
            # Remove timezone info if present for simplicity
            if 'Z' in timestamp:
                timestamp = timestamp.replace('Z', '+00:00')
            return datetime.fromisoformat(timestamp)
        
        # Try parsing as Unix timestamp (float or int)
        elif isinstance(timestamp, (int, float)):
            if timestamp > 1e12:  # Likely milliseconds
                return datetime.fromtimestamp(timestamp / 1000)
            else:  # Likely seconds
                return datetime.fromtimestamp(timestamp)
        
        else:
            logger.warning(f"Unknown timestamp format: {type(timestamp)}")
            return None
            
    except (ValueError, TypeError, OverflowError) as e:
        logger.error(f"Timestamp validation error: {e}")
        return None

def validate_url(url: str) -> bool:
    """Validate URL"""
    pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*'
    return bool(re.match(pattern, url))

def validate_json(json_str: str) -> bool:
    """Validate JSON string"""
    try:
        import json
        json.loads(json_str)
        return True
    except (json.JSONDecodeError, TypeError):
        return False

def is_internal_ip(ip_str: str) -> bool:
    """Check if IP is internal/RFC1918"""
    if not validate_ip_address(ip_str):
        return False
    
    try:
        ip = ipaddress.ip_address(ip_str)
        
        # RFC1918 private ranges
        private_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            # Link-local
            ipaddress.ip_network('169.254.0.0/16'),
            # Loopback
            ipaddress.ip_network('127.0.0.0/8'),
            ipaddress.ip_network('::1/128'),
            # Unique local addresses (IPv6)
            ipaddress.ip_network('fc00::/7'),
            # Link-local (IPv6)
            ipaddress.ip_network('fe80::/10')
        ]
        
        return any(ip in network for network in private_ranges)
        
    except ValueError:
        return False

def validate_sha256(hash_str: str) -> bool:
    """Validate SHA256 hash"""
    pattern = r'^[a-fA-F0-9]{64}$'
    return bool(re.match(pattern, hash_str))

def validate_md5(hash_str: str) -> bool:
    """Validate MD5 hash"""
    pattern = r'^[a-fA-F0-9]{32}$'
    return bool(re.match(pattern, hash_str))

def validate_filename(filename: str) -> bool:
    """Validate filename (no path traversal)"""
    if not filename:
        return False
    
    # Prevent path traversal
    if '..' in filename or '/' in filename or '\\' in filename:
        return False
    
    # Prevent control characters
    if any(ord(c) < 32 for c in filename):
        return False
    
    return True

def validate_severity(severity: str) -> bool:
    """Validate severity level"""
    valid_levels = ['critical', 'high', 'medium', 'low', 'info', 'debug']
    return severity.lower() in valid_levels

def validate_confidence(confidence: Union[int, float]) -> bool:
    """Validate confidence score (0-1 or 0-100)"""
    try:
        conf = float(confidence)
        return 0 <= conf <= 100 or 0 <= conf <= 1
    except (ValueError, TypeError):
        return False

def normalize_confidence(confidence: Union[int, float]) -> float:
    """Normalize confidence to 0-1 scale"""
    if not validate_confidence(confidence):
        return 0.0
    
    conf = float(confidence)
    if conf > 1:  # Assume 0-100 scale
        return conf / 100
    return conf