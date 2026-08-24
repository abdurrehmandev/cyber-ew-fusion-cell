# File: utils/security.py
"""
Security utilities for Cyber-EW Fusion Cell
"""
import hashlib
import hmac
import os
import base64
import logging
from typing import Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

def generate_secure_random(length: int = 32) -> bytes:
    """Generate cryptographically secure random bytes"""
    return os.urandom(length)

def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Hash password with salt using PBKDF2"""
    import hashlib
    import binascii
    
    if salt is None:
        salt = os.urandom(32)
    
    # Using PBKDF2 with SHA256
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    
    return key, salt

def verify_password(password: str, stored_hash: bytes, salt: bytes) -> bool:
    """Verify password against stored hash"""
    try:
        new_hash, _ = hash_password(password, salt)
        return hmac.compare_digest(new_hash, stored_hash)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

def create_hmac_signature(data: str, secret_key: bytes) -> str:
    """Create HMAC signature for data"""
    signature = hmac.new(secret_key, data.encode('utf-8'), hashlib.sha256).digest()
    return base64.b64encode(signature).decode('utf-8')

def verify_hmac_signature(data: str, signature: str, secret_key: bytes) -> bool:
    """Verify HMAC signature"""
    try:
        expected_signature = create_hmac_signature(data, secret_key)
        return hmac.compare_digest(signature, expected_signature)
    except Exception as e:
        logger.error(f"HMAC verification error: {e}")
        return False

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal"""
    import re
    
    # Remove path components
    filename = os.path.basename(filename)
    
    # Remove control characters and special characters
    filename = re.sub(r'[^\w\s.-]', '', filename)
    
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    
    return filename

def validate_file_path(filepath: Path, allowed_dirs: list) -> bool:
    """Validate file path is within allowed directories"""
    try:
        # Get absolute paths
        abs_filepath = filepath.resolve()
        
        # Check if file is within any allowed directory
        for allowed_dir in allowed_dirs:
            abs_allowed = Path(allowed_dir).resolve()
            
            # Use os.path.commonpath for cross-platform compatibility
            try:
                common = os.path.commonpath([abs_filepath, abs_allowed])
                if common == str(abs_allowed):
                    return True
            except ValueError:
                continue
        
        return False
    except Exception as e:
        logger.error(f"Path validation error: {e}")
        return False

def encrypt_sensitive_data(data: str, key: bytes) -> Optional[bytes]:
    """Encrypt sensitive data (simple XOR for demonstration)"""
    # WARNING: This is a simple example. Use proper encryption in production!
    try:
        from cryptography.fernet import Fernet
        # Generate Fernet key from provided key
        fernet = Fernet(base64.urlsafe_b64encode(key[:32]))
        return fernet.encrypt(data.encode('utf-8'))
    except ImportError:
        logger.warning("cryptography module not available, using simple XOR")
        # Simple XOR encryption (NOT SECURE for production!)
        data_bytes = data.encode('utf-8')
        key_bytes = key[:len(data_bytes)]
        encrypted = bytes([a ^ b for a, b in zip(data_bytes, key_bytes)])
        return base64.b64encode(encrypted)
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        return None

def decrypt_sensitive_data(encrypted_data: bytes, key: bytes) -> Optional[str]:
    """Decrypt sensitive data"""
    try:
        from cryptography.fernet import Fernet
        fernet = Fernet(base64.urlsafe_b64encode(key[:32]))
        decrypted = fernet.decrypt(encrypted_data)
        return decrypted.decode('utf-8')
    except ImportError:
        logger.warning("cryptography module not available, using simple XOR")
        # Simple XOR decryption
        encrypted_bytes = base64.b64decode(encrypted_data)
        key_bytes = key[:len(encrypted_bytes)]
        decrypted = bytes([a ^ b for a, b in zip(encrypted_bytes, key_bytes)])
        return decrypted.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return None

def generate_api_key(length: int = 32) -> str:
    """Generate secure API key"""
    import secrets
    import string
    
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def mask_sensitive_string(text: str, visible_chars: int = 4) -> str:
    """Mask sensitive string (like credit cards or API keys)"""
    if len(text) <= visible_chars * 2:
        return '*' * len(text)
    
    visible = visible_chars
    return text[:visible] + '*' * (len(text) - visible * 2) + text[-visible:]

def check_file_permissions(filepath: Path) -> dict:
    """Check file permissions"""
    import stat
    import os
    
    result = {
        'exists': filepath.exists(),
        'readable': False,
        'writable': False,
        'executable': False,
        'size': 0
    }
    
    if not result['exists']:
        return result
    
    try:
        # Check permissions
        mode = filepath.stat().st_mode
        
        result['readable'] = os.access(filepath, os.R_OK)
        result['writable'] = os.access(filepath, os.W_OK)
        result['executable'] = os.access(filepath, os.X_OK)
        result['size'] = filepath.stat().st_size
        
        # Get permission string
        result['permissions'] = stat.filemode(mode)
        
    except Exception as e:
        logger.error(f"Permission check error for {filepath}: {e}")
    
    return result

def generate_self_signed_cert(cert_path: Path, key_path: Path,
                            common_name: str = "cyber-ew.local",
                            days_valid: int = 365):
    """Generate self-signed certificate (for development)"""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from datetime import datetime, timedelta
        
        # Generate private key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cyber-EW"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=days_valid)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False
        ).sign(key, hashes.SHA256())
        
        # Write private key
        with open(key_path, 'wb') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Write certificate
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        logger.info(f"Generated self-signed certificate: {cert_path}")
        return True
        
    except ImportError:
        logger.warning("cryptography module not available, cannot generate certificate")
        return False
    except Exception as e:
        logger.error(f"Certificate generation error: {e}")
        return False