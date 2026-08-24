# File: utils/helpers.py
"""
Helper functions for Cyber-EW Fusion Cell
"""
import os
import sys
import json
import hashlib
import random
import string
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def generate_id(length: int = 16) -> str:
    """Generate a random ID"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def generate_hash_id(data: str, length: int = 16) -> str:
    """Generate deterministic ID from data hash"""
    hash_obj = hashlib.sha256(data.encode())
    return hash_obj.hexdigest()[:length]

def safe_json_dump(data: Any, default=str) -> str:
    """Safely dump data to JSON string"""
    try:
        return json.dumps(data, indent=2, default=default)
    except (TypeError, ValueError) as e:
        logger.error(f"JSON dump error: {e}")
        return json.dumps({"error": "Could not serialize data"})

def safe_json_load(json_str: str) -> Any:
    """Safely load JSON string"""
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        logger.error(f"JSON load error: {e}")
        return None

def get_file_hash(filepath: Path, algorithm: str = 'sha256') -> Optional[str]:
    """Calculate file hash"""
    if not filepath.exists():
        return None
    
    try:
        hash_func = getattr(hashlib, algorithm)()
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    except Exception as e:
        logger.error(f"File hash error for {filepath}: {e}")
        return None

def ensure_directory(path: Path) -> bool:
    """Ensure directory exists, create if not"""
    try:
        path.mkdir(parents=True, exist_ok=True)
        return True
    except Exception as e:
        logger.error(f"Failed to create directory {path}: {e}")
        return False

def get_project_root() -> Path:
    """Get project root directory"""
    # Assuming this file is in utils/, project root is parent
    return Path(__file__).parent.parent

def get_data_dir() -> Path:
    """Get data directory path"""
    data_dir = get_project_root() / 'data'
    ensure_directory(data_dir)
    return data_dir

def get_log_dir() -> Path:
    """Get log directory path"""
    log_dir = get_project_root() / 'logs'
    ensure_directory(log_dir)
    return log_dir

def get_temp_dir() -> Path:
    """Get temp directory path"""
    temp_dir = get_project_root() / 'temp'
    ensure_directory(temp_dir)
    return temp_dir

def chunk_list(lst: List, chunk_size: int) -> List[List]:
    """Split list into chunks"""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def flatten_list(nested_list: List[List]) -> List:
    """Flatten nested list"""
    return [item for sublist in nested_list for item in sublist]

def safe_get(dictionary: Dict, keys: List[str], default: Any = None) -> Any:
    """Safely get nested dictionary value"""
    current = dictionary
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current

def filter_dict(dictionary: Dict, keys: List[str]) -> Dict:
    """Filter dictionary to only include specified keys"""
    return {k: v for k, v in dictionary.items() if k in keys}

def exclude_dict(dictionary: Dict, keys: List[str]) -> Dict:
    """Filter dictionary to exclude specified keys"""
    return {k: v for k, v in dictionary.items() if k not in keys}

def merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """Merge two dictionaries (dict2 overwrites dict1)"""
    result = dict1.copy()
    result.update(dict2)
    return result

def deep_merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """Deep merge two dictionaries"""
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    
    return result

def human_readable_size(size_bytes: int) -> str:
    """Convert bytes to human readable size"""
    if size_bytes == 0:
        return "0B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    unit_index = 0
    
    while size_bytes >= 1024 and unit_index < len(units) - 1:
        size_bytes /= 1024
        unit_index += 1
    
    return f"{size_bytes:.2f}{units[unit_index]}"

def get_system_info() -> Dict:
    """Get system information"""
    import platform
    
    return {
        'platform': platform.platform(),
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'python_implementation': platform.python_implementation(),
        'cpu_count': os.cpu_count(),
        'memory': None  # Would need psutil for this
    }

def is_windows() -> bool:
    """Check if running on Windows"""
    return os.name == 'nt' or sys.platform == 'win32'

def is_linux() -> bool:
    """Check if running on Linux"""
    return os.name == 'posix' and sys.platform != 'darwin'

def is_mac() -> bool:
    """Check if running on macOS"""
    return sys.platform == 'darwin'

def get_current_timestamp() -> datetime:
    """Get current UTC timestamp"""
    from datetime import timezone
    return datetime.now(timezone.utc)

def create_backup(filepath: Path, backup_dir: Optional[Path] = None) -> Optional[Path]:
    """Create backup of file"""
    if not filepath.exists():
        return None
    
    if backup_dir is None:
        backup_dir = filepath.parent / 'backups'
    
    ensure_directory(backup_dir)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_name = f"{filepath.stem}_{timestamp}{filepath.suffix}"
    backup_path = backup_dir / backup_name
    
    try:
        import shutil
        shutil.copy2(filepath, backup_path)
        logger.info(f"Created backup: {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Failed to create backup: {e}")
        return None

def cleanup_old_files(directory: Path, pattern: str, days_to_keep: int = 30) -> int:
    """Clean up old files matching pattern"""
    from datetime import datetime, timedelta
    
    if not directory.exists():
        return 0
    
    cutoff_date = datetime.now() - timedelta(days=days_to_keep)
    files_removed = 0
    
    for filepath in directory.glob(pattern):
        if filepath.is_file():
            file_mtime = datetime.fromtimestamp(filepath.stat().st_mtime)
            if file_mtime < cutoff_date:
                try:
                    filepath.unlink()
                    files_removed += 1
                    logger.debug(f"Removed old file: {filepath}")
                except Exception as e:
                    logger.error(f"Failed to remove {filepath}: {e}")
    
    logger.info(f"Cleaned up {files_removed} old files from {directory}")
    return files_removed

def retry_on_exception(func, max_attempts: int = 3, delay: float = 1.0, 
                      exceptions: tuple = (Exception,)):
    """Retry function on exception"""
    import time
    
    for attempt in range(max_attempts):
        try:
            return func()
        except exceptions as e:
            if attempt == max_attempts - 1:
                raise
            logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay} seconds...")
            time.sleep(delay)