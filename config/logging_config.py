# File: config/logging_config.py
"""
Logging configuration for Cyber-EW Fusion Cell
"""
import logging
import logging.handlers
from pathlib import Path
import sys

from config.settings import CONFIG

def setup_logging(level: str = "INFO"):
    """Configure logging for the application"""
    
    # Convert string level to logging constant
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create log directory if it doesn't exist
    CONFIG.log_dir.mkdir(exist_ok=True, parents=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear any existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    
    # File handler
    log_file = CONFIG.log_dir / "cyber_ew.log"
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(log_level)
    
    # Audit log handler (separate file for security events)
    if CONFIG.audit_log_enabled:
        audit_file = CONFIG.log_dir / "audit.log"
        audit_handler = logging.handlers.RotatingFileHandler(
            audit_file,
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=3
        )
        audit_handler.setLevel(logging.INFO)
        audit_handler.addFilter(lambda record: hasattr(record, 'audit') and record.audit)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    
    if CONFIG.audit_log_enabled:
        audit_formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        audit_handler.setFormatter(audit_formatter)
    
    # Add handlers
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    
    if CONFIG.audit_log_enabled:
        root_logger.addHandler(audit_handler)
    
    # Set specific loggers to different levels
    logging.getLogger("scapy").setLevel(logging.WARNING)
    logging.getLogger("pyshark").setLevel(logging.WARNING)
    
    # Log startup message
    startup_logger = logging.getLogger("startup")
    startup_logger.info(f"Logging configured. Level: {level}")
    startup_logger.info(f"Log directory: {CONFIG.log_dir}")
    
    if CONFIG.audit_log_enabled:
        startup_logger.info("Audit logging enabled")
    
    # Create audit log function
    def audit_log(message: str, **kwargs):
        """Log audit events"""
        extra = {"audit": True, **kwargs}
        root_logger.info(message, extra=extra)
    
    # Attach audit function to root logger
    root_logger.audit = audit_log