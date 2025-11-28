"""
Standard logger with rotation support.
Reusable module for logging across projects.
"""

import logging
import logging.handlers
import traceback
from datetime import datetime
from typing import Optional


def setup_json_logging(service_name: str, log_file: str = "application.log") -> None:
    """
    Setup standard logging with rotation.
    
    Args:
        service_name: Name of the service/tool emitting logs
        log_file: Log file name (default: application.log)
    """

    # Define custom log level for TRACE
    TRACE_LEVEL = 5
    logging.addLevelName(TRACE_LEVEL, "TRACE")

    # Create formatter for file handler
    file_formatter = logging.Formatter(
        f'%(asctime)s - %(levelname)s - [{service_name}] - %(message)s - %(event_type)s'
    )

    # Create formatter for console handler
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Clear existing handlers
    logger = logging.getLogger()
    logger.handlers.clear()

    # File handler with rotation (20MB, 5 files)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, 
        maxBytes=20 * 1024 * 1024,  # 20MB
        backupCount=5
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Set default level
    logger.setLevel(logging.INFO)

    # No need for LoggerAdapter since we're using service_name directly in the formatter


def log_trace(message: str, event_type: str) -> None:
    """Log TRACE level message with event context."""
    logger = logging.getLogger()
    # TRACE is level 5
    logger.log(5, message, extra={'event_type': event_type})


def log_debug(message: str, event_type: str) -> None:
    """Log DEBUG level message with event context."""
    logger = logging.getLogger()
    logger.debug(message, extra={'event_type': event_type})


def log_info(message: str, event_type: str) -> None:
    """Log INFO level message with event context."""
    logger = logging.getLogger()
    logger.info(message, extra={'event_type': event_type})


def log_warn(message: str, event_type: str) -> None:
    """Log WARN level message with event context."""
    logger = logging.getLogger()
    logger.warning(message, extra={'event_type': event_type})


def log_error(message: str, event_type: str, error_type: str = "Error", error_message: Optional[str] = None, exc_info: Optional[bool] = None) -> None:
    """
    Log ERROR level message with event context.
    
    Args:
        message: Human-readable log message
        event_type: Event type string (e.g., 'scan.nuclei.error')
        error_type: Type of error (default: 'Error')
        error_message: Specific error message (default: uses message)
        exc_info: Include exception info in stack trace
    """
    logger = logging.getLogger()
    extra = {
        'event_type': event_type,
        'error_type': error_type,
        'error_message': error_message or message
    }
    logger.error(message, extra=extra, exc_info=exc_info)


def log_fatal(message: str, event_type: str, error_type: str = "FatalError", error_message: Optional[str] = None, exc_info: Optional[bool] = None) -> None:
    """
    Log FATAL level message with event context.
    
    Args:
        message: Human-readable log message
        event_type: Event type string (e.g., 'system.startup.fatal')
        error_type: Type of error (default: 'FatalError')
        error_message: Specific error message (default: uses message)
        exc_info: Include exception info in stack trace
    """
    logger = logging.getLogger()
    extra = {
        'event_type': event_type,
        'error_type': error_type,
        'error_message': error_message or message
    }
    logger.critical(message, extra=extra, exc_info=exc_info)
