"""
Centralized logging for PhishGuard SOC.

Design decisions (interview-relevant):
- One shared logger config so every module logs consistently.
- INFO for normal operation, WARNING for recoverable issues (e.g. missing
  header, VT unavailable), ERROR for failures that stop a specific analysis
  step, DEBUG for verbose troubleshooting.
- We NEVER log secrets (API keys, credentials). Callers must not pass
  sensitive values into log messages. This module has no special filtering
  for that — it is a coding discipline enforced by review, documented here
  so it is explicit rather than assumed.
"""

import logging
import sys

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Return a configured logger for the given module name.

    Usage:
        from src.utils.logger import get_logger
        logger = get_logger(__name__)
        logger.info("Parsed email successfully")
    """
    global _configured

    if not _configured:
        logging.basicConfig(
            level=level,
            format=_LOG_FORMAT,
            datefmt=_DATE_FORMAT,
            stream=sys.stdout,
        )
        _configured = True

    return logging.getLogger(name)
