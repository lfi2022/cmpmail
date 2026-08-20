import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

_logger = logging.getLogger("mailmcp.audit")
if not _logger.handlers:
    Path("logs").mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        "logs/audit.log", maxBytes=20 * 1024 * 1024, backupCount=14, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False


def audit_event(
    *,
    timestamp: str,
    action: str,
    actor: str | None,
    account: str | None = None,
    target: str | None = None,
    success: bool,
    details: dict[str, Any] | None = None,
) -> None:
    """Append a structured event; callers must never provide credentials or bodies."""
    _logger.info(
        json.dumps(
            {
                "timestamp": timestamp,
                "action": action,
                "actor": actor,
                "account": account,
                "target": target,
                "success": success,
                "details": details or {},
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )
