"""IP address helpers."""

from __future__ import annotations

from typing import Any

_PLACEHOLDERS = {"", "-"}
_LOCAL_ADDRESSES = {"::1", "127.0.0.1"}


def normalize_ip(value: Any) -> str | None:
    """Return a cleaned IP string, stripping the IPv4-mapped ``::ffff:`` prefix."""
    if value is None:
        return None
    text = str(value).strip()
    if text in _PLACEHOLDERS:
        return None
    if text.lower().startswith("::ffff:"):
        text = text[7:]
    return text or None


def is_external_ip(ip: str | None) -> bool:
    """True when the address points to another machine (not empty and not loopback)."""
    return ip is not None and ip not in _LOCAL_ADDRESSES
