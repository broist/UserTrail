"""IP-cím segédfüggvények."""

from __future__ import annotations

import ipaddress
from typing import Any

_PLACEHOLDERS = {"", "-"}
_LOCAL_ADDRESSES = {"::1", "127.0.0.1"}


def normalize_ip(value: Any) -> str | None:
    """Megtisztított IP-cím; az IPv4-re leképezett ``::ffff:`` előtagot levágja.

    Ha az érték nem IP-cím, None-t ad vissza.
    """
    if value is None:
        return None
    text = str(value).strip()
    if text in _PLACEHOLDERS:
        return None
    if text.lower().startswith("::ffff:"):
        text = text[7:]
    try:
        ipaddress.ip_address(text)
    except ValueError:
        # Nem IP-cím (pl. az RDP-naplók "LOCAL" értéke vagy egy gépnév).
        return None
    return text


def is_external_ip(ip: str | None) -> bool:
    """Igaz, ha a cím másik gépre mutat (nem üres és nem loopback)."""
    return ip is not None and ip not in _LOCAL_ADDRESSES
