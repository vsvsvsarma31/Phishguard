"""
PhishGuard — URL Obfuscation Decoder
Handles: percent-encoding (%XX), double-encoding, punycode/IDNA,
IP decimal/hex/octal, nested encoding.
"""

from __future__ import annotations

import re
import socket
from urllib.parse import unquote, urlparse


# ── helpers ───────────────────────────────────────────────────────────────────

_HEX_ENCODED_RE = re.compile(r'%[0-9A-Fa-f]{2}')
_DOUBLE_ENC_RE  = re.compile(r'%25[0-9A-Fa-f]{2}')

# Decimal IP:  http://2130706433/  (= 127.0.0.1)
_DECIMAL_IP_RE = re.compile(r'^(\d{7,12})$')
# Hex IP:      http://0x7f000001/
_HEX_IP_RE     = re.compile(r'^0x([0-9a-fA-F]{8})$')
# Octal IP:    http://0177.0.0.1/
_OCTAL_IP_RE   = re.compile(r'^0(\d+)\.0(\d+)\.0(\d+)\.0(\d+)$')


def _decode_ip_host(host: str) -> str | None:
    """
    Try to decode decimal / hex / octal IP to dotted-quad notation.
    Returns the decoded IP string, or None if not applicable.
    """
    host = host.strip("[]")  # strip IPv6 brackets

    # Decimal (e.g. 2130706433)
    m = _DECIMAL_IP_RE.match(host)
    if m:
        n = int(m.group(1))
        try:
            return socket.inet_ntoa(n.to_bytes(4, "big"))
        except Exception:
            pass

    # Hex (e.g. 0x7f000001)
    m = _HEX_IP_RE.match(host)
    if m:
        n = int(m.group(1), 16)
        try:
            return socket.inet_ntoa(n.to_bytes(4, "big"))
        except Exception:
            pass

    # Octal (e.g. 0177.0000.0000.0001)
    m = _OCTAL_IP_RE.match(host)
    if m:
        try:
            parts = [int(g, 8) for g in m.groups()]
            if all(0 <= p <= 255 for p in parts):
                return ".".join(str(p) for p in parts)
        except Exception:
            pass

    return None


def _decode_punycode_host(host: str) -> str:
    """
    Convert IDNA / punycode labels (xn--...) to unicode.
    Swallows errors and returns the original.
    """
    try:
        return host.encode("ascii").decode("idna")
    except Exception:
        try:
            parts = host.split(".")
            decoded_parts = []
            for part in parts:
                if part.lower().startswith("xn--"):
                    decoded_parts.append(part.encode("ascii").decode("punycode"))
                else:
                    decoded_parts.append(part)
            return ".".join(decoded_parts)
        except Exception:
            return host


def _fully_decode_percent(url: str, max_passes: int = 5) -> tuple[str, int]:
    """
    Iteratively percent-decode until stable (handles nested/double encoding).
    Returns (decoded_url, num_passes_needed).
    """
    current = url
    for i in range(max_passes):
        decoded = unquote(current)
        if decoded == current:
            return decoded, i
        current = decoded
    return current, max_passes


# ── public API ────────────────────────────────────────────────────────────────

def decode_url(url: str) -> dict:
    """
    Decode all obfuscation layers in a URL.

    Returns
    -------
    {
        "decoded":        str,   # fully decoded URL
        "was_obfuscated": bool,  # True if any transformation was applied
        "techniques":     list[str],  # detected obfuscation technique names
    }
    """
    original = url
    was_obfuscated = False
    techniques: list[str] = []

    # ── 1. Percent / double encoding ─────────────────────────────────────────
    has_double_enc = bool(_DOUBLE_ENC_RE.search(url))
    has_percent    = bool(_HEX_ENCODED_RE.search(url))

    decoded_url, passes = _fully_decode_percent(url)

    if decoded_url != url:
        was_obfuscated = True
        if has_double_enc:
            techniques.append("double_percent_encoding")
        elif passes > 1:
            techniques.append("nested_percent_encoding")
        else:
            techniques.append("percent_encoding")
        url = decoded_url

    # ── 2. Parse to inspect hostname ─────────────────────────────────────────
    try:
        parsed = urlparse(url)
        host   = parsed.hostname or ""
    except Exception:
        return {
            "decoded":        decoded_url,
            "was_obfuscated": was_obfuscated,
            "techniques":     techniques,
        }

    # ── 3. Decimal / hex / octal IP ──────────────────────────────────────────
    decoded_ip = _decode_ip_host(host)
    if decoded_ip:
        was_obfuscated = True
        techniques.append("ip_obfuscation")
        url = url.replace(host, decoded_ip, 1)
        host = decoded_ip

    # ── 4. Punycode / IDNA ───────────────────────────────────────────────────
    unicode_host = _decode_punycode_host(host)
    if unicode_host != host:
        was_obfuscated = True
        techniques.append("punycode_idna")
        url = url.replace(host, unicode_host, 1)

    return {
        "decoded":        url,
        "was_obfuscated": was_obfuscated,
        "techniques":     techniques,
    }
