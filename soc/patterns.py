"""Shared payload patterns used by readiness (Stage 6) and the agents' playbooks (Stage 9)."""
from __future__ import annotations

import re
from urllib.parse import urlparse

# Strict SQL-injection indicators: tautologies, UNION SELECT, comment terminators, time delays.
SQLI_STRICT = re.compile(
    r"(?i)(union(\s|\+|/\*.*?\*/)+select|'\s*or\s*'?\d|\bor\s+\d+\s*=\s*\d+|['\"]\s*--|"
    r";\s*drop\s+table|sleep\s*\(|benchmark\s*\(|waitfor\s+delay)")
# Broad "looks SQL-ish" pattern: what the SIEM rule fires on (keywords alone are not an attack).
SQL_LIKE = re.compile(r"(?i)\b(select|union|insert|update|delete|drop|where)\b|'|--|\bor\b\s*\d")
XSS_STRICT = re.compile(r"(?i)<\s*script|onerror\s*=|onload\s*=|javascript:|<\s*svg|<\s*img[^>]+\bon\w+\s*=")
EXEC_URL = re.compile(r"(?i)\.(exe|dll|scr|bat|vbs|ps1|msi)(\?|$)")
RESTRICTED_PORTS = {23, 135, 139, 445, 3389}


def http_text(event: dict) -> str:
    ext = event.get("ext", {})
    return f"{ext.get('url') or ''} {ext.get('request_body') or ''}"


def is_sqli_strict(event: dict) -> bool:
    return event["source_type"] == "HTTP" and bool(SQLI_STRICT.search(http_text(event)))


def sql_input_text(event: dict) -> str:
    """Where SQL syntax can be INPUT: the query string and the request body (never the URL path -
    a path like /update is not SQL)."""
    ext = event.get("ext", {})
    return f"{urlparse(str(ext.get('url') or '')).query} {ext.get('request_body') or ''}"


def is_sql_like(event: dict) -> bool:
    return event["source_type"] == "HTTP" and bool(SQL_LIKE.search(sql_input_text(event)))


def is_xss(event: dict) -> bool:
    return event["source_type"] == "HTTP" and bool(XSS_STRICT.search(http_text(event)))


def is_exec_download(event: dict) -> bool:
    """HTTP 200 returning an executable (URL path ends in an executable extension)."""
    ext = event.get("ext", {})
    return (event["source_type"] == "HTTP" and event["action"] in ("HTTP_REQUEST", "FILE_DOWNLOAD")
            and ext.get("status_code") == 200 and bool(EXEC_URL.search(str(ext.get("url") or ""))))


def is_payload_success(event: dict) -> bool:
    """'HTTP 200 on a payload': 200 response to an exploit payload or an executable download."""
    ext = event.get("ext", {})
    if event["source_type"] != "HTTP" or ext.get("status_code") != 200:
        return False
    return is_exec_download(event) or is_xss(event) or is_sqli_strict(event)
