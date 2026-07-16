"""
mcp_tools/read_only/api.py

Read-only MCP tool implementations.
All 14 tools are implemented with realistic deterministic mock data.
In production these would call real SIEM / EDR / threat-intel APIs.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_KNOWN_MALICIOUS_IPS = {
    "185.220.101.45": {"reputation": "malicious", "country": "RU", "asn": "AS60781",
                       "tags": ["tor-exit", "botnet-c2"], "confidence": 0.95},
    "45.83.64.1":     {"reputation": "malicious", "country": "NL", "asn": "AS209588",
                       "tags": ["phishing", "malware-distribution"], "confidence": 0.88},
    "103.21.244.0":   {"reputation": "suspicious", "country": "CN", "asn": "AS13335",
                       "tags": ["proxy"], "confidence": 0.60},
}

_KNOWN_MALICIOUS_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": {"malware_family": "Mimikatz",   "severity": 9.0},
    "5d41402abc4b2a76b9719d911017c592": {"malware_family": "Cobalt Strike", "severity": 9.5},
}

_ASSET_DB = {
    "WS-SALES-01":    {"criticality": 3, "owner": "sales@corp.local",   "os": "Windows 11"},
    "SRV-DC-01":      {"criticality": 10, "owner": "it-ops@corp.local",  "os": "Windows Server 2022"},
    "LAPTOP-FIN-07":  {"criticality": 7, "owner": "finance@corp.local", "os": "Windows 11"},
    "unknown":        {"criticality": 5, "owner": "unknown", "os": "unknown"},
}

_USER_DB = {
    "salem":    {"department": "Engineering", "role": "Admin",   "mfa_enabled": True,  "risk_score": 0.2},
    "jdoe":     {"department": "Finance",     "role": "Analyst", "mfa_enabled": True,  "risk_score": 0.1},
    "badactor": {"department": "Unknown",     "role": "Unknown", "mfa_enabled": False, "risk_score": 0.9},
    "unknown":  {"department": "Unknown",     "role": "Unknown", "mfa_enabled": False, "risk_score": 0.5},
}

_MAINTENANCE_WINDOWS = [
    # (weekday 0=Mon, start_hour, end_hour)
    (6, 2, 6),   # Sunday 02:00-06:00
    (5, 22, 24), # Saturday 22:00-24:00
]

# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def getAlertMetadata(alert_id: str, alert_raw: dict) -> dict:
    """Return enriched metadata for the alert."""
    return {
        "alert_id": alert_id,
        "source": alert_raw.get("source", "unknown"),
        "category": alert_raw.get("category", "unknown"),
        "severity_raw": alert_raw.get("severity", 0.0),
        "timestamp": alert_raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }


def getAssetRecord(hostname: Optional[str]) -> dict:
    """Return the asset record for *hostname* from the org knowledge base."""
    key = (hostname or "unknown")
    return _ASSET_DB.get(key, _ASSET_DB["unknown"])


def getUserRecord(username: Optional[str]) -> dict:
    """Return the user record for *username*."""
    key = (username or "unknown")
    return _USER_DB.get(key, _USER_DB["unknown"])


def checkMaintenanceWindow(timestamp: Optional[str] = None) -> bool:
    """Return True if *timestamp* falls inside a scheduled maintenance window."""
    try:
        ts = datetime.fromisoformat(timestamp) if timestamp else datetime.now(timezone.utc)
    except (ValueError, TypeError):
        ts = datetime.now(timezone.utc)

    for weekday, start_hour, end_hour in _MAINTENANCE_WINDOWS:
        if ts.weekday() == weekday and start_hour <= ts.hour < end_hour:
            return True
    return False


def querySIEMLogs(
    query_terms: list[str],
    source_ip: Optional[str] = None,
    user: Optional[str] = None,
    host: Optional[str] = None,
    max_results: int = 20,
) -> list[dict]:
    """Query the SIEM for correlated log events.  Returns mock events."""
    base_time = datetime.now(timezone.utc)
    events = []

    # --- Authentication events ---
    if user or "login" in " ".join(query_terms).lower():
        for i in range(min(3, max_results)):
            events.append({
                "event_id": f"4624-{i}",
                "type": "authentication",
                "timestamp": (base_time - timedelta(minutes=i * 5)).isoformat(),
                "user": user or "unknown",
                "host": host or "WS-SALES-01",
                "source_ip": source_ip or "10.0.0.55",
                "result": "success" if i < 2 else "failure",
                "logon_type": "network",
            })

    # --- Network events if source_ip looks suspicious ---
    if source_ip and source_ip in _KNOWN_MALICIOUS_IPS:
        events.append({
            "event_id": "5156-0",
            "type": "network_connection",
            "timestamp": (base_time - timedelta(minutes=2)).isoformat(),
            "source_ip": source_ip,
            "dest_ip": "10.0.0.10",
            "dest_port": 445,
            "protocol": "TCP",
            "direction": "inbound",
        })
        events.append({
            "event_id": "7045-0",
            "type": "service_install",
            "timestamp": (base_time - timedelta(minutes=1)).isoformat(),
            "host": host or "WS-SALES-01",
            "service_name": "SvcHost32",
            "image_path": "C:\\Windows\\Temp\\svchost32.exe",
        })

    # --- Process events ---
    if host or "process" in " ".join(query_terms).lower():
        events.append({
            "event_id": "4688-0",
            "type": "process_create",
            "timestamp": (base_time - timedelta(minutes=3)).isoformat(),
            "host": host or "WS-SALES-01",
            "parent_process": "WINWORD.EXE",
            "child_process": "cmd.exe",
            "command_line": "cmd.exe /c powershell -enc ...",
            "user": user or "unknown",
        })

    events.sort(key=lambda e: e["timestamp"])
    return events[:max_results]


def getProcessTree(host: Optional[str], pid: Optional[int] = None) -> dict:
    """Return a mock process tree for *host*."""
    return {
        "host": host or "WS-SALES-01",
        "root": {
            "pid": 1234, "name": "WINWORD.EXE", "path": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
            "children": [
                {
                    "pid": 5678, "name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe",
                    "children": [
                        {"pid": 9012, "name": "powershell.exe",
                         "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                         "command_line": "powershell -enc JABjAD0ATgBlAHcA...",
                         "children": []}
                    ]
                }
            ]
        }
    }


def getNetworkConnections(host: Optional[str]) -> list[dict]:
    """Return active network connections for *host*."""
    return [
        {"local_ip": "10.0.0.12", "local_port": 52341, "remote_ip": "185.220.101.45",
         "remote_port": 443, "protocol": "TCP", "state": "ESTABLISHED", "pid": 9012},
        {"local_ip": "10.0.0.12", "local_port": 138,   "remote_ip": "10.0.0.255",
         "remote_port": 138, "protocol": "UDP",  "state": "LISTEN",      "pid": 4},
    ]


def getFileSystemEvent(host: Optional[str], path: Optional[str] = None) -> list[dict]:
    """Return recent file-system events on *host*."""
    base_time = datetime.now(timezone.utc)
    return [
        {"timestamp": (base_time - timedelta(seconds=90)).isoformat(),
         "host": host, "event_type": "file_create",
         "path": path or "C:\\Windows\\Temp\\svchost32.exe",
         "user": "SYSTEM", "size_bytes": 204800},
        {"timestamp": (base_time - timedelta(seconds=45)).isoformat(),
         "host": host, "event_type": "file_execute",
         "path": path or "C:\\Windows\\Temp\\svchost32.exe",
         "user": "SYSTEM", "size_bytes": 204800},
    ]


def lookupIP(ip: Optional[str]) -> dict:
    """Look up IP reputation in threat-intelligence feeds."""
    if not ip:
        return {"ip": None, "reputation": "unknown", "confidence": 0.0}
    record = _KNOWN_MALICIOUS_IPS.get(ip)
    if record:
        return {"ip": ip, **record}
    seed = sum(ord(c) for c in ip)
    r = random.Random(seed)
    return {
        "ip": ip,
        "reputation": r.choice(["clean", "clean", "clean", "suspicious"]),
        "country": r.choice(["US", "DE", "FR", "GB", "NL"]),
        "asn": f"AS{r.randint(1000, 99999)}",
        "tags": [],
        "confidence": round(r.uniform(0.1, 0.4), 2),
    }


def lookupHash(file_hash: Optional[str]) -> dict:
    """Look up file hash in malware databases."""
    if not file_hash:
        return {"hash": None, "known_malicious": False}
    record = _KNOWN_MALICIOUS_HASHES.get(file_hash)
    if record:
        return {"hash": file_hash, "known_malicious": True, **record}
    return {"hash": file_hash, "known_malicious": False, "malware_family": None, "severity": 0.0}


def lookupDomain(domain: Optional[str]) -> dict:
    """Look up domain reputation."""
    if not domain:
        return {"domain": None, "reputation": "unknown"}
    _bad = {"evil.ru", "malware-c2.net", "phish-kit.xyz"}
    return {
        "domain": domain,
        "reputation": "malicious" if domain in _bad else "clean",
        "registrar": "NameCheap" if domain in _bad else "GoDaddy",
        "age_days": 3 if domain in _bad else 1200,
        "confidence": 0.9 if domain in _bad else 0.1,
    }


def getThreatIntelFeed(category: Optional[str] = None) -> list[dict]:
    """Return recent threat-intel items for a given alert category."""
    feed = {
        "impossible_travel": [
            {"title": "APT29 Credential Stuffing Campaign", "severity": "high",
             "iocs": ["185.220.101.45"], "techniques": ["T1078", "T1110"]},
        ],
        "malware": [
            {"title": "QakBot Resurgence via Office Macros", "severity": "critical",
             "iocs": ["45.83.64.1"], "techniques": ["T1566.001", "T1059.001", "T1055"]},
        ],
        "lateral_movement": [
            {"title": "Pass-the-Hash Exploitation via Mimikatz", "severity": "critical",
             "iocs": [], "techniques": ["T1550.002", "T1003.001"]},
        ],
        "data_exfiltration": [
            {"title": "Cloud Storage Exfiltration via HTTPS", "severity": "high",
             "iocs": [], "techniques": ["T1567.002", "T1048"]},
        ],
    }
    return feed.get(category or "", [{"title": "No specific threat intel", "severity": "info", "iocs": [], "techniques": []}])


def generateReport(content: dict) -> str:
    """Format a structured report as a markdown string."""
    lines = [
        "# SOC Incident Report",
        f"**Alert ID**: {content.get('alert_id', 'N/A')}",
        f"**Generated**: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Executive Summary",
        content.get("executive_summary", "No summary available."),
        "",
        "## Verdict",
        f"`{content.get('verdict', 'UNKNOWN')}` -- Confidence: {content.get('confidence', 0):.1%}",
    ]
    return "\n".join(lines)


def logAuditEntry(entry: dict) -> None:
    """Log an audit entry (prints to stdout; in production would write to SIEM)."""
    print(f"[AUDIT] {datetime.now(timezone.utc).isoformat()} | {entry}")
