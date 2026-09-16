import os
import math
import hashlib
import urllib.request
import urllib.parse
import json
import ssl
import socket
import random
import sqlite3
import concurrent.futures
import ipaddress
import re
import base64
import requests

from datetime import datetime
from flask import Flask, request, render_template_string, send_file, redirect, url_for, jsonify
from dotenv import load_dotenv
from io import BytesIO, StringIO
import csv
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak


# ============================================================
# TRUVEX CORE
# ============================================================

load_dotenv()

app = Flask(__name__)

DB_NAME = "truvex_soc.db"

HTTP_TIMEOUT = 12
OTX_TIMEOUT = 7
WHOIS_TIMEOUT = 7
GEO_TIMEOUT = 4

USER_AGENT = "Truvex-CTI/2.0 (educational project)"

VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "").strip()
PHISHTANK_APP_KEY = os.getenv("PHISHTANK_APP_KEY", "").strip()

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"


# ============================================================
# DATABASE
# ============================================================

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            type TEXT,
            score INTEGER,
            incident_id TEXT,
            tags TEXT,
            timestamp TEXT,
            report_json TEXT,
            analyst_notes TEXT DEFAULT ''
        )
    """)

    # Safe migration for existing TRUVEX databases.
    columns = {
        row[1]
        for row in cursor.execute("PRAGMA table_info(scans)").fetchall()
    }

    if "report_json" not in columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN report_json TEXT")

    if "analyst_notes" not in columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN analyst_notes TEXT DEFAULT ''")

    conn.commit()
    conn.close()


init_db()


def save_scan_to_db(target, scan_type, score, incident_id, tags, report_data=None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    report_json = json.dumps(report_data, ensure_ascii=False) if report_data else None

    cursor.execute("""
        INSERT INTO scans
        (target, type, score, incident_id, tags, timestamp, report_json, analyst_notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        target,
        scan_type,
        score,
        incident_id,
        ",".join(tags),
        datetime.now().isoformat(timespec="seconds"),
        report_json,
        ""
    ))

    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def update_report_json(scan_id, report_data):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE scans SET report_json = ? WHERE id = ?",
        (json.dumps(report_data, ensure_ascii=False), scan_id)
    )
    conn.commit()
    conn.close()


def get_scans_from_db(search="", verdict="ALL", scan_type="ALL", date_from="", date_to="", limit=10):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    where = []
    params = []

    if search:
        like = f"%{search}%"
        where.append("(target LIKE ? OR incident_id LIKE ? OR tags LIKE ?)")
        params.extend([like, like, like])

    if verdict and verdict != "ALL":
        ranges = {
            "CRITICAL": (75, 100),
            "HIGH": (50, 74),
            "MEDIUM": (25, 49),
            "LOW": (1, 24),
            "CLEAN": (0, 0),
        }
        if verdict in ranges:
            lo, hi = ranges[verdict]
            where.append("score BETWEEN ? AND ?")
            params.extend([lo, hi])

    if scan_type and scan_type != "ALL":
        where.append("type = ?")
        params.append(scan_type)

    if date_from:
        where.append("date(timestamp) >= date(?)")
        params.append(date_from)

    if date_to:
        where.append("date(timestamp) <= date(?)")
        params.append(date_to)

    sql = """
        SELECT id, target, type, score, incident_id, tags, timestamp, analyst_notes
        FROM scans
    """

    if where:
        sql += " WHERE " + " AND ".join(where)

    sql += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))

    cursor.execute(sql, params)
    rows = cursor.fetchall()
    conn.close()

    feed = []

    for row in rows:
        scan_id, target, scan_type, score, incident_id, tags_str, time_str, notes = row
        try:
            item_time = datetime.fromisoformat(time_str)
        except Exception:
            item_time = datetime.now()

        if score >= 75:
            row_verdict = "CRITICAL"
        elif score >= 50:
            row_verdict = "HIGH"
        elif score >= 25:
            row_verdict = "MEDIUM"
        elif score > 0:
            row_verdict = "LOW"
        else:
            row_verdict = "CLEAN"

        feed.append({
            "id": scan_id,
            "target": target,
            "type": scan_type,
            "score": score,
            "verdict": row_verdict,
            "incident_id": incident_id,
            "tags": tags_str.split(",") if tags_str else [],
            "time": item_time,
            "notes": notes or ""
        })

    return feed


def get_dashboard_stats():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*), COALESCE(AVG(score), 0) FROM scans")
    total, avg_score = cursor.fetchone()

    cursor.execute("SELECT COUNT(*) FROM scans WHERE score >= 75")
    critical = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scans WHERE score BETWEEN 50 AND 74")
    high = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scans WHERE score BETWEEN 25 AND 49")
    medium = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scans WHERE score BETWEEN 1 AND 24")
    low = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scans WHERE score = 0")
    clean = cursor.fetchone()[0]

    cursor.execute("""
        SELECT type, COUNT(*)
        FROM scans
        GROUP BY type
        ORDER BY COUNT(*) DESC
    """)
    by_type = cursor.fetchall()

    cursor.execute("""
        SELECT tags, COUNT(*)
        FROM scans
        WHERE tags IS NOT NULL AND tags != ''
        GROUP BY tags
        ORDER BY COUNT(*) DESC
        LIMIT 5
    """)
    top_tags = cursor.fetchall()

    cursor.execute("""
        SELECT COUNT(*) FROM scans
        WHERE timestamp >= datetime('now', '-1 day')
    """)
    last_24h = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM scans
        WHERE timestamp >= datetime('now', '-7 day')
    """)
    last_7d = cursor.fetchone()[0]

    conn.close()

    return {
        "total": total,
        "avg_score": round(avg_score or 0, 1),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "clean": clean,
        "last_24h": last_24h,
        "last_7d": last_7d,
        "by_type": by_type,
        "top_tags": top_tags,
    }


def get_scan_by_id(scan_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, target, type, score, incident_id, tags, timestamp, report_json, analyst_notes
        FROM scans WHERE id = ?
    """, (scan_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    scan_id, target, scan_type, score, incident_id, tags_str, timestamp, report_json, notes = row
    try:
        report = json.loads(report_json) if report_json else None
    except Exception:
        report = None

    return {
        "id": scan_id,
        "target": target,
        "type": scan_type,
        "score": score,
        "incident_id": incident_id,
        "tags": tags_str.split(",") if tags_str else [],
        "timestamp": timestamp,
        "report": report,
        "analyst_notes": notes or ""
    }


def update_analyst_notes(scan_id, notes):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE scans SET analyst_notes = ? WHERE id = ?",
        (notes.strip(), scan_id)
    )
    conn.commit()
    changed = cursor.rowcount
    conn.close()
    return changed


def delete_scan_from_db(scan_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    changed = cursor.rowcount
    conn.close()
    return changed


# ============================================================
# BASIC HELPERS
# ============================================================

def _not_configured(engine, detail):
    return {
        "engine": engine,
        "malicious": False,
        "available": False,
        "status": "NOT_CONFIGURED",
        "detail": detail
    }


def _error_result(engine, detail):
    return {
        "engine": engine,
        "malicious": False,
        "available": False,
        "status": "ERROR",
        "detail": detail
    }


def _bool(value):
    if isinstance(value, bool):
        return value

    return str(value).strip().lower() in {
        "1", "true", "yes", "y"
    }


def normalize_url(target):
    target = target.strip()

    if not re.match(r"^https?://", target, re.I):
        return "http://" + target

    return target


def detect_indicator_type(target):
    """
    Detect:
    - URL
    - IPv4 / IPv6
    - MD5
    - SHA1
    - SHA256
    - Domain
    """

    target = target.strip()

    if re.match(r"^https?://", target, re.I):
        return "url"

    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass

    if re.fullmatch(r"[A-Fa-f0-9]{32}", target):
        return "hash_md5"

    if re.fullmatch(r"[A-Fa-f0-9]{40}", target):
        return "hash_sha1"

    if re.fullmatch(r"[A-Fa-f0-9]{64}", target):
        return "hash_sha256"

    return "domain"


def extract_hostname(target):
    try:
        parsed = urllib.parse.urlparse(
            target if "://" in target else f"http://{target}"
        )

        host = parsed.hostname

        if host:
            return host.lower().strip(".")

    except Exception:
        pass

    return target.strip().lower().strip(".")


# ============================================================
# TRUST DECAY
# ============================================================

def calculate_decay(score):

    if score >= 75:
        return {
            "trend": "Rapid Degrading (Şiddətli risk artımı)",
            "history": [20, 50, score],
            "forecast": (
                "Yüksək riskli profil. Əlavə araşdırma və "
                "monitorinq tövsiyə olunur."
            ),
            "color": "#f43f5e"
        }

    elif score >= 50:
        return {
            "trend": "Elevated Risk (Artmış risk)",
            "history": [15, 35, score],
            "forecast": (
                "Təhdid göstəriciləri müşahidə olunur. "
                "Yaxından izlənilməsi tövsiyə edilir."
            ),
            "color": "#fbbf24"
        }

    elif score > 0:
        return {
            "trend": "Limited Evidence (Məhdud sübut)",
            "history": [5, 10, score],
            "forecast": (
                "Məhdud threat intelligence sübutu mövcuddur. "
                "Risk aşağı səviyyədə qiymətləndirilir."
            ),
            "color": "#fbbf24"
        }

    else:
        return {
            "trend": "Stable / No Evidence",
            "history": [0, 0, 0],
            "forecast": (
                "Mövcud CTI mənbələrində əhəmiyyətli təhlükə "
                "sübutu aşkar edilmədi."
            ),
            "color": "#10b981"
        }


# ============================================================
# MITRE ATT&CK
# ============================================================

MITRE_ATTACK_MAPPING = {

    "phishing": {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may use phishing techniques to "
            "gain access to victim systems."
        )
    },

    "ingress_tool": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may transfer files or payloads "
            "from an external system into the target network."
        )
    },

    "user_execution": {
        "id": "T1204",
        "name": "User Execution",
        "tactic": "Execution",
        "description": (
            "An adversary may rely upon a user opening "
            "a malicious file or executing a payload."
        )
    }
}


def map_to_mitre(target, indicator_type, consensus_score, engines_data):

    # Do not create MITRE mappings from weak evidence.
    if consensus_score < 50:
        return None

    target_lower = target.lower()

    # Verified phishing
    if (
        engines_data.get("phishtank", {}).get("status") == "MALICIOUS"
        or engines_data.get("openphish", {}).get("status") == "MALICIOUS"
    ):
        return MITRE_ATTACK_MAPPING["phishing"]

    # Malware URL / payload transfer
    if (
        engines_data.get("urlhaus", {}).get("status") == "MALICIOUS"
        and (
            "download" in target_lower
            or "payload" in target_lower
            or engines_data.get("urlhaus", {}).get("malware_download")
        )
    ):
        return MITRE_ATTACK_MAPPING["ingress_tool"]

    # File analysis
    if indicator_type == "file":
        return MITRE_ATTACK_MAPPING["user_execution"]

    # IMPORTANT:
    # Do NOT automatically assign T1071 to every IP/domain.
    return None


# ============================================================
# VIRUSTOTAL
# ============================================================

def check_virustotal(target):

    if not VT_API_KEY:
        return _not_configured(
            "VirusTotal",
            "VT_API_KEY .env-də yoxdur"
        )

    indicator_type = detect_indicator_type(target)

    try:

        # ----------------------------------------------------
        # URL
        # ----------------------------------------------------

        if indicator_type == "url":

            encoded = (
                base64.urlsafe_b64encode(
                    target.encode()
                )
                .decode()
                .rstrip("=")
            )

            endpoint = (
                f"https://www.virustotal.com/api/v3/urls/{encoded}"
            )

        # ----------------------------------------------------
        # IP
        # ----------------------------------------------------

        elif indicator_type == "ip":

            endpoint = (
                "https://www.virustotal.com/api/v3/ip_addresses/"
                + target
            )

        # ----------------------------------------------------
        # HASH
        # ----------------------------------------------------

        elif indicator_type in (
            "hash_md5",
            "hash_sha1",
            "hash_sha256"
        ):

            endpoint = (
                "https://www.virustotal.com/api/v3/files/"
                + target
            )

        # ----------------------------------------------------
        # DOMAIN
        # ----------------------------------------------------

        else:

            host = extract_hostname(target)

            endpoint = (
                "https://www.virustotal.com/api/v3/domains/"
                + host
            )

        r = requests.get(
            endpoint,
            headers={
                "x-apikey": VT_API_KEY,
                "Accept": "application/json"
            },
            timeout=HTTP_TIMEOUT
        )

        if r.status_code == 404:

            return {
                "engine": "VirusTotal",
                "malicious": False,
                "available": True,
                "status": "NOT_FOUND",
                "positives": 0,
                "suspicious": 0,
                "total": 0,
                "detail": "VirusTotal-da obyekt tapılmadı."
            }

        if r.status_code == 401:
            return _error_result(
                "VirusTotal",
                "API key etibarsızdır (401)."
            )

        if r.status_code == 429:
            return _error_result(
                "VirusTotal",
                "Rate limit (429)."
            )

        r.raise_for_status()

        data = r.json().get(
            "data",
            {}
        ).get(
            "attributes",
            {}
        )

        stats = data.get(
            "last_analysis_stats",
            {}
        )

        malicious = int(
            stats.get("malicious", 0) or 0
        )

        suspicious = int(
            stats.get("suspicious", 0) or 0
        )

        total = sum(
            int(stats.get(k, 0) or 0)
            for k in (
                "malicious",
                "suspicious",
                "harmless",
                "undetected",
                "timeout",
                "confirmed-timeout"
            )
        )

        if malicious > 0:
            status = "MALICIOUS"
        elif suspicious > 0:
            status = "SUSPICIOUS"
        else:
            status = "CLEAN"

        return {
            "engine": "VirusTotal",
            "malicious": malicious > 0,
            "available": True,
            "status": status,
            "positives": malicious,
            "suspicious": suspicious,
            "total": total,
            "detail": (
                f"Malicious: {malicious} | "
                f"Suspicious: {suspicious} | "
                f"Total: {total}"
            )
        }

    except requests.exceptions.Timeout:

        return _error_result(
            "VirusTotal",
            "Sorğu timeout oldu."
        )

    except Exception as e:

        return _error_result(
            "VirusTotal",
            str(e)
        )


# ============================================================
# URLHAUS
# ============================================================

def check_urlhaus(target):

    if not re.match(r"^https?://", target, re.I):

        return {
            "engine": "URLhaus",
            "malicious": False,
            "available": False,
            "status": "SKIPPED",
            "detail": "URLhaus üçün URL daxil edilməlidir."
        }

    if not URLHAUS_AUTH_KEY:

        return _not_configured(
            "URLhaus",
            "URLHAUS_AUTH_KEY .env-də yoxdur"
        )

    try:

        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={
                "url": normalize_url(target)
            },
            headers={
                "Auth-Key": URLHAUS_AUTH_KEY,
                "User-Agent": USER_AGENT
            },
            timeout=HTTP_TIMEOUT
        )

        if r.status_code in (401, 403):

            return _error_result(
                "URLhaus",
                f"Auth-Key qəbul edilmədi ({r.status_code})."
            )

        r.raise_for_status()

        data = r.json()

        qs = data.get("query_status")

        if qs == "ok":

            tags = data.get("tags") or []

            threat = data.get(
                "threat",
                "unknown"
            )

            url_status = data.get(
                "url_status",
                "unknown"
            )

            malware_download = (
                "payload" in " ".join(tags).lower()
                or "malware" in " ".join(tags).lower()
                or "exe" in " ".join(tags).lower()
            )

            return {
                "engine": "URLhaus",
                "malicious": True,
                "available": True,
                "status": "MALICIOUS",
                "malware_download": malware_download,
                "detail": (
                    f"Threat: {threat} | "
                    f"Status: {url_status} | "
                    f"Tags: {', '.join(tags) if tags else 'none'}"
                )
            }

        if qs == "no_results":

            return {
                "engine": "URLhaus",
                "malicious": False,
                "available": True,
                "status": "NOT_LISTED",
                "detail": (
                    "URL URLhaus database-də tapılmadı."
                )
            }

        return {
            "engine": "URLhaus",
            "malicious": False,
            "available": True,
            "status": "UNKNOWN",
            "detail": f"query_status: {qs}"
        }

    except requests.exceptions.Timeout:

        return _error_result(
            "URLhaus",
            "Sorğu timeout oldu."
        )

    except Exception as e:

        return _error_result(
            "URLhaus",
            str(e)
        )


# ============================================================
# ABUSEIPDB
# ============================================================

def check_abuseipdb(target):

    try:
        ipaddress.ip_address(target)

    except ValueError:

        host = extract_hostname(target)

        try:

            target = socket.gethostbyname(host)

        except Exception:

            return {
                "engine": "AbuseIPDB",
                "malicious": False,
                "available": False,
                "status": "SKIPPED",
                "detail": "IP həll edilə bilmədi."
            }

    if not ABUSEIPDB_API_KEY:

        return _not_configured(
            "AbuseIPDB",
            "ABUSEIPDB_API_KEY .env-də yoxdur"
        )

    try:

        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={
                "ipAddress": target,
                "maxAgeInDays": 90
            },
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            },
            timeout=HTTP_TIMEOUT
        )

        if r.status_code == 401:

            return _error_result(
                "AbuseIPDB",
                "API key etibarsızdır (401)."
            )

        r.raise_for_status()

        d = r.json().get(
            "data",
            {}
        )

        conf = int(
            d.get(
                "abuseConfidenceScore",
                0
            ) or 0
        )

        reports = int(
            d.get(
                "totalReports",
                0
            ) or 0
        )

        malicious = conf >= 70

        if malicious:
            status = "MALICIOUS"
        elif conf > 0:
            status = "SUSPICIOUS"
        else:
            status = "CLEAN"

        return {
            "engine": "AbuseIPDB",
            "malicious": malicious,
            "available": True,
            "status": status,
            "confidence": conf,
            "detail": (
                f"Abuse Confidence: {conf}% | "
                f"Reports: {reports}"
            )
        }

    except requests.exceptions.Timeout:

        return _error_result(
            "AbuseIPDB",
            "Sorğu timeout oldu."
        )

    except Exception as e:

        return _error_result(
            "AbuseIPDB",
            str(e)
        )


# ============================================================
# ALIENVAULT OTX
# ============================================================

def check_alienvault_otx(target):

    host = extract_hostname(target)

    try:

        ipaddress.ip_address(host)

        if ":" in host:
            kind = "IPv6"
        else:
            kind = "IPv4"

        value = host

    except ValueError:

        kind = "domain"
        value = host

    try:

        endpoint = (
            f"https://otx.alienvault.com/api/v1/"
            f"indicators/{kind}/"
            f"{urllib.parse.quote(value, safe='')}/general"
        )

        r = requests.get(
            endpoint,
            headers={
                "User-Agent": USER_AGENT
            },
            timeout=OTX_TIMEOUT
        )

        r.raise_for_status()

        d = r.json()

        count = int(
            d.get(
                "pulse_info",
                {}
            ).get(
                "count",
                0
            ) or 0
        )

        malicious = count > 0

        return {
            "engine": "AlienVault OTX",
            "malicious": malicious,
            "available": True,
            "status": (
                "MALICIOUS"
                if malicious
                else "NOT_LISTED"
            ),
            "pulses": count,
            "detail": f"Threat Pulses: {count}"
        }

    except requests.exceptions.Timeout:

        return _error_result(
            "AlienVault OTX",
            f"OTX timeout oldu ({OTX_TIMEOUT}s)."
        )

    except Exception as e:

        return _error_result(
            "AlienVault OTX",
            str(e)
        )


# ============================================================
# PHISHTANK
# ============================================================

def check_phishtank(target):

    if not re.match(r"^https?://", target, re.I):

        return {
            "engine": "PhishTank",
            "malicious": False,
            "available": False,
            "status": "SKIPPED",
            "detail": (
                "PhishTank üçün URL daxil edilməlidir."
            )
        }

    try:

        payload = {
            "url": normalize_url(target),
            "format": "json"
        }

        if PHISHTANK_APP_KEY:
            payload["app_key"] = PHISHTANK_APP_KEY

        r = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data=payload,
            headers={
                "User-Agent": "phishtank/truvex"
            },
            timeout=HTTP_TIMEOUT
        )

        if r.status_code == 509:

            return _error_result(
                "PhishTank",
                "Rate limit (509)."
            )

        r.raise_for_status()

        results = r.json().get(
            "results",
            {}
        )

        entries = []

        if isinstance(results, dict):

            if any(
                k in results
                for k in (
                    "in_database",
                    "verified",
                    "valid"
                )
            ):
                entries.append(results)

            for v in results.values():

                if isinstance(v, dict):
                    entries.append(v)

        for item in entries:

            if (
                _bool(item.get("in_database"))
                and _bool(item.get("verified"))
                and _bool(item.get("valid"))
            ):

                return {
                    "engine": "PhishTank",
                    "malicious": True,
                    "available": True,
                    "status": "MALICIOUS",
                    "detail": (
                        "Verified phishing URL"
                    )
                }

            if _bool(item.get("in_database")):

                return {
                    "engine": "PhishTank",
                    "malicious": False,
                    "available": True,
                    "status": "SUSPICIOUS",
                    "detail": (
                        "URL database-də var, "
                        "lakin tam verified/valid deyil."
                    )
                }

        return {
            "engine": "PhishTank",
            "malicious": False,
            "available": True,
            "status": "NOT_LISTED",
            "detail": (
                "URL PhishTank database-də tapılmadı."
            )
        }

    except requests.exceptions.Timeout:

        return _error_result(
            "PhishTank",
            "Sorğu timeout oldu."
        )

    except Exception as e:

        return _error_result(
            "PhishTank",
            str(e)
        )


# ============================================================
# OPENPHISH
# ============================================================

def check_openphish(target):

    if not re.match(r"^https?://", target, re.I):

        return {
            "engine": "OpenPhish",
            "malicious": False,
            "available": False,
            "status": "SKIPPED",
            "detail": "URL tələb olunur."
        }

    try:

        r = requests.get(
            OPENPHISH_FEED_URL,
            headers={
                "User-Agent": USER_AGENT
            },
            timeout=HTTP_TIMEOUT
        )

        r.raise_for_status()

        normalized = normalize_url(
            target
        ).rstrip("/")

        found = any(
            line.strip().rstrip("/") == normalized
            for line in r.text.splitlines()
            if line.strip()
            and not line.startswith("#")
        )

        return {
            "engine": "OpenPhish",
            "malicious": found,
            "available": True,
            "status": (
                "MALICIOUS"
                if found
                else "NOT_LISTED"
            ),
            "detail": (
                "URL OpenPhish feed-də tapıldı."
                if found
                else
                "URL OpenPhish feed-də tapılmadı."
            )
        }

    except requests.exceptions.Timeout:

        return _error_result(
            "OpenPhish",
            "Sorğu timeout oldu."
        )

    except Exception as e:

        return _error_result(
            "OpenPhish",
            str(e)
        )


# ============================================================
# GEOLOCATION / DNS
# ============================================================

def get_ip_geolocation(target):

    resolved_domain = "Reverse DNS tapılmadı"

    try:

        host = extract_hostname(target)

        # ----------------------------------------------------
        # Reverse DNS
        # ----------------------------------------------------

        try:

            ipaddress.ip_address(host)

            try:
                resolved_domain = socket.gethostbyaddr(host)[0]
            except Exception:
                resolved_domain = "Reverse DNS tapılmadı"

        except ValueError:
            pass

        # ----------------------------------------------------
        # Resolve domain → IPv4
        # ----------------------------------------------------

        try:

            ip = socket.gethostbyname(host)

        except Exception:

            return (
                "Naməlum",
                "Bilinmir",
                "🌍",
                resolved_domain
            )

        # ----------------------------------------------------
        # IP Geolocation
        # ----------------------------------------------------

        url = f"http://ip-api.com/json/{ip}"

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Truvex-SOC"
            }
        )

        with urllib.request.urlopen(
            req,
            timeout=GEO_TIMEOUT
        ) as resp:

            data = json.loads(
                resp.read().decode()
            )

        if data.get("status") == "success":

            country = data.get(
                "country",
                "Bilinmir"
            )

            city = data.get(
                "city",
                ""
            )

            c_code = data.get(
                "countryCode",
                ""
            )

            if len(c_code) == 2:

                flag = (
                    chr(127397 + ord(c_code[0]))
                    + chr(127397 + ord(c_code[1]))
                )

            else:
                flag = "🌍"

            return (
                ip,
                f"{country} ({city})" if city else country,
                flag,
                resolved_domain
            )

    except Exception:
        pass

    return (
        "Naməlum",
        "Bilinmir",
        "🌍",
        resolved_domain
    )


# ============================================================
# DOMAIN RDAP
# ============================================================

def check_domain_whois(target):

    try:

        domain = extract_hostname(target)

        try:
            ipaddress.ip_address(domain)

            return (
                False,
                None,
                "IP ünvanıdır — domen yaşı tətbiq edilmir."
            )

        except ValueError:
            pass

        # RDAP public service
        endpoint = (
            "https://rdap.org/domain/"
            + urllib.parse.quote(domain)
        )

        r = requests.get(
            endpoint,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/rdap+json"
            },
            timeout=WHOIS_TIMEOUT
        )

        if r.status_code == 404:

            return (
                False,
                None,
                "Domen qeydiyyat məlumatı tapılmadı."
            )

        r.raise_for_status()

        data = r.json()

        events = data.get(
            "events",
            []
        )

        registration_date = None

        for event in events:

            if event.get("eventAction") in (
                "registration",
                "registered"
            ):

                registration_date = event.get(
                    "eventDate"
                )

                break

        if not registration_date:

            return (
                True,
                None,
                "Domen yaşı: məlumat mövcud deyil."
            )

        try:

            created = datetime.fromisoformat(
                registration_date.replace(
                    "Z",
                    "+00:00"
                )
            )

            now = datetime.now(
                created.tzinfo
            )

            age_days = max(
                0,
                (now - created).days
            )

            return (
                True,
                age_days,
                f"Domen yaşı: {age_days} gün"
            )

        except Exception:

            return (
                True,
                None,
                "Domen yaşı hesablana bilmədi."
            )

    except requests.exceptions.Timeout:

        return (
            False,
            None,
            "RDAP sorğusu timeout oldu."
        )

    except Exception:

        return (
            False,
            None,
            "Domen yaşı müəyyən edilə bilmədi."
        )


# ============================================================
# SSL
# ============================================================

def check_ssl_certificate(target):

    try:

        hostname = extract_hostname(target)

        ctx = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443),
            timeout=4
        ) as sock:

            with ctx.wrap_socket(
                sock,
                server_hostname=hostname
            ) as ssock:

                cert = ssock.getpeercert()

                issuer = dict(
                    x[0]
                    for x in cert.get(
                        "issuer",
                        []
                    )
                ).get(
                    "organizationName",
                    "Valid CA"
                )

                return (
                    True,
                    f"SSL Aktiv ({issuer})"
                )

    except Exception:

        return (
            False,
            "SSL Sertifikatı yoxdur / yoxlanılmadı"
        )


# ============================================================
# TTI ENGINE
# ============================================================

def calculate_tti(cti):

    score = 0
    evidence = []

    # --------------------------------------------------------
    # VIRUSTOTAL
    # --------------------------------------------------------

    vt = cti.get(
        "vt",
        {}
    )

    if vt.get("available"):

        malicious = int(
            vt.get(
                "positives",
                0
            ) or 0
        )

        total = int(
            vt.get(
                "total",
                0
            ) or 0
        )

        suspicious = int(
            vt.get(
                "suspicious",
                0
            ) or 0
        )

        if total > 0:

            ratio = malicious / total

            # Very strong consensus
            if ratio >= 0.20:

                score += 35

                evidence.append(
                    "VirusTotal: high malicious ratio"
                )

            # Moderate consensus
            elif ratio >= 0.05:

                score += 20

                evidence.append(
                    "VirusTotal: elevated malicious ratio"
                )

            # Limited detections
            elif ratio > 0:

                score += 5

                evidence.append(
                    "VirusTotal: limited detections"
                )

        if suspicious > 0 and malicious == 0:

            score += 3

            evidence.append(
                "VirusTotal: suspicious engines"
            )

    # --------------------------------------------------------
    # URLHAUS
    # --------------------------------------------------------

    urlhaus = cti.get(
        "urlhaus",
        {}
    )

    if urlhaus.get("status") == "MALICIOUS":

        score += 30

        evidence.append(
            "URLhaus: malicious URL"
        )

    # --------------------------------------------------------
    # PHISHTANK
    # --------------------------------------------------------

    phish = cti.get(
        "phishtank",
        {}
    )

    if phish.get("status") == "MALICIOUS":

        score += 30

        evidence.append(
            "PhishTank: verified phishing"
        )

    # --------------------------------------------------------
    # OPENPHISH
    # --------------------------------------------------------

    openphish = cti.get(
        "openphish",
        {}
    )

    if openphish.get("status") == "MALICIOUS":

        score += 30

        evidence.append(
            "OpenPhish: malicious URL"
        )

    # --------------------------------------------------------
    # ABUSEIPDB
    # --------------------------------------------------------

    abuse = cti.get(
        "abuseipdb",
        {}
    )

    confidence = int(
        abuse.get(
            "confidence",
            0
        ) or 0
    )

    if abuse.get("available"):

        if confidence >= 90:

            score += 25

            evidence.append(
                "AbuseIPDB: very high confidence"
            )

        elif confidence >= 70:

            score += 20

            evidence.append(
                "AbuseIPDB: high confidence"
            )

        elif confidence >= 50:

            score += 10

            evidence.append(
                "AbuseIPDB: moderate confidence"
            )

    # --------------------------------------------------------
    # OTX
    # --------------------------------------------------------

    otx = cti.get(
        "otx",
        {}
    )

    if otx.get("status") == "MALICIOUS":

        score += 10

        evidence.append(
            "AlienVault OTX: threat pulses found"
        )

    # --------------------------------------------------------
    # LIMIT
    # --------------------------------------------------------

    score = min(
        max(score, 0),
        100
    )

    # --------------------------------------------------------
    # VERDICT
    # --------------------------------------------------------

    if score >= 75:

        verdict = "CRITICAL"

    elif score >= 50:

        verdict = "HIGH"

    elif score >= 25:

        verdict = "MEDIUM"

    elif score > 0:

        verdict = "LOW"

    else:

        verdict = "CLEAN"

    return score, verdict, evidence


# ============================================================
# HTML
# ============================================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="az">

<head>

<meta charset="UTF-8">

<title>
Truvex v16.0 | CTI Platform
</title>

<style>

body {
    font-family:
        'Segoe UI',
        Tahoma,
        Geneva,
        Verdana,
        sans-serif;

    background: #07090e;
    color: #f8fafc;

    margin: 0;
    padding: 30px;

    display: flex;
    justify-content: center;
}

.container {

    width: 1040px;

    background: #0d1322;

    padding: 40px;

    border-radius: 16px;

    box-shadow:
        0 15px 35px rgba(0,0,0,0.9);

    border:
        1px solid #1e293b;
}

.top-bar {

    display: flex;

    justify-content:
        space-between;

    align-items: center;

    margin-bottom: 10px;
}

.logo-area {

    display: flex;

    align-items: center;

    gap: 12px;
}

h2 {

    color: #38bdf8;

    margin: 0;

    font-size: 26px;

    letter-spacing: 1.5px;

    font-weight: 800;
}

.subtitle {

    color: #64748b;

    font-size: 12px;

    margin-bottom: 25px;

    text-transform: uppercase;

    letter-spacing: 2px;

    font-weight: 600;
}

.tabs {

    display: flex;

    justify-content: center;

    gap: 12px;

    margin-bottom: 25px;
}

.tab-btn {

    background: #111827;

    color: #94a3b8;

    border:
        1px solid #1f2937;

    padding:
        10px 22px;

    border-radius: 8px;

    cursor: pointer;

    font-weight: 600;
}

.tab-btn.active {

    background: #0284c7;

    color: white;

    border-color: #0284c7;
}

.section-box {

    display: none;

    border:
        2px dashed #1e293b;

    padding: 30px;

    text-align: center;

    border-radius: 12px;

    background: #0b0f19;
}

.section-box.active {

    display: block;
}

input[type="text"] {

    color: #cbd5e1;

    margin-bottom: 15px;

    padding: 11px;

    width: 75%;

    background: #131b2e;

    border:
        1px solid #334155;

    border-radius: 6px;
}

button[type="submit"] {

    padding:
        11px 24px;

    background: #0284c7;

    color: white;

    border: none;

    border-radius: 6px;

    cursor: pointer;

    font-weight: bold;

    font-size: 14px;
}

.results {

    margin-top: 30px;

    background: #0b0f19;

    padding: 30px;

    border-radius: 12px;

    border:
        1px solid #1e293b;

    text-align: left;
}

.risk-critical {

    color: #f43f5e;

    font-weight: 850;

    background:
        rgba(244,63,94,0.1);

    padding: 4px 10px;

    border-radius: 4px;

    border:
        1px solid rgba(244,63,94,0.3);
}

.risk-safe {

    color: #10b981;

    font-weight: 850;

    background:
        rgba(16,185,129,0.1);

    padding: 4px 10px;

    border-radius: 4px;

    border:
        1px solid rgba(16,185,129,0.3);
}

.risk-low {

    color: #fbbf24;

    font-weight: 850;
}

.incident-badge {

    background: #1e1b4b;

    border:
        1px solid #4f46e5;

    padding: 12px 18px;

    border-radius: 8px;

    margin-bottom: 20px;

    display: flex;

    justify-content: space-between;

    align-items: center;
}

.mitre-box {

    background: #18122b;

    border:
        1px solid #7c3aed;

    padding: 15px;

    border-radius: 8px;

    margin-top: 20px;
}

.decay-box {

    background: #111827;

    border:
        1px solid #334155;

    padding: 15px;

    border-radius: 8px;

    margin-top: 20px;
}

.tag {

    background: #334155;

    color: #e2e8f0;

    padding: 2px 8px;

    border-radius: 4px;

    font-size: 11px;

    font-weight: 600;

    margin-right: 5px;
}

.cti-grid {

    display: grid;

    grid-template-columns:
        1fr 1fr 1fr;

    gap: 12px;

    margin-top: 20px;
}

.cti-card {

    background: #131b2e;

    border:
        1px solid #334155;

    padding: 14px;

    border-radius: 8px;

    font-size: 13px;
}

.ai-report {

    background: #12102e;

    border:
        1px solid #4f46e5;

    padding: 22px;

    border-radius: 10px;

    margin-top: 25px;

    color: #e0e7ff;

    line-height: 1.7;
}

.feed-section {

    margin-top: 35px;

    background: #0b0f19;

    border:
        1px solid #1e293b;

    padding: 20px;

    border-radius: 12px;
}

.feed-item {

    display: flex;

    justify-content:
        space-between;

    align-items: center;

    padding: 8px 12px;

    border-bottom:
        1px solid #131b2e;

    font-size: 12px;

    color: #94a3b8;
}

.footer {

    text-align: center;

    margin-top: 40px;

    color: #475569;

    font-size: 12px;
}


.dashboard-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:18px 0}.stat-card{background:#0b1220;border:1px solid #1e293b;border-radius:10px;padding:14px}.stat-card span{display:block;color:#64748b;font-size:10px;text-transform:uppercase}.stat-card strong{display:block;color:#e2e8f0;font-size:25px;margin:6px 0}.stat-card small{color:#475569;font-size:10px}.analytics-box{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:15px}.analytics-col,.filter-box{background:#0b1220;border:1px solid #1e293b;border-radius:10px;padding:14px}.analytics-col h4{margin:0 0 10px;color:#38bdf8;font-size:11px;text-transform:uppercase}.mini-bars div,.type-line{display:flex;justify-content:space-between;padding:5px 0;color:#94a3b8;font-size:11px;border-bottom:1px solid #111827}.mini-bars b,.type-line b{color:#e2e8f0}.filter-form{display:flex;gap:8px;flex-wrap:wrap}.filter-form input,.filter-form select{background:#07090e;color:#cbd5e1;border:1px solid #334155;border-radius:6px;padding:8px;font-size:11px}.filter-form button,.clear-btn,.action-btn,.delete-btn{border:1px solid #334155;background:#111827;color:#cbd5e1;border-radius:6px;padding:7px 10px;text-decoration:none;font-size:10px;cursor:pointer}.clear-btn{display:inline-flex;align-items:center}.feed-main{display:flex;justify-content:space-between;gap:12px;align-items:center;flex:1}.feed-actions{display:flex;gap:5px;align-items:center}.feed-actions form{margin:0}.score-critical{color:#f43f5e}.score-high{color:#fb7185}.score-medium{color:#fbbf24}.score-low{color:#f59e0b}.score-clean{color:#10b981}.feed-item{display:flex;justify-content:space-between;gap:10px;align-items:center}.muted{color:#475569;font-size:11px}.incident-page{background:#0b1220;border:1px solid #1e293b;border-radius:10px;padding:20px;margin-top:20px}.incident-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.detail-card{background:#07090e;border:1px solid #1e293b;border-radius:8px;padding:12px}.detail-card span{display:block;color:#64748b;font-size:10px;text-transform:uppercase}.detail-card b{display:block;color:#e2e8f0;margin-top:5px;word-break:break-word}.notes-area{width:100%;box-sizing:border-box;min-height:110px;background:#07090e;color:#cbd5e1;border:1px solid #334155;border-radius:8px;padding:10px}.report-btn{display:inline-block;background:#0f172a;border:1px solid #38bdf8;color:#38bdf8;padding:7px 10px;border-radius:6px;text-decoration:none;font-size:11px}
@media(max-width:900px){.dashboard-grid{grid-template-columns:repeat(3,1fr)}.analytics-box{grid-template-columns:1fr}.incident-grid{grid-template-columns:1fr}.feed-item{flex-direction:column;align-items:stretch}.feed-main{flex-direction:column;align-items:flex-start}}

</style>


<script>

function switchTab(tabName) {

    document
        .getElementById('file-section')
        .classList
        .remove('active');

    document
        .getElementById('domain-section')
        .classList
        .remove('active');

    document
        .getElementById('btn-file')
        .classList
        .remove('active');

    document
        .getElementById('btn-domain')
        .classList
        .remove('active');


    if (tabName === 'file') {

        document
            .getElementById('file-section')
            .classList
            .add('active');

        document
            .getElementById('btn-file')
            .classList
            .add('active');

    } else {

        document
            .getElementById('domain-section')
            .classList
            .add('active');

        document
            .getElementById('btn-domain')
            .classList
            .add('active');
    }
}

</script>

</head>


<body>

<div class="container">


<div class="top-bar">

    <div class="logo-area">

        <span>🛡️</span>

        <h2>
            TRUVEX CORE - CTI PLATFORM
        </h2>

    </div>

</div>


<div class="subtitle">

Multi-Source Threat Intelligence & IOC Analysis

</div>


<div class="tabs">

<button
    id="btn-file"
    class="tab-btn"
    onclick="switchTab('file')"
>
📁 File Analysis
</button>


<button
    id="btn-domain"
    class="tab-btn active"
    onclick="switchTab('domain')"
>
🌐 URL / Domain / IP / Hash
</button>

</div>


<!-- DASHBOARD -->
<div class="dashboard-grid">
    <div class="stat-card"><span>Total Scans</span><strong>{{ stats.total }}</strong><small>All telemetry records</small></div>
    <div class="stat-card"><span>Critical</span><strong>{{ stats.critical }}</strong><small>TTI ≥ 75</small></div>
    <div class="stat-card"><span>High</span><strong>{{ stats.high }}</strong><small>TTI 50–74</small></div>
    <div class="stat-card"><span>Average TTI</span><strong>{{ stats.avg_score }}</strong><small>Across all scans</small></div>
    <div class="stat-card"><span>Last 24h</span><strong>{{ stats.last_24h }}</strong><small>New telemetry</small></div>
    <div class="stat-card"><span>Last 7d</span><strong>{{ stats.last_7d }}</strong><small>New telemetry</small></div>
</div>

<div class="analytics-box">
    <div class="analytics-col">
        <h4>Severity Distribution</h4>
        <div class="mini-bars">
            <div><span>CRITICAL</span><b>{{ stats.critical }}</b></div>
            <div><span>HIGH</span><b>{{ stats.high }}</b></div>
            <div><span>MEDIUM</span><b>{{ stats.medium }}</b></div>
            <div><span>LOW</span><b>{{ stats.low }}</b></div>
            <div><span>CLEAN</span><b>{{ stats.clean }}</b></div>
        </div>
    </div>
    <div class="analytics-col">
        <h4>Indicator Types</h4>
        {% for typ, count in stats.by_type %}<div class="type-line"><span>{{ typ }}</span><b>{{ count }}</b></div>{% else %}<div class="muted">No data</div>{% endfor %}
    </div>
    <div class="analytics-col">
        <h4>Top Tags</h4>
        {% for tag, count in stats.top_tags %}<div class="type-line"><span>{{ tag }}</span><b>{{ count }}</b></div>{% else %}<div class="muted">No data</div>{% endfor %}
    </div>
</div>

<div class="filter-box">
    <form action="/" method="GET" class="filter-form">
        <input type="text" name="search" value="{{ filters.search }}" placeholder="Search IOC, incident ID or tag">
        <select name="verdict">
            {% for v in ["ALL","CRITICAL","HIGH","MEDIUM","LOW","CLEAN"] %}
            <option value="{{ v }}" {% if filters.verdict == v %}selected{% endif %}>{{ v }}</option>
            {% endfor %}
        </select>
        <select name="scan_type">
            {% for v in ["ALL","pure-cti","fayl","demo"] %}
            <option value="{{ v }}" {% if filters.scan_type == v %}selected{% endif %}>{{ v }}</option>
            {% endfor %}
        </select>
        <input type="date" name="date_from" value="{{ filters.date_from }}">
        <input type="date" name="date_to" value="{{ filters.date_to }}">
        <button type="submit">🔎 Filter</button>
        <a class="clear-btn" href="/">Clear</a>
    </form>
</div>

<!-- FILE -->

<div
    id="file-section"
    class="section-box"
>

<form
    action="/analyze-file"
    method="POST"
    enctype="multipart/form-data"
>

<input
    type="file"
    name="file"
    required
    style="
        color:#cbd5e1;
        margin-bottom:15px;
    "
>

<br>

<button type="submit">
    Faylı Hash ilə Analiz Et
</button>

</form>

</div>


<!-- DOMAIN / URL / IP / HASH -->

<div
    id="domain-section"
    class="section-box active"
>

<form
    action="/analyze-domain"
    method="POST"
>

<input
    type="text"
    name="domain"
    placeholder="URL, domain, IP və ya MD5/SHA1/SHA256 hash daxil edin"
    required
>

<br>

<button type="submit">
    CTI Analizini Başlat
</button>

</form>

</div>


{% if result %}

<div class="results">


{% if result.incident_id %}

<div class="incident-badge">

<div>

<span
style="
font-size:11px;
color:#a5b4fc;
text-transform:uppercase;
font-weight:bold;
"
>
Avtomatik İnsident Bilet Generatoru
</span>

<div
style="
font-size:15px;
color:#fff;
font-weight:bold;
margin-top:2px;
"
>

{{ result.incident_id }}

<span
style="
font-size:11px;
color:#f43f5e;
background:rgba(244,63,94,0.2);
padding:2px 6px;
border-radius:4px;
margin-left:8px;
"
>
SEVERITY:
{{ result.verdict }}
</span>

</div>

</div>


<div>

{% for tag in result.tags %}

<span class="tag">
{{ tag }}
</span>

{% endfor %}

</div>

</div>

{% endif %}


<h3>

📊 Truvex Threat Intelligence Hesabatı:

<span style="color:#38bdf8;">

{{ result.target }}

</span>

</h3>


<p>

<strong>Indicator Type:</strong>

<span style="color:#c084fc;font-weight:bold;">

{{ result.indicator_type }}

</span>

</p>


{% if result.indicator_type not in
['hash_md5','hash_sha1','hash_sha256'] %}

<p>

<strong>Server IP & Geo-Location:</strong>

<span
style="
color:#38bdf8;
font-weight:bold;
"
>

{{ result.geo_flag }}
{{ result.geo_country }}

</span>

(<code>{{ result.ip }}</code>)

|

<strong>Reverse DNS:</strong>

<span style="color:#c084fc;">

{{ result.resolved_domain }}

</span>

</p>


<p>

<strong>Domen Yaşı:</strong>

{{ result.whois_info }}

|

<strong>SSL:</strong>

{{ result.ssl_info }}

</p>

{% endif %}


<p>

<strong>
Truvex Threat Index (TTI):
</strong>


{% if result.verdict in ["CRITICAL", "HIGH"] %}

<span class="risk-critical">

{{ result.score }} / 100

({{ result.verdict }})

</span>


{% elif result.verdict == "MEDIUM" %}

<span
style="
color:#fbbf24;
font-weight:850;
"
>

{{ result.score }} / 100

(MEDIUM)

</span>


{% elif result.verdict == "LOW" %}

<span class="risk-low">

{{ result.score }} / 100

(LOW)

</span>


{% else %}

<span class="risk-safe">

{{ result.score }} / 100

(CLEAN)

</span>

{% endif %}

</p>


<!-- DECAY -->

<div class="decay-box">

<h4
style="
margin:0 0 8px 0;
color:#38bdf8;
"
>

📈 Trust-Decay Trajectory

</h4>


<p
style="
margin:0 0 6px 0;
font-size:13px;
color:#cbd5e1;
"
>

<strong>Trend:</strong>

<span
style="color:{{ result.decay.color }};"
>

{{ result.decay.trend }}

</span>

</p>


<p
style="
margin:0;
font-size:12px;
color:#94a3b8;
"
>

{{ result.decay.forecast }}

</p>

</div>


<!-- MITRE -->

{% if result.mitre %}

<div class="mitre-box">

<h4
style="
margin:0 0 8px 0;
color:#c084fc;
"
>

🎯 MITRE ATT&CK Mapping

</h4>


<span
style="
background:#7c3aed;
color:white;
padding:3px 8px;
border-radius:4px;
font-weight:bold;
font-size:12px;
"
>

{{ result.mitre.id }}
-
{{ result.mitre.name }}

</span>


<span
style="
color:#cbd5e1;
font-size:13px;
margin-left:8px;
"
>

<b>Taktika:</b>

{{ result.mitre.tactic }}

</span>


<p
style="
margin:8px 0 0 0;
font-size:12px;
color:#94a3b8;
"
>

{{ result.mitre.description }}

</p>

</div>

{% else %}

<div
style="
margin-top:20px;
padding:14px;
background:#111827;
border:1px solid #334155;
border-radius:8px;
color:#94a3b8;
font-size:12px;
"
>

🎯 <strong>MITRE ATT&CK:</strong>

No confirmed technique based on current CTI evidence.

</div>

{% endif %}


<!-- CTI -->

<h4
style="
color:#a5b4fc;
margin-top:25px;
margin-bottom:10px;
"
>

🌐 Qlobal CTI Mühərrik Konsensusu

</h4>


<div class="cti-grid">


<!-- VT -->

<div class="cti-card">

<strong>
VirusTotal:
</strong>

<br>

<span
style="
color:
{% if result.cti.vt.status == 'MALICIOUS' %}
#f43f5e
{% elif result.cti.vt.status == 'SUSPICIOUS' %}
#fbbf24
{% elif result.cti.vt.status in ['CLEAN','NOT_FOUND'] %}
#10b981
{% else %}
#94a3b8
{% endif %}
"
>

{{ result.cti.vt.get('positives', 0) }}

/

{{ result.cti.vt.get('total', 0) }}

—

{{ result.cti.vt.status }}

</span>

<br>

<small style="color:#64748b;">

{{ result.cti.vt.detail }}

</small>

</div>


<!-- URLHAUS -->

<div class="cti-card">

<strong>
URLhaus:
</strong>

<br>

<span
style="
color:
{% if result.cti.urlhaus.status == 'MALICIOUS' %}
#f43f5e
{% elif result.cti.urlhaus.status == 'SUSPICIOUS' %}
#fbbf24
{% elif result.cti.urlhaus.status in ['CLEAN','NOT_LISTED'] %}
#10b981
{% else %}
#94a3b8
{% endif %}
"
>

{{ result.cti.urlhaus.status }}

</span>

<br>

<small style="color:#64748b;">

{{ result.cti.urlhaus.detail }}

</small>

</div>


<!-- ABUSEIPDB -->

<div class="cti-card">

<strong>
AbuseIPDB:
</strong>

<br>

<span
style="
color:
{% if result.cti.abuseipdb.status == 'MALICIOUS' %}
#f43f5e
{% elif result.cti.abuseipdb.status == 'SUSPICIOUS' %}
#fbbf24
{% elif result.cti.abuseipdb.status == 'CLEAN' %}
#10b981
{% else %}
#94a3b8
{% endif %}
"
>

{{ result.cti.abuseipdb.status }}

</span>

<br>

<small style="color:#64748b;">

{{ result.cti.abuseipdb.detail }}

</small>

</div>


<!-- OTX -->

<div class="cti-card">

<strong>
AlienVault OTX:
</strong>

<br>

<span
style="
color:
{% if result.cti.otx.status == 'MALICIOUS' %}
#f43f5e
{% elif result.cti.otx.status == 'SUSPICIOUS' %}
#fbbf24
{% elif result.cti.otx.status == 'NOT_LISTED' %}
#10b981
{% else %}
#94a3b8
{% endif %}
"
>

{{ result.cti.otx.status }}

</span>

<br>

<small style="color:#64748b;">

{{ result.cti.otx.detail }}

</small>

</div>


<!-- PHISHTANK -->

<div class="cti-card">

<strong>
PhishTank:
</strong>

<br>

<span
style="
color:
{% if result.cti.phishtank.status == 'MALICIOUS' %}
#f43f5e
{% elif result.cti.phishtank.status == 'SUSPICIOUS' %}
#fbbf24
{% elif result.cti.phishtank.status == 'NOT_LISTED' %}
#10b981
{% else %}
#94a3b8
{% endif %}
"
>

{{ result.cti.phishtank.status }}

</span>

<br>

<small style="color:#64748b;">

{{ result.cti.phishtank.detail }}

</small>

</div>


<!-- OPENPHISH -->

<div class="cti-card">

<strong>
OpenPhish:
</strong>

<br>

<span
style="
color:
{% if result.cti.openphish.status == 'MALICIOUS' %}
#f43f5e
{% elif result.cti.openphish.status == 'SUSPICIOUS' %}
#fbbf24
{% elif result.cti.openphish.status == 'NOT_LISTED' %}
#10b981
{% else %}
#94a3b8
{% endif %}
"
>

{{ result.cti.openphish.status }}

</span>

<br>

<small style="color:#64748b;">

{{ result.cti.openphish.detail }}

</small>

</div>


</div>


<!-- EVIDENCE -->

{% if result.evidence %}

<div
style="
margin-top:20px;
padding:15px;
background:#0f172a;
border:1px solid #334155;
border-radius:8px;
"
>

<h4
style="
margin-top:0;
color:#38bdf8;
"
>

🔎 Risk Evidence

</h4>

<ul
style="
color:#94a3b8;
font-size:12px;
line-height:1.8;
"
>

{% for item in result.evidence %}

<li>
{{ item }}
</li>

{% endfor %}

</ul>

</div>

{% endif %}


<!-- AI -->

<div class="ai-report">

<h4
style="
margin-top:0;
color:#818cf8;
"
>

🤖 Truvex AI-Assisted Triage Prototype

</h4>

<p>

{{ result.ai_analysis | safe }}

</p>

</div>


</div>

{% endif %}


<!-- FEED -->

<div class="feed-section">

<h4
style="
margin:0 0 15px 0;
color:#38bdf8;
font-size:14px;
text-transform:uppercase;
"
>

📡 Canlı Telemetriya Lenti

</h4>


{% if feed %}

{% for item in feed %}

<div class="feed-item">
    <div class="feed-main">
        <span>🎯 <b style="color:#cbd5e1;">{{ item.target }}</b></span>
        <span>Skor: <b class="score-{{ item.verdict|lower }}">{{ item.score }}/100</b> <small>{{ item.verdict }}</small></span>
    </div>
    <div class="feed-actions">
        <a class="action-btn" href="/incident/{{ item.id }}">Incident</a>
        <a class="action-btn" href="/generate-report/{{ item.id }}">PDF</a>
        <a class="action-btn" href="/export-json/{{ item.id }}">JSON</a>
        <form method="POST" action="/delete-scan/{{ item.id }}" onsubmit="return confirm('Bu scan tarixçədən silinsin?');">
            <button class="delete-btn" type="submit">Delete</button>
        </form>
    </div>
</div>

{% endfor %}


{% else %}

<div
style="
text-align:center;
color:#475569;
padding:15px;
font-size:12px;
"
>

Qeyd yoxdur.

</div>

{% endif %}

</div>


<div class="footer">

Truvex CTI v16.0
&bull;
Multi-Source IOC Analysis Platform

</div>


</div>

</body>

</html>
"""


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    search = request.args.get("search", "").strip()
    verdict = request.args.get("verdict", "ALL").strip().upper()
    scan_type = request.args.get("scan_type", "ALL").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    feed = get_scans_from_db(
        search=search,
        verdict=verdict,
        scan_type=scan_type,
        date_from=date_from,
        date_to=date_to,
        limit=50
    )

    return render_template_string(
        HTML_TEMPLATE,
        result=None,
        feed=feed,
        stats=get_dashboard_stats(),
        filters={
            "search": search,
            "verdict": verdict,
            "scan_type": scan_type,
            "date_from": date_from,
            "date_to": date_to
        }
    )


# ============================================================
# DOMAIN / URL / IP / HASH ANALYSIS
# ============================================================

@app.route(
    "/analyze-domain",
    methods=["POST"]
)
def analyze_domain():

    target = request.form.get(
        "domain",
        ""
    ).strip()

    if not target:

        return "Indicator daxil edilməyib.", 400

    indicator_type = detect_indicator_type(
        target
    )

    # --------------------------------------------------------
    # Parallel CTI
    # --------------------------------------------------------

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=8
    ) as executor:

        f_vt = executor.submit(
            check_virustotal,
            target
        )

        f_urlhaus = executor.submit(
            check_urlhaus,
            target
        )

        f_abuse = executor.submit(
            check_abuseipdb,
            target
        )

        f_otx = executor.submit(
            check_alienvault_otx,
            target
        )

        f_phish = executor.submit(
            check_phishtank,
            target
        )

        f_openphish = executor.submit(
            check_openphish,
            target
        )

        f_whois = executor.submit(
            check_domain_whois,
            target
        )

        f_ssl = executor.submit(
            check_ssl_certificate,
            target
        )

        vt_res = f_vt.result()

        urlhaus_res = f_urlhaus.result()

        abuse_res = f_abuse.result()

        otx_res = f_otx.result()

        phish_res = f_phish.result()

        openphish_res = f_openphish.result()

        has_whois, age_days, whois_msg = (
            f_whois.result()
        )

        has_ssl, ssl_msg = f_ssl.result()


    # --------------------------------------------------------
    # Geo
    # --------------------------------------------------------

    if indicator_type in (
        "hash_md5",
        "hash_sha1",
        "hash_sha256"
    ):

        ip = "N/A"
        country = "N/A"
        flag = "🔢"
        resolved_domain = "N/A"

    else:

        ip, country, flag, resolved_domain = (
            get_ip_geolocation(target)
        )


    # --------------------------------------------------------
    # CTI Dictionary
    # --------------------------------------------------------

    cti_dict = {

        "vt": vt_res,

        "urlhaus": urlhaus_res,

        "abuseipdb": abuse_res,

        "otx": otx_res,

        "phishtank": phish_res,

        "openphish": openphish_res

    }


    # --------------------------------------------------------
    # TTI
    # --------------------------------------------------------

    score, verdict, evidence = calculate_tti(
        cti_dict
    )


    # --------------------------------------------------------
    # Available engines
    # --------------------------------------------------------

    engine_results = list(
        cti_dict.values()
    )

    available_results = [
        r
        for r in engine_results
        if r.get("available") is True
    ]

    malicious_votes = sum(
        1
        for r in available_results
        if r.get("malicious") is True
    )


    # --------------------------------------------------------
    # Incident
    # --------------------------------------------------------

    incident_id = (
        f"INC-{random.randint(10000, 99999)}"
        if score >= 50
        else None
    )


    # --------------------------------------------------------
    # Tags
    # --------------------------------------------------------

    tags = []


    if indicator_type == "url":
        tags.append("URL-Analysis")

    elif indicator_type == "domain":
        tags.append("Domain-Analysis")

    elif indicator_type == "ip":
        tags.append("IP-Analysis")

    elif indicator_type.startswith("hash"):
        tags.append("Hash-Analysis")


    if score >= 75:

        tags.append("High-Risk")

    elif score >= 50:

        tags.append("Suspicious")

    elif score > 0:

        tags.append("Limited-Evidence")

    else:

        tags.append("No-Threat-Evidence")


    if malicious_votes > 0:

        tags.append(
            f"CTI-{malicious_votes}-Sources"
        )


    # --------------------------------------------------------
    # MITRE
    # --------------------------------------------------------

    mitre_info = map_to_mitre(
        target,
        "file"
        if indicator_type.startswith("hash")
        else indicator_type,
        score,
        cti_dict
    )


    if mitre_info:

        tags.append(
            mitre_info["id"]
        )


    # --------------------------------------------------------
    # AI TRIAGE
    # --------------------------------------------------------

    available_count = len(
        available_results
    )

    ai_text = f"""
    Hədəf <b>{target}</b> üçün
    <b>{indicator_type}</b> tipli IOC analizi aparıldı.
    """

    ai_text += f"""
    <br><br>
    Mövcud CTI mühərrikləri:
    <b>{available_count}</b>/6.
    """

    ai_text += f"""
    <br>
    Malicious nəticə verən mənbələr:
    <b>{malicious_votes}</b>.
    """

    ai_text += f"""
    <br>
    Yekun Truvex Threat Index:
    <b>{score}/100 ({verdict})</b>.
    """

    if evidence:

        ai_text += (
            "<br><br><b>Risk evidence:</b><br>"
            + "<br>".join(
                f"• {x}"
                for x in evidence
            )
        )

    else:

        ai_text += (
            "<br><br>"
            "Mövcud mənbələrdə əhəmiyyətli "
            "malicious evidence aşkar edilmədi."
        )


    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    result = {

        "target": target,

        "indicator_type": indicator_type,

        "score": score,

        "verdict": verdict,

        "decay": calculate_decay(
            score
        ),

        "ip": ip,

        "resolved_domain": resolved_domain,

        "geo_country": country,

        "geo_flag": flag,

        "incident_id": incident_id,

        "tags": tags,

        "mitre": mitre_info,

        "whois_info": whois_msg,

        "ssl_info": ssl_msg,

        "cti": cti_dict,

        "evidence": evidence,

        "ai_analysis": ai_text

    }


    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    scan_id = save_scan_to_db(
        target,
        "pure-cti",
        score,
        incident_id,
        tags,
        report_data=result
    )
    result["scan_id"] = scan_id
    update_report_json(scan_id, result)

    feed = get_scans_from_db(limit=50)

    return render_template_string(
        HTML_TEMPLATE,
        result=result,
        feed=feed,
        stats=get_dashboard_stats(),
        filters={"search":"", "verdict":"ALL", "scan_type":"ALL", "date_from":"", "date_to":""}
    )


# ============================================================
# FILE ANALYSIS
# ============================================================

@app.route(
    "/analyze-file",
    methods=["POST"]
)
def analyze_file():

    if "file" not in request.files:

        return "Fayl yoxdur.", 400


    file = request.files["file"]

    filename = file.filename or "unknown_file"

    file_bytes = file.read()


    if not file_bytes:

        return "Fayl boşdur.", 400


    # --------------------------------------------------------
    # Hashes
    # --------------------------------------------------------

    md5 = hashlib.md5(
        file_bytes
    ).hexdigest()

    sha1 = hashlib.sha1(
        file_bytes
    ).hexdigest()

    sha256 = hashlib.sha256(
        file_bytes
    ).hexdigest()


    # --------------------------------------------------------
    # VirusTotal SHA256
    # --------------------------------------------------------

    vt_res = check_virustotal(
        sha256
    )


    # --------------------------------------------------------
    # TTI
    # --------------------------------------------------------

    file_cti_dict = {

        "vt": vt_res,

        "urlhaus": {
            "available": False,
            "status": "SKIPPED",
            "malicious": False,
            "detail": "Fayl üçün tətbiq edilmir."
        },

        "abuseipdb": {
            "available": False,
            "status": "SKIPPED",
            "malicious": False,
            "detail": "Fayl üçün tətbiq edilmir."
        },

        "otx": {
            "available": False,
            "status": "SKIPPED",
            "malicious": False,
            "detail": "Fayl üçün tətbiq edilmir."
        },

        "phishtank": {
            "available": False,
            "status": "SKIPPED",
            "malicious": False,
            "detail": "Fayl üçün tətbiq edilmir."
        },

        "openphish": {
            "available": False,
            "status": "SKIPPED",
            "malicious": False,
            "detail": "Fayl üçün tətbiq edilmir."
        }

    }


    score, verdict, evidence = (
        calculate_tti(
            file_cti_dict
        )
    )


    incident_id = (
        f"INC-{random.randint(10000, 99999)}"
        if score >= 50
        else None
    )


    tags = [
        "File-Analysis"
    ]


    if score >= 75:

        tags.append(
            "High-Risk-Malware"
        )

    elif score >= 50:

        tags.append(
            "Suspicious-File"
        )

    elif score > 0:

        tags.append(
            "Limited-Evidence"
        )

    else:

        tags.append(
            "No-Threat-Evidence"
        )


    # --------------------------------------------------------
    # MITRE
    # --------------------------------------------------------

    mitre_info = None

    if score >= 50:

        mitre_info = MITRE_ATTACK_MAPPING[
            "user_execution"
        ]

        tags.append(
            mitre_info["id"]
        )


    # --------------------------------------------------------
    # AI
    # --------------------------------------------------------

    ai_text = f"""
    Fayl <b>{filename}</b> üçün statik hash analizi aparıldı.
    """

    ai_text += f"""
    <br><br>
    MD5:
    <code>{md5}</code>
    """

    ai_text += f"""
    <br>
    SHA1:
    <code>{sha1}</code>
    """

    ai_text += f"""
    <br>
    SHA256:
    <code>{sha256}</code>
    """

    ai_text += f"""
    <br><br>
    VirusTotal nəticəsi:
    <b>{vt_res.get("status")}</b>.
    """

    ai_text += f"""
    <br>
    TTI:
    <b>{score}/100 ({verdict})</b>.
    """


    result = {

        "target": (
            f"{filename}"
            f" (SHA256: {sha256[:16]}...)"
        ),

        "indicator_type": "file",

        "score": score,

        "verdict": verdict,

        "decay": calculate_decay(
            score
        ),

        "ip": "N/A",

        "resolved_domain": "N/A",

        "geo_country": "Local File Analysis",

        "geo_flag": "📁",

        "incident_id": incident_id,

        "tags": tags,

        "mitre": mitre_info,

        "whois_info": "N/A",

        "ssl_info": "N/A",

        "cti": file_cti_dict,

        "evidence": evidence,

        "ai_analysis": ai_text

    }


    scan_id = save_scan_to_db(
        filename,
        "fayl",
        score,
        incident_id,
        tags,
        report_data=result
    )
    result["scan_id"] = scan_id
    update_report_json(scan_id, result)

    feed = get_scans_from_db(limit=50)

    return render_template_string(
        HTML_TEMPLATE,
        result=result,
        feed=feed,
        stats=get_dashboard_stats(),
        filters={"search":"", "verdict":"ALL", "scan_type":"ALL", "date_from":"", "date_to":""}
    )



# ============================================================
# TELEMETRY / INCIDENT MANAGEMENT
# ============================================================

@app.route("/delete-scan/<int:scan_id>", methods=["POST"])
def delete_scan(scan_id):
    delete_scan_from_db(scan_id)
    return redirect(url_for("home"))


@app.route("/incident/<int:scan_id>", methods=["GET", "POST"])
def incident_detail(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return "Scan tapılmadı.", 404

    if request.method == "POST":
        notes = request.form.get("analyst_notes", "")
        update_analyst_notes(scan_id, notes)
        return redirect(url_for("incident_detail", scan_id=scan_id))

    report = scan.get("report") or {}
    if not report:
        report = {
            "target": scan["target"],
            "indicator_type": scan["type"],
            "score": scan["score"],
            "verdict": "CRITICAL" if scan["score"] >= 75 else "HIGH" if scan["score"] >= 50 else "MEDIUM" if scan["score"] >= 25 else "LOW" if scan["score"] > 0 else "CLEAN",
            "incident_id": scan["incident_id"],
            "tags": scan["tags"],
            "evidence": [],
            "cti": {},
            "mitre": None,
            "ai_analysis": "Tarixi scan üçün saxlanılmış geniş report məlumatı yoxdur."
        }

    cti_rows = []
    for name, data in (report.get("cti") or {}).items():
        if not isinstance(data, dict):
            continue
        cti_rows.append((name.upper(), data.get("status", "N/A"), data.get("detail", "")))

    html = """
    <!DOCTYPE html><html lang="az"><head><meta charset="UTF-8"><title>TRUVEX Incident</title>
    <style>body{font-family:Segoe UI,Tahoma,sans-serif;background:#07090e;color:#f8fafc;margin:0;padding:30px}.wrap{max-width:1100px;margin:auto}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:15px}.back{color:#38bdf8;text-decoration:none}.box{background:#0b1220;border:1px solid #1e293b;border-radius:10px;padding:18px;margin-bottom:15px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.card{background:#07090e;border:1px solid #1e293b;border-radius:8px;padding:12px}.label{color:#64748b;font-size:10px;text-transform:uppercase}.value{color:#e2e8f0;margin-top:5px;word-break:break-word}.critical{color:#f43f5e}.high{color:#fb7185}.medium{color:#fbbf24}.low{color:#f59e0b}.clean{color:#10b981}.tag{display:inline-block;border:1px solid #334155;padding:4px 7px;border-radius:5px;color:#94a3b8;font-size:10px;margin:3px}.cti{width:100%;border-collapse:collapse}.cti th,.cti td{border-bottom:1px solid #1e293b;padding:8px;text-align:left;font-size:11px}.cti th{color:#38bdf8}.notes{width:100%;box-sizing:border-box;min-height:140px;background:#07090e;border:1px solid #334155;border-radius:8px;color:#cbd5e1;padding:10px}.btn{background:#111827;color:#cbd5e1;border:1px solid #334155;border-radius:6px;padding:8px 12px;cursor:pointer}.btn.blue{border-color:#38bdf8;color:#38bdf8}@media(max-width:800px){.grid{grid-template-columns:1fr}}</style></head><body><div class="wrap">
    <div class="top"><h2>🛡️ TRUVEX Incident Details</h2><a class="back" href="/">← Dashboard</a></div>
    <div class="box"><div class="grid">
    <div class="card"><div class="label">Indicator</div><div class="value">{{ report.get('target','N/A') }}</div></div>
    <div class="card"><div class="label">Type</div><div class="value">{{ report.get('indicator_type', scan.type) }}</div></div>
    <div class="card"><div class="label">TTI</div><div class="value {{ report.get('verdict','CLEAN')|lower }}">{{ report.get('score',scan.score) }}/100 — {{ report.get('verdict','CLEAN') }}</div></div>
    <div class="card"><div class="label">Incident ID</div><div class="value">{{ report.get('incident_id') or 'No incident' }}</div></div>
    <div class="card"><div class="label">Created</div><div class="value">{{ scan.timestamp }}</div></div>
    <div class="card"><div class="label">MITRE ATT&CK</div><div class="value">{% if report.get('mitre') %}{{ report.mitre.id }} — {{ report.mitre.name }}{% else %}N/A{% endif %}</div></div>
    </div></div>
    <div class="box"><h3>CTI Evidence</h3><table class="cti"><tr><th>Engine</th><th>Status</th><th>Detail</th></tr>{% for name,status,detail in cti_rows %}<tr><td>{{ name }}</td><td>{{ status }}</td><td>{{ detail }}</td></tr>{% else %}<tr><td colspan="3">CTI report data yoxdur.</td></tr>{% endfor %}</table></div>
    <div class="box"><h3>Risk Evidence</h3>{% for e in report.get('evidence',[]) %}<div class="tag">{{ e }}</div>{% else %}<div class="value">No evidence recorded.</div>{% endfor %}</div>
    <div class="box"><h3>AI-Assisted Triage</h3><div class="value">{{ report.get('ai_analysis','N/A')|safe }}</div></div>
    <div class="box"><h3>Analyst Notes</h3><form method="POST"><textarea class="notes" name="analyst_notes" placeholder="Analyst note...">{{ scan.analyst_notes }}</textarea><br><br><button class="btn blue" type="submit">Save Notes</button></form></div>
    <div><a class="btn" href="/generate-report/{{ scan.id }}">PDF Report</a> <a class="btn" href="/export-json/{{ scan.id }}">Export JSON</a></div>
    </div></body></html>
    """

    return render_template_string(html, scan=scan, report=report, cti_rows=cti_rows)


# ============================================================
# REPORTING / EXPORT
# ============================================================

def build_pdf_report(scan):
    report = scan.get("report") or {}
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("TruvexTitle", parent=styles["Title"], alignment=TA_CENTER, fontSize=18, spaceAfter=16)
    h = ParagraphStyle("TruvexH", parent=styles["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=7)
    body = ParagraphStyle("TruvexBody", parent=styles["BodyText"], fontSize=9, leading=13)

    story = [Paragraph("TRUVEX CTI INCIDENT REPORT", title)]
    story.append(Paragraph(f"Generated: {escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}", body))
    story.append(Spacer(1, 10))

    summary = [
        ["Indicator", str(report.get("target", scan["target"]))],
        ["Indicator Type", str(report.get("indicator_type", scan["type"]))],
        ["TTI", f"{report.get('score', scan['score'])}/100"],
        ["Verdict", str(report.get("verdict", "N/A"))],
        ["Incident ID", str(report.get("incident_id") or "N/A")],
        ["Timestamp", str(scan.get("timestamp", "N/A"))],
    ]
    t = Table(summary, colWidths=[110, 395])
    t.setStyle(TableStyle([("BACKGROUND", (0,0),(0,-1), colors.HexColor("#e2e8f0")), ("GRID",(0,0),(-1,-1),0.5,colors.grey), ("VALIGN",(0,0),(-1,-1),"TOP"), ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),8)]))
    story += [t, Spacer(1, 12)]

    story.append(Paragraph("Risk Evidence", h))
    evidence = report.get("evidence") or []
    if evidence:
        for item in evidence:
            story.append(Paragraph("• " + escape(str(item)), body))
    else:
        story.append(Paragraph("No recorded malicious evidence.", body))

    story.append(Paragraph("CTI Sources", h))
    cti_rows = [["Engine", "Status", "Detail"]]
    for name, data in (report.get("cti") or {}).items():
        if isinstance(data, dict):
            cti_rows.append([str(name), str(data.get("status", "N/A")), str(data.get("detail", ""))])
    ct = Table(cti_rows, colWidths=[100, 85, 320], repeatRows=1)
    ct.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1e293b")), ("TEXTCOLOR",(0,0),(-1,0),colors.white), ("GRID",(0,0),(-1,-1),0.35,colors.grey), ("VALIGN",(0,0),(-1,-1),"TOP"), ("FONTSIZE",(0,0),(-1,-1),7)]))
    story += [ct, Spacer(1, 12)]

    story.append(Paragraph("MITRE ATT&CK", h))
    mitre = report.get("mitre")
    if mitre:
        story.append(Paragraph(escape(f"{mitre.get('id','N/A')} — {mitre.get('name','N/A')} | {mitre.get('tactic','N/A')}"), body))
        story.append(Paragraph(escape(str(mitre.get("description", ""))), body))
    else:
        story.append(Paragraph("No MITRE mapping recorded.", body))

    story.append(Paragraph("Network / Context", h))
    context = [
        ["IP", str(report.get("ip", "N/A"))],
        ["Country", str(report.get("geo_country", "N/A"))],
        ["Resolved Domain", str(report.get("resolved_domain", "N/A"))],
        ["WHOIS", str(report.get("whois_info", "N/A"))],
        ["SSL", str(report.get("ssl_info", "N/A"))],
    ]
    nt = Table(context, colWidths=[110,395])
    nt.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.35,colors.grey), ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),8), ("VALIGN",(0,0),(-1,-1),"TOP")]))
    story += [nt, Spacer(1, 12)]

    story.append(Paragraph("Analyst Notes", h))
    story.append(Paragraph(escape(scan.get("analyst_notes") or "No analyst notes."), body))

    doc.build(story)
    buffer.seek(0)
    return buffer


@app.route("/generate-report/<int:scan_id>")
def generate_report(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan or not scan.get("report"):
        return "Bu scan üçün report məlumatı mövcud deyil.", 404
    pdf = build_pdf_report(scan)
    filename = f"truvex_report_{scan_id}.pdf"
    return send_file(pdf, mimetype="application/pdf", as_attachment=True, download_name=filename)


@app.route("/export-json/<int:scan_id>")
def export_json(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return "Scan tapılmadı.", 404
    payload = {
        "scan_id": scan["id"],
        "target": scan["target"],
        "type": scan["type"],
        "score": scan["score"],
        "incident_id": scan["incident_id"],
        "timestamp": scan["timestamp"],
        "tags": scan["tags"],
        "analyst_notes": scan["analyst_notes"],
        "report": scan["report"]
    }
    data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    return send_file(BytesIO(data), mimetype="application/json", as_attachment=True, download_name=f"truvex_scan_{scan_id}.json")


@app.route("/export-csv")
def export_csv():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id,target,type,score,incident_id,tags,timestamp,analyst_notes FROM scans ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()

    out = StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "target", "type", "score", "verdict", "incident_id", "tags", "timestamp", "analyst_notes"])
    for row in rows:
        score = row[3]
        verdict = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW" if score > 0 else "CLEAN"
        writer.writerow([row[0],row[1],row[2],score,verdict,row[4],row[5],row[6],row[7] or ""])

    data = out.getvalue().encode("utf-8-sig")
    return send_file(BytesIO(data), mimetype="text/csv", as_attachment=True, download_name="truvex_telemetry.csv")


# ============================================================
# API / ENGINE HEALTH
# ============================================================

def get_engine_status():
    configured = {
        "VirusTotal": bool(VT_API_KEY),
        "URLhaus": bool(URLHAUS_AUTH_KEY),
        "AbuseIPDB": bool(ABUSEIPDB_API_KEY),
        "PhishTank": True,
        "OpenPhish": True,
        "AlienVault OTX": True,
    }
    return configured


@app.route("/api/health")
def api_health():
    status = get_engine_status()
    return jsonify({
        "truvex": "online",
        "database": os.path.exists(DB_NAME),
        "reporting": True,
        "engines": {
            name: "configured" if ok else "not_configured"
            for name, ok in status.items()
        },
        "timestamp": datetime.now().isoformat(timespec="seconds")
    })


@app.route("/engine-status")
def engine_status():
    status = get_engine_status()
    html = """<!DOCTYPE html><html lang="az"><head><meta charset="UTF-8"><title>TRUVEX Engine Health</title><style>body{font-family:Segoe UI;background:#07090e;color:#f8fafc;padding:30px}.wrap{max-width:850px;margin:auto}.box{background:#0b1220;border:1px solid #1e293b;border-radius:10px;padding:16px;margin:8px 0;display:flex;justify-content:space-between}.ok{color:#10b981}.off{color:#fbbf24}.back{color:#38bdf8}</style></head><body><div class="wrap"><a class="back" href="/">← Dashboard</a><h2>⚙️ CTI Engine Health</h2>{% for name,ok in status.items() %}<div class="box"><span>{{ name }}</span><b class="{{ 'ok' if ok else 'off' }}">{{ 'CONFIGURED / READY' if ok else 'NOT CONFIGURED' }}</b></div>{% endfor %}</div></body></html>"""
    return render_template_string(html, status=status)


# ============================================================
# DEMO / PRESENTATION MODE
# ============================================================

@app.route("/demo")
def demo_mode():
    target = "login-security-demo.example"
    cti = {
        "vt": {"engine":"VirusTotal","available":True,"malicious":True,"status":"MALICIOUS","positives":8,"suspicious":1,"total":70,"detail":"Demo detection: 8/70"},
        "urlhaus": {"engine":"URLhaus","available":True,"malicious":True,"status":"MALICIOUS","detail":"Demo malicious URL"},
        "abuseipdb": {"engine":"AbuseIPDB","available":True,"malicious":False,"status":"CLEAN","confidence":0,"detail":"Demo"},
        "otx": {"engine":"AlienVault OTX","available":True,"malicious":True,"status":"MALICIOUS","pulses":4,"detail":"Demo threat pulses: 4"},
        "phishtank": {"engine":"PhishTank","available":True,"malicious":True,"status":"MALICIOUS","detail":"Demo verified phishing"},
        "openphish": {"engine":"OpenPhish","available":True,"malicious":True,"status":"MALICIOUS","detail":"Demo malicious URL"}
    }
    score, verdict, evidence = calculate_tti(cti)
    incident_id = f"INC-DEMO-{random.randint(100,999)}"
    tags = ["URL-Analysis", "High-Risk", "CTI-4-Sources", "T1566"]
    result = {
        "target": target,
        "indicator_type": "domain",
        "score": score,
        "verdict": verdict,
        "decay": calculate_decay(score),
        "ip": "203.0.113.50",
        "resolved_domain": target,
        "geo_country": "Demo / TEST-NET",
        "geo_flag": "🧪",
        "incident_id": incident_id,
        "tags": tags,
        "mitre": MITRE_ATTACK_MAPPING["phishing"],
        "whois_info": "Demo data — not a real WHOIS lookup",
        "ssl_info": "Demo SSL context",
        "cti": cti,
        "evidence": evidence,
        "ai_analysis": "<b>Demo mode:</b> This report is synthetic and is intended only for presentation/testing."
    }
    scan_id = save_scan_to_db(target, "demo", score, incident_id, tags, report_data=result)
    result["scan_id"] = scan_id
    update_report_json(scan_id, result)
    return render_template_string(HTML_TEMPLATE, result=result, feed=get_scans_from_db(limit=50), stats=get_dashboard_stats(), filters={"search":"", "verdict":"ALL", "scan_type":"ALL", "date_from":"", "date_to":""})


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    print(
        "[*] Truvex v16.0 "
        "(Multi-Source CTI + IOC Analysis) "
        "işə düşdü:"
    )

    print(
        "[*] http://127.0.0.1:5000"
    )

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )