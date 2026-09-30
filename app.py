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
from markupsafe import Markup, escape as h_escape
from dotenv import load_dotenv
from io import BytesIO, StringIO
import csv
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


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
# VIVID THEME (shared CSS)
# ============================================================
APP_CSS = """
:root{
  --bg:#0f1115; --panel:#181b21; --panel2:#20242b; --panel3:#13161b;
  --border:#303640; --text:#e8ebef; --muted:#9ba4af; --dim:#69727d;
  --cyan:#4f9bb8; --blue:#3f78a0; --violet:#687585; --pink:#8a6678;
  --crit:#d45d69; --high:#d48a45; --med:#c7ae4d; --low:#5598b8; --ok:#55a477;
}
*{box-sizing:border-box}
body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;color:var(--text);margin:0;padding:30px;background:var(--bg);background-attachment:fixed;min-height:100vh}
.container{max-width:1040px;width:100%;margin:0 auto;background:var(--panel);padding:40px;border-radius:18px;box-shadow:0 10px 30px rgba(0,0,0,.28),0 0 0 1px var(--border)}
.top-bar{display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:10px}
.logo-area{display:flex;align-items:center;gap:12px}.logo-area>span{font-size:30px}
h2{margin:0;font-size:26px;letter-spacing:1.5px;font-weight:800;color:#8fb4cc}.subtitle{color:var(--muted);font-size:12px;margin-bottom:25px;text-transform:uppercase;letter-spacing:2px;font-weight:600}
.tabs{display:flex;justify-content:center;gap:12px;margin-bottom:25px;flex-wrap:wrap}.tab-btn{background:var(--panel2);color:var(--muted);border:1px solid var(--border);padding:10px 22px;border-radius:10px;cursor:pointer;font-weight:700;transition:all .15s}.tab-btn:hover{color:#fff;border-color:var(--blue);background:#29343e}.tab-btn.active{background:var(--blue);color:#fff;border-color:var(--blue)}
.section-box{display:none;border:1px solid var(--border);padding:30px;text-align:center;border-radius:14px;background:var(--panel3)}.section-box.active{display:block}
input[type="text"]{color:var(--text);margin-bottom:15px;padding:12px;width:75%;max-width:100%;background:var(--panel3);border:1px solid var(--border);border-radius:8px}input:focus,select:focus,textarea:focus{outline:none;border-color:var(--cyan);box-shadow:0 0 0 3px rgba(79,155,184,.12)}
button[type="submit"]{padding:12px 26px;background:var(--blue);color:#fff;border:none;border-radius:8px;cursor:pointer;font-weight:800;font-size:14px;transition:transform .12s}button[type="submit"]:hover{transform:translateY(-2px)}
.results{margin-top:30px;background:var(--panel3);padding:30px;border-radius:14px;border:1px solid var(--border);text-align:left}.results h3{margin-top:0}.accent{color:var(--cyan)}.violet{color:#8b9baa;font-weight:700}
.risk{font-weight:850;padding:4px 12px;border-radius:6px;border:1px solid}.risk-critical{color:var(--crit);background:#2c1d21;border-color:#66333a}.risk-high{color:var(--high);background:#2d241b;border-color:#68482d}.risk-medium{color:var(--med);background:#2c291b;border-color:#655a2b}.risk-low{color:var(--low);background:#1c2a31;border-color:#385b6c}.risk-clean{color:var(--ok);background:#1b2a22;border-color:#39684e}
.incident-badge{background:var(--panel2);border:1px solid var(--border);padding:14px 18px;border-radius:10px;margin-bottom:20px;display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}.incident-badge .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:800;letter-spacing:1px}.incident-badge .id{font-size:16px;color:var(--text);font-weight:800;margin-top:3px}.sev-pill{font-size:11px;margin-left:8px;padding:3px 8px;border-radius:5px;background:#2c1d21;color:var(--crit);border:1px solid #66333a}
.mitre-box{background:var(--panel2);border:1px solid var(--border);padding:16px;border-radius:10px;margin-top:20px}.mitre-box h4{margin:0 0 8px;color:#8b9baa}.mitre-id{background:var(--blue);color:#fff;padding:3px 9px;border-radius:5px;font-weight:800;font-size:12px}.decay-box{background:var(--panel2);border:1px solid var(--border);padding:16px;border-radius:10px;margin-top:20px}.decay-box h4{margin:0 0 8px;color:var(--cyan)}.info-box{margin-top:20px;padding:14px;background:var(--panel2);border:1px solid var(--border);border-radius:10px;color:var(--muted);font-size:12px}
.evidence-box{margin-top:20px;padding:16px;background:#2c291b;border:1px solid #655a2b;border-radius:10px}.evidence-box h4{margin:0;color:var(--med)}.evidence-box ul{color:var(--text);font-size:12px;line-height:1.8}.tag{display:inline-block;background:#334d5e;color:#e7edf2;padding:3px 10px;border-radius:999px;font-size:11px;font-weight:700;margin:2px 4px 2px 0}.cti-title{color:#8b9baa;margin:25px 0 10px}.cti-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-top:10px}.cti-card{background:var(--panel2);border:1px solid var(--border);border-top:3px solid var(--blue);padding:14px;border-radius:10px;font-size:13px}.cti-card small{color:var(--muted)}
.st-bad{color:var(--crit);font-weight:800}.st-warn{color:var(--med);font-weight:800}.st-ok{color:var(--ok);font-weight:800}.st-na{color:var(--muted);font-weight:700}.ai-report{background:var(--panel2);border:1px solid var(--border);padding:22px;border-radius:12px;margin-top:25px;color:#cbd2d9;line-height:1.7}.ai-report h4{margin-top:0;color:#8b9baa}.ai-report code{background:#2b3139;color:#8fc3d8;padding:1px 5px;border-radius:4px;word-break:break-all}
.feed-section{margin-top:35px;background:var(--panel3);border:1px solid var(--border);padding:20px;border-radius:14px}.feed-section h4{margin:0 0 15px;color:var(--cyan);font-size:14px;text-transform:uppercase}.feed-item{display:flex;justify-content:space-between;gap:10px;align-items:center;padding:9px 12px;border-bottom:1px solid var(--border);font-size:12px;color:var(--muted)}.feed-item:hover{background:var(--panel2)}.feed-main{display:flex;justify-content:space-between;gap:12px;align-items:center;flex:1}.feed-main b.t{color:var(--text);word-break:break-all}.feed-actions{display:flex;gap:6px;align-items:center}.feed-actions form{margin:0}.score-critical{color:var(--crit)}.score-high{color:var(--high)}.score-medium{color:var(--med)}.score-low{color:var(--low)}.score-clean{color:var(--ok)}.footer{text-align:center;margin-top:40px;color:var(--dim);font-size:12px}.muted{color:var(--dim);font-size:11px}
.dashboard-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:18px 0}.stat-card{background:var(--panel2);border:1px solid var(--border);border-radius:12px;padding:14px;position:relative;overflow:hidden}.stat-card:before{content:"";position:absolute;left:0;top:0;right:0;height:3px;background:var(--blue)}.stat-card:nth-child(2):before{background:var(--crit)}.stat-card:nth-child(3):before{background:var(--high)}.stat-card:nth-child(4):before{background:var(--med)}.stat-card:nth-child(5):before{background:var(--ok)}.stat-card:nth-child(6):before{background:var(--cyan)}.stat-card span{display:block;color:var(--muted);font-size:10px;text-transform:uppercase;font-weight:700}.stat-card strong{display:block;color:var(--text);font-size:26px;margin:6px 0}.stat-card small{color:var(--dim);font-size:10px}
.analytics-box{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:15px}.analytics-col,.filter-box{background:var(--panel2);border:1px solid var(--border);border-radius:12px;padding:14px}.analytics-col h4{margin:0 0 10px;color:#9b7b8c;font-size:11px;text-transform:uppercase;letter-spacing:1px}.mini-bars div,.type-line{display:flex;justify-content:space-between;gap:8px;padding:5px 0;color:var(--muted);font-size:11px;border-bottom:1px solid var(--border)}.mini-bars b,.type-line b{color:var(--text)}.mini-bars .c-critical b{color:var(--crit)}.mini-bars .c-high b{color:var(--high)}.mini-bars .c-medium b{color:var(--med)}.mini-bars .c-low b{color:var(--low)}.mini-bars .c-clean b{color:var(--ok)}
.filter-box{margin-bottom:15px}.filter-form{display:flex;gap:8px;flex-wrap:wrap}.filter-form input,.filter-form select{background:var(--panel3);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:8px;font-size:11px;margin:0}.filter-form input[type="text"]{width:auto;flex:1;min-width:180px}.filter-form button{padding:8px 14px!important;font-size:11px!important}.clear-btn,.action-btn,.delete-btn{border:1px solid var(--border);background:var(--panel2);color:var(--text);border-radius:8px;padding:7px 11px;text-decoration:none;font-size:10px;font-weight:700;cursor:pointer;display:inline-flex;align-items:center}.clear-btn:hover,.action-btn:hover{border-color:var(--cyan);color:var(--cyan)}.delete-btn{border-color:#66333a;color:var(--crit)}.delete-btn:hover{background:var(--crit);color:#fff}
.page{max-width:1100px;margin:0 auto}.ibox{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:18px;margin-bottom:15px}.ibox h3{margin-top:0;color:var(--cyan)}.igrid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.icard{background:var(--panel3);border:1px solid var(--border);border-radius:10px;padding:12px}.ilabel{color:var(--muted);font-size:10px;text-transform:uppercase;font-weight:700}.ivalue{color:var(--text);margin-top:5px;word-break:break-word}.ivalue.critical{color:var(--crit)}.ivalue.high{color:var(--high)}.ivalue.medium{color:var(--med)}.ivalue.low{color:var(--low)}.ivalue.clean{color:var(--ok)}.back{color:var(--cyan);text-decoration:none;font-weight:700}.ctitable{width:100%;border-collapse:collapse}.ctitable th,.ctitable td{border-bottom:1px solid var(--border);padding:9px;text-align:left;font-size:12px}.ctitable th{color:#9b7b8c}.notes{width:100%;min-height:140px;background:var(--panel3);border:1px solid var(--border);border-radius:10px;color:var(--text);padding:10px}.btn{display:inline-block;background:var(--panel2);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:9px 14px;cursor:pointer;text-decoration:none;font-weight:700;font-size:12px}.btn:hover{border-color:var(--cyan)}.btn.blue{background:var(--blue);border-color:var(--blue);color:#fff}.engine-row{display:flex;justify-content:space-between;background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px;margin:8px 0}.engine-row .ok{color:var(--ok);font-weight:800}.engine-row .off{color:var(--med);font-weight:800}
@media(max-width:900px){body{padding:12px}.container{padding:20px}.dashboard-grid{grid-template-columns:repeat(3,1fr)}.analytics-box,.cti-grid,.igrid{grid-template-columns:1fr}.feed-item{flex-direction:column;align-items:stretch}.feed-main{flex-direction:column;align-items:flex-start}}
@media(prefers-color-scheme:light){:root{--bg:#111318;--panel:#181b21;--panel2:#20242b;--panel3:#13161b;--border:#303640;--text:#e8ebef;--muted:#9ba4af;--dim:#69727d}}
"""





# ============================================================
# I18N  (English / Azərbaycan dili)
# ============================================================
# Dinamik mətnlər (engine detalları, sübutlar, AI hesabatı və s.) DB-də
# dil-neytral açar kimi (M(...)) saxlanılır və göstərilən zaman seçilmiş
# dildə render olunur. Buna görə dili dəyişəndə KEÇMİŞ skanlar da
# yeni dildə görünür.

LANGS = ("en", "az")
DEFAULT_LANG = "az"
LANG_COOKIE = "truvex_lang"

S = {
    # ---------- Main UI ----------
    "page_title": ("Truvex v16.0 | CTI Platform", "Truvex v16.0 | CTI Platforması"),
    "app_title": ("TRUVEX CORE - CTI PLATFORM", "TRUVEX CORE - CTI PLATFORMASI"),
    "subtitle": ("Multi-Source Threat Intelligence & IOC Analysis", "Çoxmənbəli Təhdid Kəşfiyyatı və IOC Analizi"),
    "tab_file": ("📁 File Analysis", "📁 Fayl Analizi"),
    "tab_domain": ("🌐 URL / Domain / IP / Hash", "🌐 URL / Domen / IP / Hash"),
    "st_total": ("Total Scans", "Ümumi Skanlar"),
    "st_total_sub": ("All telemetry records", "Bütün telemetriya qeydləri"),
    "st_critical": ("Critical", "Kritik"),
    "st_critical_sub": ("TTI ≥ 75", "TTI ≥ 75"),
    "st_high": ("High", "Yüksək"),
    "st_high_sub": ("TTI 50–74", "TTI 50–74"),
    "st_avg": ("Average TTI", "Orta TTI"),
    "st_avg_sub": ("Across all scans", "Bütün skanlar üzrə"),
    "st_24h": ("Last 24h", "Son 24 saat"),
    "st_7d": ("Last 7d", "Son 7 gün"),
    "st_new": ("New telemetry", "Yeni telemetriya"),
    "sev_dist": ("Severity Distribution", "Ciddilik Bölgüsü"),
    "ind_types": ("Indicator Types", "İndikator Tipləri"),
    "top_tags": ("Top Tags", "Ən Çox Teqlər"),
    "no_data": ("No data", "Məlumat yoxdur"),
    "search_ph": ("Search IOC, incident ID or tag", "IOC, insident ID və ya teq axtarın"),
    "all": ("ALL", "HAMISI"),
    "filter_btn": ("🔎 Filter", "🔎 Filtrlə"),
    "clear_btn": ("Clear", "Təmizlə"),
    "file_btn": ("Analyze File by Hash", "Faylı Hash ilə Analiz Et"),
    "domain_ph": ("Enter a URL, domain, IP or MD5/SHA1/SHA256 hash", "URL, domen, IP və ya MD5/SHA1/SHA256 hash daxil edin"),
    "domain_btn": ("Start CTI Analysis", "CTI Analizini Başlat"),
    "incident_gen": ("Automatic Incident Ticket Generator", "Avtomatik İnsident Bilet Generatoru"),
    "severity": ("SEVERITY:", "CİDDİLİK:"),
    "report_title": ("📊 Truvex Threat Intelligence Report:", "📊 Truvex Threat Intelligence Hesabatı:"),
    "ind_type": ("Indicator Type:", "İndikator Tipi:"),
    "server_geo": ("Server IP & Geo-Location:", "Server IP və Geolokasiya:"),
    "rdns": ("Reverse DNS:", "Reverse DNS:"),
    "domain_age": ("Domain Age:", "Domen Yaşı:"),
    "ssl": ("SSL:", "SSL:"),
    "tti_label": ("Truvex Threat Index (TTI):", "Truvex Təhdid İndeksi (TTI):"),
    "decay_title": ("📈 Trust-Decay Trajectory", "📈 Etibar-Azalma Trayektoriyası"),
    "trend": ("Trend:", "Trend:"),
    "mitre_title": ("🎯 MITRE ATT&CK Mapping", "🎯 MITRE ATT&CK Uyğunlaşdırması"),
    "tactic": ("Tactic:", "Taktika:"),
    "no_mitre": ("No confirmed technique based on current CTI evidence.", "Mövcud CTI sübutlarına əsasən təsdiqlənmiş texnika yoxdur."),
    "cti_consensus": ("🌐 Global CTI Engine Consensus", "🌐 Qlobal CTI Mühərrik Konsensusu"),
    "risk_evidence": ("🔎 Risk Evidence", "🔎 Risk Sübutları"),
    "ai_title": ("🤖 Truvex AI-Assisted Triage Prototype", "🤖 Truvex AI-Dəstəkli Triage Prototipi"),
    "feed_title": ("📡 Live Telemetry Feed", "📡 Canlı Telemetriya Lenti"),
    "score": ("Score:", "Skor:"),
    "btn_incident": ("Incident", "İnsident"),
    "btn_pdf": ("PDF", "PDF"),
    "btn_json": ("JSON", "JSON"),
    "btn_delete": ("Delete", "Sil"),
    "confirm_delete": ("Delete this scan from history?", "Bu skan tarixçədən silinsin?"),
    "no_records": ("No records.", "Qeyd yoxdur."),
    "footer": ("Truvex CTI v16.0 • Multi-Source IOC Analysis Platform", "Truvex CTI v16.0 • Çoxmənbəli IOC Analiz Platforması"),
    "lang_en": ("English", "English"),
    "lang_az": ("Azərbaycan", "Azərbaycan"),
    "lang_label": ("Language", "Dil"),
    # ---------- Verdicts ----------
    "v_CRITICAL": ("CRITICAL", "KRİTİK"),
    "v_HIGH": ("HIGH", "YÜKSƏK"),
    "v_MEDIUM": ("MEDIUM", "ORTA"),
    "v_LOW": ("LOW", "AŞAĞI"),
    "v_CLEAN": ("CLEAN", "TƏMİZ"),
    # ---------- Engine statuses ----------
    "s_MALICIOUS": ("MALICIOUS", "ZƏRƏRLİ"),
    "s_SUSPICIOUS": ("SUSPICIOUS", "ŞÜBHƏLİ"),
    "s_CLEAN": ("CLEAN", "TƏMİZ"),
    "s_NOT_FOUND": ("NOT FOUND", "TAPILMADI"),
    "s_NOT_LISTED": ("NOT LISTED", "SİYAHIDA YOXDUR"),
    "s_NOT_CONFIGURED": ("NOT CONFIGURED", "QURULMAYIB"),
    "s_SKIPPED": ("SKIPPED", "KEÇİLDİ"),
    "s_ERROR": ("ERROR", "XƏTA"),
    "s_UNKNOWN": ("UNKNOWN", "NAMƏLUM"),
    # ---------- Indicator / scan types ----------
    "ty_url": ("URL", "URL"),
    "ty_domain": ("Domain", "Domen"),
    "ty_ip": ("IP address", "IP ünvanı"),
    "ty_hash_md5": ("MD5 hash", "MD5 hash"),
    "ty_hash_sha1": ("SHA1 hash", "SHA1 hash"),
    "ty_hash_sha256": ("SHA256 hash", "SHA256 hash"),
    "ty_file": ("File", "Fayl"),
    "ty_pure-cti": ("CTI scan", "CTI skan"),
    "ty_fayl": ("File scan", "Fayl skanı"),
    "ty_demo": ("Demo", "Demo"),
    # ---------- Tags ----------
    "tg_URL-Analysis": ("URL-Analysis", "URL-Analiz"),
    "tg_Domain-Analysis": ("Domain-Analysis", "Domen-Analiz"),
    "tg_IP-Analysis": ("IP-Analysis", "IP-Analiz"),
    "tg_Hash-Analysis": ("Hash-Analysis", "Hash-Analiz"),
    "tg_File-Analysis": ("File-Analysis", "Fayl-Analiz"),
    "tg_High-Risk": ("High-Risk", "Yüksək-Risk"),
    "tg_High-Risk-Malware": ("High-Risk-Malware", "Yüksək-Risk-Zərərverici"),
    "tg_Suspicious": ("Suspicious", "Şübhəli"),
    "tg_Suspicious-File": ("Suspicious-File", "Şübhəli-Fayl"),
    "tg_Limited-Evidence": ("Limited-Evidence", "Məhdud-Sübut"),
    "tg_No-Threat-Evidence": ("No-Threat-Evidence", "Təhdid-Sübutu-Yoxdur"),
    "tg_cti_sources": ("CTI-{n}-Sources", "CTI-{n}-Mənbə"),
    # ---------- MITRE ----------
    "mt_T1566_name": ("Phishing", "Fişinq"),
    "mt_T1566_tactic": ("Initial Access", "İlkin Giriş"),
    "mt_T1566_desc": ("Adversaries may use phishing techniques to gain access to victim systems.", "Hücumçular qurban sistemlərinə giriş əldə etmək üçün fişinq texnikalarından istifadə edə bilərlər."),
    "mt_T1105_name": ("Ingress Tool Transfer", "Alətlərin Daxil Edilməsi"),
    "mt_T1105_tactic": ("Command and Control", "Komanda və İdarəetmə"),
    "mt_T1105_desc": ("Adversaries may transfer files or payloads from an external system into the target network.", "Hücumçular faylları və ya zərərli yükləri xarici sistemdən hədəf şəbəkəyə köçürə bilərlər."),
    "mt_T1204_name": ("User Execution", "İstifadəçi Tərəfindən İcra"),
    "mt_T1204_tactic": ("Execution", "İcra"),
    "mt_T1204_desc": ("An adversary may rely upon a user opening a malicious file or executing a payload.", "Hücumçu istifadəçinin zərərli faylı açmasına və ya zərərli yükü icra etməsinə arxalana bilər."),
    # ---------- Trust decay ----------
    "decay_t_rapid": ("Rapid Degrading (Severe risk increase)", "Sürətli Pisləşmə (Şiddətli risk artımı)"),
    "decay_f_rapid": ("High-risk profile. Further investigation and monitoring are recommended.", "Yüksək riskli profil. Əlavə araşdırma və monitorinq tövsiyə olunur."),
    "decay_t_elev": ("Elevated Risk", "Artmış Risk"),
    "decay_f_elev": ("Threat indicators were observed. Close monitoring is recommended.", "Təhdid göstəriciləri müşahidə olunur. Yaxından izlənilməsi tövsiyə edilir."),
    "decay_t_lim": ("Limited Evidence", "Məhdud Sübut"),
    "decay_f_lim": ("Only limited threat intelligence evidence exists. Risk is assessed as low.", "Məhdud threat intelligence sübutu mövcuddur. Risk aşağı səviyyədə qiymətləndirilir."),
    "decay_t_stable": ("Stable / No Evidence", "Sabit / Sübut Yoxdur"),
    "decay_f_stable": ("No significant threat evidence was found in the available CTI sources.", "Mövcud CTI mənbələrində əhəmiyyətli təhlükə sübutu aşkar edilmədi."),
    # ---------- Risk evidence ----------
    "ev_vt_high": ("VirusTotal: high malicious ratio", "VirusTotal: yüksək zərərli nisbəti"),
    "ev_vt_elev": ("VirusTotal: elevated malicious ratio", "VirusTotal: artmış zərərli nisbəti"),
    "ev_vt_lim": ("VirusTotal: limited detections", "VirusTotal: məhdud aşkarlamalar"),
    "ev_vt_susp": ("VirusTotal: suspicious engines", "VirusTotal: şübhəli mühərriklər"),
    "ev_urlhaus": ("URLhaus: malicious URL", "URLhaus: zərərli URL"),
    "ev_phish": ("PhishTank: verified phishing", "PhishTank: təsdiqlənmiş fişinq"),
    "ev_openphish": ("OpenPhish: malicious URL", "OpenPhish: zərərli URL"),
    "ev_abuse_vh": ("AbuseIPDB: very high confidence", "AbuseIPDB: çox yüksək əminlik"),
    "ev_abuse_h": ("AbuseIPDB: high confidence", "AbuseIPDB: yüksək əminlik"),
    "ev_abuse_m": ("AbuseIPDB: moderate confidence", "AbuseIPDB: orta əminlik"),
    "ev_otx": ("AlienVault OTX: threat pulses found", "AlienVault OTX: təhdid pulsları tapıldı"),
    # ---------- Engine details ----------
    "e_timeout": ("Request timed out.", "Sorğu timeout oldu."),
    "e_nokey": ("{name} is missing in .env", "{name} .env-də yoxdur"),
    "e_apikey_bad": ("API key is invalid ({code}).", "API key etibarsızdır ({code})."),
    "e_authkey_bad": ("Auth-Key was rejected ({code}).", "Auth-Key qəbul edilmədi ({code})."),
    "e_rate": ("Rate limit ({code}).", "Rate limit ({code})."),
    "vt_notfound": ("Object not found in VirusTotal.", "VirusTotal-da obyekt tapılmadı."),
    "vt_detail": ("Malicious: {m} | Suspicious: {s} | Total: {t}", "Zərərli: {m} | Şübhəli: {s} | Cəmi: {t}"),
    "uh_need_url": ("A URL must be provided for URLhaus.", "URLhaus üçün URL daxil edilməlidir."),
    "uh_detail": ("Threat: {threat} | Status: {status} | Tags: {tags}", "Təhdid: {threat} | Status: {status} | Teqlər: {tags}"),
    "uh_detail_nt": ("Threat: {threat} | Status: {status} | Tags: none", "Təhdid: {threat} | Status: {status} | Teqlər: yoxdur"),
    "uh_notfound": ("URL not found in the URLhaus database.", "URL URLhaus database-də tapılmadı."),
    "uh_qs": ("query_status: {qs}", "query_status: {qs}"),
    "ab_noip": ("Could not resolve an IP address.", "IP həll edilə bilmədi."),
    "ab_detail": ("Abuse Confidence: {conf}% | Reports: {reports}", "Sui-istifadə Əminliyi: {conf}% | Hesabatlar: {reports}"),
    "otx_pulses": ("Threat Pulses: {count}", "Təhdid Pulsları: {count}"),
    "otx_timeout": ("OTX timed out ({sec}s).", "OTX timeout oldu ({sec}s)."),
    "pt_need_url": ("A URL must be provided for PhishTank.", "PhishTank üçün URL daxil edilməlidir."),
    "pt_verified": ("Verified phishing URL", "Təsdiqlənmiş fişinq URL-i"),
    "pt_partial": ("URL is in the database, but not fully verified/valid.", "URL database-də var, lakin tam verified/valid deyil."),
    "pt_notfound": ("URL not found in the PhishTank database.", "URL PhishTank database-də tapılmadı."),
    "op_need_url": ("A URL is required.", "URL tələb olunur."),
    "op_found": ("URL found in the OpenPhish feed.", "URL OpenPhish feed-də tapıldı."),
    "op_notfound": ("URL not found in the OpenPhish feed.", "URL OpenPhish feed-də tapılmadı."),
    "na_file": ("Not applicable to files.", "Fayl üçün tətbiq edilmir."),
    # ---------- Network context ----------
    "rdns_none": ("Reverse DNS not found", "Reverse DNS tapılmadı"),
    "geo_unknown_ip": ("Unknown", "Naməlum"),
    "geo_unknown": ("Unknown", "Bilinmir"),
    "geo_file": ("Local File Analysis", "Lokal Fayl Analizi"),
    "whois_ip": ("This is an IP address — domain age does not apply.", "IP ünvanıdır — domen yaşı tətbiq edilmir."),
    "whois_none": ("Domain registration data not found.", "Domen qeydiyyat məlumatı tapılmadı."),
    "whois_unavail": ("Domain age: data not available.", "Domen yaşı: məlumat mövcud deyil."),
    "whois_age": ("Domain age: {days} days", "Domen yaşı: {days} gün"),
    "whois_calc": ("Domain age could not be calculated.", "Domen yaşı hesablana bilmədi."),
    "whois_timeout": ("RDAP request timed out.", "RDAP sorğusu timeout oldu."),
    "whois_fail": ("Domain age could not be determined.", "Domen yaşı müəyyən edilə bilmədi."),
    "ssl_ok": ("SSL Active ({issuer})", "SSL Aktiv ({issuer})"),
    "ssl_none": ("No SSL certificate / not verified", "SSL Sertifikatı yoxdur / yoxlanılmadı"),
    # ---------- AI triage text (HTML) ----------
    "ai_dom_1": ("An IOC analysis of type <b>{type}</b> was performed for target <b>{target}</b>.", "<b>{target}</b> hədəfi üçün <b>{type}</b> tipli IOC analizi aparıldı."),
    "ai_dom_2": ("<br><br>Available CTI engines: <b>{n}</b>/6.", "<br><br>Mövcud CTI mühərrikləri: <b>{n}</b>/6."),
    "ai_dom_3": ("<br>Sources reporting malicious: <b>{m}</b>.", "<br>Zərərli nəticə verən mənbələr: <b>{m}</b>."),
    "ai_dom_4": ("<br>Final Truvex Threat Index: <b>{score}/100 ({verdict})</b>.", "<br>Yekun Truvex Təhdid İndeksi: <b>{score}/100 ({verdict})</b>."),
    "ai_ev_head": ("<br><br><b>Risk evidence:</b><br>", "<br><br><b>Risk sübutları:</b><br>"),
    "ai_ev_none": ("<br><br>No significant malicious evidence was found in the available sources.", "<br><br>Mövcud mənbələrdə əhəmiyyətli zərərli sübut aşkar edilmədi."),
    "ai_file_1": ("A static hash analysis was performed for file <b>{filename}</b>.", "<b>{filename}</b> faylı üçün statik hash analizi aparıldı."),
    "ai_file_2": ("<br><br>MD5: <code>{md5}</code><br>SHA1: <code>{sha1}</code><br>SHA256: <code>{sha256}</code>", "<br><br>MD5: <code>{md5}</code><br>SHA1: <code>{sha1}</code><br>SHA256: <code>{sha256}</code>"),
    "ai_file_3": ("<br><br>VirusTotal result: <b>{vt}</b>.<br>TTI: <b>{score}/100 ({verdict})</b>.", "<br><br>VirusTotal nəticəsi: <b>{vt}</b>.<br>TTI: <b>{score}/100 ({verdict})</b>."),
    "ai_demo": ("<b>Demo mode:</b> This report is synthetic and is intended only for presentation/testing.", "<b>Demo rejimi:</b> Bu hesabat sintetikdir və yalnız təqdimat/test üçündür."),
    "ai_legacy": ("No extended report data was stored for this historical scan.", "Tarixi skan üçün saxlanılmış geniş hesabat məlumatı yoxdur."),
    # ---------- Demo data ----------
    "demo_vt": ("Demo detection: {p}/{t}", "Demo aşkarlama: {p}/{t}"),
    "demo_url": ("Demo malicious URL", "Demo zərərli URL"),
    "demo_plain": ("Demo", "Demo"),
    "demo_pulses": ("Demo threat pulses: {n}", "Demo təhdid pulsları: {n}"),
    "demo_phish": ("Demo verified phishing", "Demo təsdiqlənmiş fişinq"),
    "demo_whois": ("Demo data — not a real WHOIS lookup", "Demo məlumat — real WHOIS sorğusu deyil"),
    "demo_ssl": ("Demo SSL context", "Demo SSL konteksti"),
    # ---------- HTTP messages ----------
    "err_no_indicator": ("No indicator was entered.", "İndikator daxil edilməyib."),
    "err_no_file": ("No file provided.", "Fayl yoxdur."),
    "err_empty_file": ("The file is empty.", "Fayl boşdur."),
    "err_scan_nf": ("Scan not found.", "Skan tapılmadı."),
    "err_no_report": ("No report data exists for this scan.", "Bu skan üçün hesabat məlumatı mövcud deyil."),
    # ---------- Incident page ----------
    "inc_title": ("🛡️ TRUVEX Incident Details", "🛡️ TRUVEX İnsident Təfərrüatları"),
    "inc_back": ("← Dashboard", "← Panel"),
    "inc_indicator": ("Indicator", "İndikator"),
    "inc_type": ("Type", "Tip"),
    "inc_id": ("Incident ID", "İnsident ID"),
    "inc_none": ("No incident", "İnsident yoxdur"),
    "inc_created": ("Created", "Yaradılıb"),
    "inc_cti_ev": ("CTI Evidence", "CTI Sübutları"),
    "inc_engine": ("Engine", "Mühərrik"),
    "inc_status": ("Status", "Status"),
    "inc_detail": ("Detail", "Təfərrüat"),
    "inc_no_cti": ("No CTI report data.", "CTI hesabat məlumatı yoxdur."),
    "inc_no_ev": ("No evidence recorded.", "Sübut qeyd edilməyib."),
    "inc_notes": ("Analyst Notes", "Analitik Qeydləri"),
    "inc_notes_ph": ("Analyst note...", "Analitik qeydi..."),
    "inc_save": ("Save Notes", "Qeydləri Saxla"),
    "inc_pdf": ("PDF Report", "PDF Hesabat"),
    "inc_json": ("Export JSON", "JSON İxrac"),
    # ---------- Engine health page ----------
    "eh_title": ("TRUVEX Engine Health", "TRUVEX Mühərrik Vəziyyəti"),
    "eh_head": ("⚙️ CTI Engine Health", "⚙️ CTI Mühərrik Vəziyyəti"),
    "eh_ready": ("CONFIGURED / READY", "QURULUB / HAZIRDIR"),
    "eh_not": ("NOT CONFIGURED", "QURULMAYIB"),
    # ---------- PDF report ----------
    "pdf_title": ("TRUVEX CTI INCIDENT REPORT", "TRUVEX CTI İNSİDENT HESABATI"),
    "pdf_generated": ("Generated", "Yaradılma vaxtı"),
    "pdf_verdict": ("Verdict", "Nəticə"),
    "pdf_timestamp": ("Timestamp", "Vaxt damğası"),
    "pdf_no_ev": ("No recorded malicious evidence.", "Qeydə alınmış zərərli sübut yoxdur."),
    "pdf_cti_sources": ("CTI Sources", "CTI Mənbələri"),
    "pdf_no_mitre": ("No MITRE mapping recorded.", "MITRE uyğunlaşdırması qeyd edilməyib."),
    "pdf_context": ("Network / Context", "Şəbəkə / Kontekst"),
    "pdf_ip": ("IP", "IP"),
    "pdf_country": ("Country", "Ölkə"),
    "pdf_resolved": ("Resolved Domain", "Həll olunmuş Domen"),
    "pdf_whois": ("WHOIS", "WHOIS"),
    "pdf_no_notes": ("No analyst notes.", "Analitik qeydi yoxdur."),
    "none": ("none", "yoxdur"),
}

_MSG_RE = re.compile("\x1e([A-Za-z0-9_\\-]+)\x1f(.*?)\x1d", re.S)


def get_lang():
    try:
        code = request.cookies.get(LANG_COOKIE, DEFAULT_LANG)
    except RuntimeError:
        code = DEFAULT_LANG
    return code if code in LANGS else DEFAULT_LANG


def t(key, **params):
    entry = S.get(key)
    if not entry:
        return key
    text = entry[LANGS.index(get_lang())] or entry[0]
    if params:
        try:
            return text.format(**params)
        except Exception:
            return text
    return text


def M(key, **params):
    """Dil-neytral mesaj: DB-də açar kimi saxlanılır, göstərilən zaman tərcümə olunur."""
    return "\x1e" + key + "\x1f" + json.dumps(params, ensure_ascii=False) + "\x1d"


def _msg_sub(match, html):
    key = match.group(1)
    try:
        params = json.loads(match.group(2))
    except Exception:
        params = {}
    if "verdict" in params:
        params["verdict"] = verdict_t(params["verdict"])
    if "type" in params:
        params["type"] = type_t(params["type"])
    if "vt" in params:
        params["vt"] = status_t(params["vt"])
    if html:
        params = {k: str(h_escape(str(v))) for k, v in params.items()}
    return t(key, **params)


def tx(value):
    """M(...) mesajlarını cari dildə mətn kimi açır. Adi mətni olduğu kimi qaytarır."""
    if not isinstance(value, str) or "\x1e" not in value:
        return value
    return _MSG_RE.sub(lambda m: _msg_sub(m, False), value)


def txh(value):
    """Eyni, amma HTML üçün (parametrlər escape olunur, şablon HTML-dir)."""
    if not isinstance(value, str):
        return value
    return Markup(_MSG_RE.sub(lambda m: _msg_sub(m, True), value))


def tx_deep(obj):
    if isinstance(obj, str):
        return tx(obj)
    if isinstance(obj, list):
        return [tx_deep(x) for x in obj]
    if isinstance(obj, dict):
        return {k: tx_deep(v) for k, v in obj.items()}
    return obj


def verdict_t(v):
    return t("v_" + str(v)) if ("v_" + str(v)) in S else str(v)


def status_t(s):
    return t("s_" + str(s)) if ("s_" + str(s)) in S else str(s)


def type_t(x):
    return t("ty_" + str(x)) if ("ty_" + str(x)) in S else str(x)


def status_cls(s):
    if s == "MALICIOUS":
        return "st-bad"
    if s == "SUSPICIOUS":
        return "st-warn"
    if s in ("CLEAN", "NOT_FOUND", "NOT_LISTED"):
        return "st-ok"
    return "st-na"


def tag_t(tag):
    tag = str(tag).strip()
    m = re.fullmatch(r"CTI-(\d+)-Sources", tag)
    if m:
        return t("tg_cti_sources", n=m.group(1))
    return t("tg_" + tag) if ("tg_" + tag) in S else tag


def tags_t(tags):
    if isinstance(tags, str):
        tags = tags.split(",")
    return ", ".join(tag_t(x) for x in tags if str(x).strip())


def mitre_t(m):
    if not m:
        return m
    mid = m.get("id", "")
    out = dict(m)
    for field in ("name", "tactic", "desc"):
        key = f"mt_{mid}_{field}"
        if key in S:
            out["description" if field == "desc" else field] = t(key)
    return out


LANG_CSS = """
.lang-switch{display:flex;gap:8px;align-items:center}
.lang-switch .lang-label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-right:2px}
.lang-btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:999px;border:1px solid var(--border);
background:var(--panel2);color:var(--text);text-decoration:none;font-size:12px;font-weight:700;transition:all .15s}
.lang-btn:hover{border-color:var(--cyan);color:var(--cyan)}
.lang-btn.active{background:var(--blue);border-color:var(--blue);color:#fff}
"""


def lang_switch_html():
    cur = get_lang()
    nxt = request.full_path.rstrip("?") if request else "/"
    parts = [f'<div class="lang-switch"><span class="lang-label">{h_escape(t("lang_label"))}</span>']
    for code, flag in (("en", "🇬🇧"), ("az", "🇦🇿")):
        href = url_for("set_lang", code=code, next=nxt)
        cls = "lang-btn active" if code == cur else "lang-btn"
        parts.append(f'<a class="{cls}" href="{h_escape(href)}" hreflang="{code}">{flag} {h_escape(t("lang_" + code))}</a>')
    parts.append("</div>")
    return Markup("".join(parts))


@app.context_processor
def inject_i18n():
    return {
        "t": t, "tx": tx, "txh": txh, "lang": get_lang(),
        "verdict_t": verdict_t, "status_t": status_t, "type_t": type_t,
        "status_cls": status_cls, "tag_t": tag_t, "tags_t": tags_t, "mitre_t": mitre_t,
        "lang_switch": lang_switch_html(), "app_css": Markup(APP_CSS + LANG_CSS),
    }


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
            "trend": M("decay_t_rapid"),
            "history": [20, 50, score],
            "forecast": M("decay_f_rapid"),
            "color": "#ff2d55"
        }

    elif score >= 50:
        return {
            "trend": M("decay_t_elev"),
            "history": [15, 35, score],
            "forecast": M("decay_f_elev"),
            "color": "#ff7a00"
        }

    elif score > 0:
        return {
            "trend": M("decay_t_lim"),
            "history": [5, 10, score],
            "forecast": M("decay_f_lim"),
            "color": "#ffd60a"
        }

    else:
        return {
            "trend": M("decay_t_stable"),
            "history": [0, 0, 0],
            "forecast": M("decay_f_stable"),
            "color": "#00ff9d"
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
            M("e_nokey", name="VT_API_KEY")
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
                "detail": M("vt_notfound")
            }

        if r.status_code == 401:
            return _error_result(
                "VirusTotal",
                M("e_apikey_bad", code=401)
            )

        if r.status_code == 429:
            return _error_result(
                "VirusTotal",
                M("e_rate", code=429)
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
                M("vt_detail", m=malicious, s=suspicious, t=total)
            )
        }

    except requests.exceptions.Timeout:

        return _error_result(
            "VirusTotal",
            M("e_timeout")
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
            "detail": M("uh_need_url")
        }

    if not URLHAUS_AUTH_KEY:

        return _not_configured(
            "URLhaus",
            M("e_nokey", name="URLHAUS_AUTH_KEY")
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
                M("e_authkey_bad", code=r.status_code)
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
                    M("uh_detail", threat=threat, status=url_status, tags=", ".join(tags)) if tags else M("uh_detail_nt", threat=threat, status=url_status)
                )
            }

        if qs == "no_results":

            return {
                "engine": "URLhaus",
                "malicious": False,
                "available": True,
                "status": "NOT_LISTED",
                "detail": (
                    M("uh_notfound")
                )
            }

        return {
            "engine": "URLhaus",
            "malicious": False,
            "available": True,
            "status": "UNKNOWN",
            "detail": M("uh_qs", qs=qs)
        }

    except requests.exceptions.Timeout:

        return _error_result(
            "URLhaus",
            M("e_timeout")
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
                "detail": M("ab_noip")
            }

    if not ABUSEIPDB_API_KEY:

        return _not_configured(
            "AbuseIPDB",
            M("e_nokey", name="ABUSEIPDB_API_KEY")
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
                M("e_apikey_bad", code=401)
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
                M("ab_detail", conf=conf, reports=reports)
            )
        }

    except requests.exceptions.Timeout:

        return _error_result(
            "AbuseIPDB",
            M("e_timeout")
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
            "detail": M("otx_pulses", count=count)
        }

    except requests.exceptions.Timeout:

        return _error_result(
            "AlienVault OTX",
            M("otx_timeout", sec=OTX_TIMEOUT)
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
                M("pt_need_url")
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
                M("e_rate", code=509)
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
                        M("pt_verified")
                    )
                }

            if _bool(item.get("in_database")):

                return {
                    "engine": "PhishTank",
                    "malicious": False,
                    "available": True,
                    "status": "SUSPICIOUS",
                    "detail": (
                        M("pt_partial")
                    )
                }

        return {
            "engine": "PhishTank",
            "malicious": False,
            "available": True,
            "status": "NOT_LISTED",
            "detail": (
                M("pt_notfound")
            )
        }

    except requests.exceptions.Timeout:

        return _error_result(
            "PhishTank",
            M("e_timeout")
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
            "detail": M("op_need_url")
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
                M("op_found")
                if found
                else
                M("op_notfound")
            )
        }

    except requests.exceptions.Timeout:

        return _error_result(
            "OpenPhish",
            M("e_timeout")
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

    resolved_domain = M("rdns_none")

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
                resolved_domain = M("rdns_none")

        except ValueError:
            pass

        # ----------------------------------------------------
        # Resolve domain → IPv4
        # ----------------------------------------------------

        try:

            ip = socket.gethostbyname(host)

        except Exception:

            return (
                M("geo_unknown_ip"),
                M("geo_unknown"),
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
                M("geo_unknown")
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
        M("geo_unknown_ip"),
        M("geo_unknown"),
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
                M("whois_ip")
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
                M("whois_none")
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
                M("whois_unavail")
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
                M("whois_age", days=age_days)
            )

        except Exception:

            return (
                True,
                None,
                M("whois_calc")
            )

    except requests.exceptions.Timeout:

        return (
            False,
            None,
            M("whois_timeout")
        )

    except Exception:

        return (
            False,
            None,
            M("whois_fail")
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
                    M("ssl_ok", issuer=issuer)
                )

    except Exception:

        return (
            False,
            M("ssl_none")
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
                    M("ev_vt_high")
                )

            # Moderate consensus
            elif ratio >= 0.05:

                score += 20

                evidence.append(
                    M("ev_vt_elev")
                )

            # Limited detections
            elif ratio > 0:

                score += 5

                evidence.append(
                    M("ev_vt_lim")
                )

        if suspicious > 0 and malicious == 0:

            score += 3

            evidence.append(
                M("ev_vt_susp")
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
            M("ev_urlhaus")
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
            M("ev_phish")
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
            M("ev_openphish")
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
                M("ev_abuse_vh")
            )

        elif confidence >= 70:

            score += 20

            evidence.append(
                M("ev_abuse_h")
            )

        elif confidence >= 50:

            score += 10

            evidence.append(
                M("ev_abuse_m")
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
            M("ev_otx")
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
<html lang="{{ lang }}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ t('page_title') }}</title>
<style>{{ app_css }}</style>
<script>
function switchTab(tabName) {
    ['file', 'domain'].forEach(function (n) {
        document.getElementById(n + '-section').classList.toggle('active', n === tabName);
        document.getElementById('btn-' + n).classList.toggle('active', n === tabName);
    });
}
</script>
</head>
<body>
<div class="container">

<div class="top-bar">
    <div class="logo-area"><span>🛡️</span><h2>{{ t('app_title') }}</h2></div>
    {{ lang_switch }}
</div>
<div class="subtitle">{{ t('subtitle') }}</div>

<div class="tabs">
    <button id="btn-file" class="tab-btn" onclick="switchTab('file')">{{ t('tab_file') }}</button>
    <button id="btn-domain" class="tab-btn active" onclick="switchTab('domain')">{{ t('tab_domain') }}</button>
</div>

<!-- DASHBOARD -->
<div class="dashboard-grid">
    <div class="stat-card"><span>{{ t('st_total') }}</span><strong>{{ stats.total }}</strong><small>{{ t('st_total_sub') }}</small></div>
    <div class="stat-card"><span>{{ t('st_critical') }}</span><strong>{{ stats.critical }}</strong><small>{{ t('st_critical_sub') }}</small></div>
    <div class="stat-card"><span>{{ t('st_high') }}</span><strong>{{ stats.high }}</strong><small>{{ t('st_high_sub') }}</small></div>
    <div class="stat-card"><span>{{ t('st_avg') }}</span><strong>{{ stats.avg_score }}</strong><small>{{ t('st_avg_sub') }}</small></div>
    <div class="stat-card"><span>{{ t('st_24h') }}</span><strong>{{ stats.last_24h }}</strong><small>{{ t('st_new') }}</small></div>
    <div class="stat-card"><span>{{ t('st_7d') }}</span><strong>{{ stats.last_7d }}</strong><small>{{ t('st_new') }}</small></div>
</div>

<div class="analytics-box">
    <div class="analytics-col">
        <h4>{{ t('sev_dist') }}</h4>
        <div class="mini-bars">
            {% for v in ['CRITICAL','HIGH','MEDIUM','LOW','CLEAN'] %}
            <div class="c-{{ v|lower }}"><span>{{ verdict_t(v) }}</span><b>{{ stats[v|lower] }}</b></div>
            {% endfor %}
        </div>
    </div>
    <div class="analytics-col">
        <h4>{{ t('ind_types') }}</h4>
        {% for typ, count in stats.by_type %}<div class="type-line"><span>{{ type_t(typ) }}</span><b>{{ count }}</b></div>{% else %}<div class="muted">{{ t('no_data') }}</div>{% endfor %}
    </div>
    <div class="analytics-col">
        <h4>{{ t('top_tags') }}</h4>
        {% for tag, count in stats.top_tags %}<div class="type-line"><span>{{ tags_t(tag) }}</span><b>{{ count }}</b></div>{% else %}<div class="muted">{{ t('no_data') }}</div>{% endfor %}
    </div>
</div>

<div class="filter-box">
    <form action="/" method="GET" class="filter-form">
        <input type="text" name="search" value="{{ filters.search }}" placeholder="{{ t('search_ph') }}">
        <select name="verdict">
            {% for v in ["ALL","CRITICAL","HIGH","MEDIUM","LOW","CLEAN"] %}
            <option value="{{ v }}" {% if filters.verdict == v %}selected{% endif %}>{{ t('all') if v == 'ALL' else verdict_t(v) }}</option>
            {% endfor %}
        </select>
        <select name="scan_type">
            {% for v in ["ALL","pure-cti","fayl","demo"] %}
            <option value="{{ v }}" {% if filters.scan_type == v %}selected{% endif %}>{{ t('all') if v == 'ALL' else type_t(v) }}</option>
            {% endfor %}
        </select>
        <input type="date" name="date_from" value="{{ filters.date_from }}">
        <input type="date" name="date_to" value="{{ filters.date_to }}">
        <button type="submit">{{ t('filter_btn') }}</button>
        <a class="clear-btn" href="/">{{ t('clear_btn') }}</a>
    </form>
</div>

<!-- FILE -->
<div id="file-section" class="section-box">
    <form action="/analyze-file" method="POST" enctype="multipart/form-data">
        <input type="file" name="file" required style="color:#fbfaff;margin-bottom:15px;">
        <br>
        <button type="submit">{{ t('file_btn') }}</button>
    </form>
</div>

<!-- DOMAIN / URL / IP / HASH -->
<div id="domain-section" class="section-box active">
    <form action="/analyze-domain" method="POST">
        <input type="text" name="domain" placeholder="{{ t('domain_ph') }}" required>
        <br>
        <button type="submit">{{ t('domain_btn') }}</button>
    </form>
</div>

{% if result %}
<div class="results">

{% if result.incident_id %}
<div class="incident-badge">
    <div>
        <span class="lbl">{{ t('incident_gen') }}</span>
        <div class="id">{{ result.incident_id }}<span class="sev-pill">{{ t('severity') }} {{ verdict_t(result.verdict) }}</span></div>
    </div>
    <div>{% for tag in result.tags %}<span class="tag">{{ tag_t(tag) }}</span>{% endfor %}</div>
</div>
{% endif %}

<h3>{{ t('report_title') }} <span class="accent">{{ result.target }}</span></h3>

<p><strong>{{ t('ind_type') }}</strong> <span class="violet">{{ type_t(result.indicator_type) }}</span></p>

{% if result.indicator_type not in ['hash_md5','hash_sha1','hash_sha256'] %}
<p>
    <strong>{{ t('server_geo') }}</strong>
    <span class="accent" style="font-weight:700;">{{ result.geo_flag }} {{ tx(result.geo_country) }}</span>
    (<code>{{ tx(result.ip) }}</code>)
    |
    <strong>{{ t('rdns') }}</strong>
    <span class="violet">{{ tx(result.resolved_domain) }}</span>
</p>
<p>
    <strong>{{ t('domain_age') }}</strong> {{ tx(result.whois_info) }}
    |
    <strong>{{ t('ssl') }}</strong> {{ tx(result.ssl_info) }}
</p>
{% endif %}

<p>
    <strong>{{ t('tti_label') }}</strong>
    <span class="risk risk-{{ result.verdict|lower }}">{{ result.score }} / 100 ({{ verdict_t(result.verdict) }})</span>
</p>

<!-- DECAY -->
{% if result.decay %}
<div class="decay-box">
    <h4>{{ t('decay_title') }}</h4>
    <p style="margin:0 0 6px;font-size:13px;"><strong>{{ t('trend') }}</strong>
        <span style="color:{{ result.decay.color }};font-weight:700;">{{ tx(result.decay.trend) }}</span></p>
    <p style="margin:0;font-size:12px;color:var(--muted);">{{ tx(result.decay.forecast) }}</p>
</div>
{% endif %}

<!-- MITRE -->
{% if result.mitre %}
{% set mt = mitre_t(result.mitre) %}
<div class="mitre-box">
    <h4>{{ t('mitre_title') }}</h4>
    <span class="mitre-id">{{ mt.id }} - {{ mt.name }}</span>
    <span style="color:var(--text);font-size:13px;margin-left:8px;"><b>{{ t('tactic') }}</b> {{ mt.tactic }}</span>
    <p style="margin:8px 0 0;font-size:12px;color:var(--muted);">{{ mt.description }}</p>
</div>
{% else %}
<div class="info-box">🎯 <strong>MITRE ATT&amp;CK:</strong> {{ t('no_mitre') }}</div>
{% endif %}

<!-- CTI -->
<h4 class="cti-title">{{ t('cti_consensus') }}</h4>
<div class="cti-grid">
{% for label, key in [('VirusTotal','vt'),('URLhaus','urlhaus'),('AbuseIPDB','abuseipdb'),('AlienVault OTX','otx'),('PhishTank','phishtank'),('OpenPhish','openphish')] %}
{% set eng = result.cti[key] %}
<div class="cti-card">
    <strong>{{ label }}:</strong><br>
    <span class="{{ status_cls(eng.status) }}">
        {% if key == 'vt' %}{{ eng.get('positives', 0) }} / {{ eng.get('total', 0) }} — {% endif %}{{ status_t(eng.status) }}
    </span><br>
    <small>{{ tx(eng.detail) }}</small>
</div>
{% endfor %}
</div>

<!-- EVIDENCE -->
{% if result.evidence %}
<div class="evidence-box">
    <h4>{{ t('risk_evidence') }}</h4>
    <ul>{% for item in result.evidence %}<li>{{ tx(item) }}</li>{% endfor %}</ul>
</div>
{% endif %}

<!-- AI -->
<div class="ai-report">
    <h4>{{ t('ai_title') }}</h4>
    <p>{{ txh(result.ai_analysis) }}</p>
</div>

</div>
{% endif %}

<!-- FEED -->
<div class="feed-section">
<h4>{{ t('feed_title') }}</h4>
{% if feed %}
{% for item in feed %}
<div class="feed-item">
    <div class="feed-main">
        <span>🎯 <b class="t">{{ item.target }}</b></span>
        <span>{{ t('score') }} <b class="score-{{ item.verdict|lower }}">{{ item.score }}/100</b> <small>{{ verdict_t(item.verdict) }}</small></span>
    </div>
    <div class="feed-actions">
        <a class="action-btn" href="/incident/{{ item.id }}">{{ t('btn_incident') }}</a>
        <a class="action-btn" href="/generate-report/{{ item.id }}">{{ t('btn_pdf') }}</a>
        <a class="action-btn" href="/export-json/{{ item.id }}">{{ t('btn_json') }}</a>
        <form method="POST" action="/delete-scan/{{ item.id }}" onsubmit="return confirm({{ t('confirm_delete')|tojson }});">
            <button class="delete-btn" type="submit">{{ t('btn_delete') }}</button>
        </form>
    </div>
</div>
{% endfor %}
{% else %}
<div style="text-align:center;color:var(--dim);padding:15px;font-size:12px;">{{ t('no_records') }}</div>
{% endif %}
</div>

<div class="footer">{{ t('footer') }}</div>

</div>
</body>
</html>
"""



# ============================================================
# LANGUAGE SWITCH / RESULT VIEW
# ============================================================

def _default_filters():
    return {"search": "", "verdict": "ALL", "scan_type": "ALL", "date_from": "", "date_to": ""}


@app.route("/set-lang/<code>")
def set_lang(code):
    if code not in LANGS:
        code = DEFAULT_LANG
    nxt = request.args.get("next", "") or "/"
    # yalnız daxili yollara icazə (open-redirect qoruması)
    if not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt:
        nxt = "/"
    resp = redirect(nxt)
    resp.set_cookie(LANG_COOKIE, code, max_age=60 * 60 * 24 * 365, samesite="Lax")
    return resp


@app.route("/result/<int:scan_id>")
def view_result(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan or not scan.get("report"):
        return redirect(url_for("home"))
    result = dict(scan["report"])
    result["scan_id"] = scan_id
    return render_template_string(
        HTML_TEMPLATE,
        result=result,
        feed=get_scans_from_db(limit=50),
        stats=get_dashboard_stats(),
        filters=_default_filters()
    )


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

        return t("err_no_indicator"), 400

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

    ai_text = M("ai_dom_1", type=indicator_type, target=target)
    ai_text += M("ai_dom_2", n=available_count)
    ai_text += M("ai_dom_3", m=malicious_votes)
    ai_text += M("ai_dom_4", score=score, verdict=verdict)

    if evidence:
        ai_text += M("ai_ev_head") + "<br>".join("• " + x for x in evidence)
    else:
        ai_text += M("ai_ev_none")




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

    return redirect(url_for("view_result", scan_id=scan_id))


# ============================================================
# FILE ANALYSIS
# ============================================================

@app.route(
    "/analyze-file",
    methods=["POST"]
)
def analyze_file():

    if "file" not in request.files:

        return t("err_no_file"), 400


    file = request.files["file"]

    filename = file.filename or "unknown_file"

    file_bytes = file.read()


    if not file_bytes:

        return t("err_empty_file"), 400


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
            "detail": M("na_file")
        },

        "abuseipdb": {
            "available": False,
            "status": "SKIPPED",
            "malicious": False,
            "detail": M("na_file")
        },

        "otx": {
            "available": False,
            "status": "SKIPPED",
            "malicious": False,
            "detail": M("na_file")
        },

        "phishtank": {
            "available": False,
            "status": "SKIPPED",
            "malicious": False,
            "detail": M("na_file")
        },

        "openphish": {
            "available": False,
            "status": "SKIPPED",
            "malicious": False,
            "detail": M("na_file")
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

    ai_text = M("ai_file_1", filename=filename)
    ai_text += M("ai_file_2", md5=md5, sha1=sha1, sha256=sha256)
    ai_text += M("ai_file_3", vt=vt_res.get("status"), score=score, verdict=verdict)



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

        "geo_country": M("geo_file"),

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

    return redirect(url_for("view_result", scan_id=scan_id))



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
        return t("err_scan_nf"), 404

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
            "ai_analysis": M("ai_legacy")
        }

    cti_rows = []
    for name, data in (report.get("cti") or {}).items():
        if not isinstance(data, dict):
            continue
        cti_rows.append((name.upper(), data.get("status", "N/A"), data.get("detail", "")))

    html = """
    <!DOCTYPE html><html lang="{{ lang }}"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{{ t('inc_title') }}</title>
    <style>{{ app_css }}</style></head><body><div class="page">
    <div class="top-bar"><h2>{{ t('inc_title') }}</h2>{{ lang_switch }}</div>
    <p><a class="back" href="/">{{ t('inc_back') }}</a></p>
    <div class="ibox"><div class="igrid">
    <div class="icard"><div class="ilabel">{{ t('inc_indicator') }}</div><div class="ivalue">{{ report.get('target','N/A') }}</div></div>
    <div class="icard"><div class="ilabel">{{ t('inc_type') }}</div><div class="ivalue">{{ type_t(report.get('indicator_type', scan.type)) }}</div></div>
    <div class="icard"><div class="ilabel">TTI</div><div class="ivalue {{ report.get('verdict','CLEAN')|lower }}">{{ report.get('score',scan.score) }}/100 — {{ verdict_t(report.get('verdict','CLEAN')) }}</div></div>
    <div class="icard"><div class="ilabel">{{ t('inc_id') }}</div><div class="ivalue">{{ report.get('incident_id') or t('inc_none') }}</div></div>
    <div class="icard"><div class="ilabel">{{ t('inc_created') }}</div><div class="ivalue">{{ scan.timestamp }}</div></div>
    <div class="icard"><div class="ilabel">MITRE ATT&amp;CK</div><div class="ivalue">{% if report.get('mitre') %}{% set mt = mitre_t(report.mitre) %}{{ mt.id }} — {{ mt.name }}{% else %}N/A{% endif %}</div></div>
    </div></div>
    <div class="ibox"><h3>{{ t('inc_cti_ev') }}</h3><table class="ctitable"><tr><th>{{ t('inc_engine') }}</th><th>{{ t('inc_status') }}</th><th>{{ t('inc_detail') }}</th></tr>{% for name,status,detail in cti_rows %}<tr><td>{{ name }}</td><td class="{{ status_cls(status) }}">{{ status_t(status) }}</td><td>{{ tx(detail) }}</td></tr>{% else %}<tr><td colspan="3">{{ t('inc_no_cti') }}</td></tr>{% endfor %}</table></div>
    <div class="ibox"><h3>{{ t('risk_evidence') }}</h3>{% for e in report.get('evidence',[]) %}<span class="tag">{{ tx(e) }}</span>{% else %}<div class="ivalue">{{ t('inc_no_ev') }}</div>{% endfor %}</div>
    <div class="ibox"><h3>{{ t('ai_title') }}</h3><div class="ivalue">{{ txh(report.get('ai_analysis','N/A')) }}</div></div>
    <div class="ibox"><h3>{{ t('inc_notes') }}</h3><form method="POST"><textarea class="notes" name="analyst_notes" placeholder="{{ t('inc_notes_ph') }}">{{ scan.analyst_notes }}</textarea><br><br><button class="btn blue" type="submit">{{ t('inc_save') }}</button></form></div>
    <div><a class="btn" href="/generate-report/{{ scan.id }}">{{ t('inc_pdf') }}</a> <a class="btn" href="/export-json/{{ scan.id }}">{{ t('inc_json') }}</a></div>
    </div></body></html>
    """

    return render_template_string(html, scan=scan, report=report, cti_rows=cti_rows)


# ============================================================
# REPORTING / EXPORT
# ============================================================

_PDF_FONTS = None
_AZ_TRANSLIT = str.maketrans({
    "ə": "e", "Ə": "E", "ı": "i", "İ": "I", "ş": "s", "Ş": "S", "ğ": "g", "Ğ": "G",
    "ç": "c", "Ç": "C", "ö": "o", "Ö": "O", "ü": "u", "Ü": "U", "≥": ">=", "→": "->", "←": "<-"
})


def _pdf_fonts():
    """Azərbaycan hərfləri (ə, ş, ğ, ı...) üçün Unicode TTF şrift tapır."""
    global _PDF_FONTS
    if _PDF_FONTS:
        return _PDF_FONTS

    candidates = []
    if os.getenv("TRUVEX_PDF_FONT") and os.getenv("TRUVEX_PDF_FONT_BOLD"):
        candidates.append((os.getenv("TRUVEX_PDF_FONT"), os.getenv("TRUVEX_PDF_FONT_BOLD")))
    candidates += [
        ("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf"),
        ("C:/Windows/Fonts/segoeui.ttf", "C:/Windows/Fonts/segoeuib.ttf"),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        ("/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf", "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"),
        ("/Library/Fonts/Arial.ttf", "/Library/Fonts/Arial Bold.ttf"),
        ("/System/Library/Fonts/Supplemental/Arial.ttf", "/System/Library/Fonts/Supplemental/Arial Bold.ttf"),
    ]
    for reg, bold in candidates:
        if os.path.exists(reg) and os.path.exists(bold):
            try:
                pdfmetrics.registerFont(TTFont("TruvexSans", reg))
                pdfmetrics.registerFont(TTFont("TruvexSans-Bold", bold))
                _PDF_FONTS = ("TruvexSans", "TruvexSans-Bold", True)
                return _PDF_FONTS
            except Exception:
                continue

    _PDF_FONTS = ("Helvetica", "Helvetica-Bold", False)
    return _PDF_FONTS


def build_pdf_report(scan):
    report = scan.get("report") or {}
    reg, bold, unicode_ok = _pdf_fonts()

    def C(value):
        """Mətni cari dilə çevirir; Unicode şrift yoxdursa ASCII-yə yaxınlaşdırır."""
        text = str(tx(value))
        return text if unicode_ok else text.translate(_AZ_TRANSLIT)

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("TruvexTitle", parent=styles["Title"], alignment=TA_CENTER, fontName=bold, fontSize=18, spaceAfter=16, textColor=colors.HexColor("#5b21b6"))
    h = ParagraphStyle("TruvexH", parent=styles["Heading2"], fontName=bold, fontSize=12, spaceBefore=10, spaceAfter=7, textColor=colors.HexColor("#0891b2"))
    body = ParagraphStyle("TruvexBody", parent=styles["BodyText"], fontName=reg, fontSize=9, leading=13)
    cell = ParagraphStyle("TruvexCell", parent=body, fontSize=7, leading=9)

    verdict = str(report.get("verdict", "N/A"))
    story = [Paragraph(escape(t("pdf_title") if unicode_ok else C(t("pdf_title"))), title)]
    story.append(Paragraph(f"{escape(C(t('pdf_generated')))}: {escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}", body))
    story.append(Spacer(1, 10))

    summary = [
        [C(t("inc_indicator")), C(report.get("target", scan["target"]))],
        [C(t("ind_type")).rstrip(":"), C(type_t(report.get("indicator_type", scan["type"])))],
        ["TTI", f"{report.get('score', scan['score'])}/100"],
        [C(t("pdf_verdict")), C(verdict_t(verdict)) if verdict != "N/A" else "N/A"],
        [C(t("inc_id")), C(report.get("incident_id") or "N/A")],
        [C(t("pdf_timestamp")), str(scan.get("timestamp", "N/A"))],
    ]
    tbl = Table(summary, colWidths=[110, 395])
    tbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), reg), ("FONTNAME", (0, 0), (0, -1), bold),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ede9fe")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#a78bfa")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTSIZE", (0, 0), (-1, -1), 8)]))
    story += [tbl, Spacer(1, 12)]

    story.append(Paragraph(escape(C(t("risk_evidence")).replace("🔎", "").strip()), h))
    evidence = report.get("evidence") or []
    if evidence:
        for item in evidence:
            story.append(Paragraph("• " + escape(C(item)), body))
    else:
        story.append(Paragraph(escape(C(t("pdf_no_ev"))), body))

    story.append(Paragraph(escape(C(t("pdf_cti_sources"))), h))
    cti_rows = [[C(t("inc_engine")), C(t("inc_status")), C(t("inc_detail"))]]
    for name, data in (report.get("cti") or {}).items():
        if isinstance(data, dict):
            cti_rows.append([
                str(name).upper(),
                C(status_t(data.get("status", "N/A"))),
                Paragraph(escape(C(data.get("detail", ""))), cell),
            ])
    ct = Table(cti_rows, colWidths=[100, 95, 310], repeatRows=1)
    ct.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), reg), ("FONTNAME", (0, 0), (-1, 0), bold),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#5b21b6")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#a78bfa")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTSIZE", (0, 0), (-1, -1), 7)]))
    story += [ct, Spacer(1, 12)]

    story.append(Paragraph("MITRE ATT&amp;CK", h))
    mitre = mitre_t(report.get("mitre"))
    if mitre:
        story.append(Paragraph(escape(C(f"{mitre.get('id','N/A')} — {mitre.get('name','N/A')} | {mitre.get('tactic','N/A')}")), body))
        story.append(Paragraph(escape(C(mitre.get("description", ""))), body))
    else:
        story.append(Paragraph(escape(C(t("pdf_no_mitre"))), body))

    story.append(Paragraph(escape(C(t("pdf_context"))), h))
    context = [
        [C(t("pdf_ip")), C(report.get("ip", "N/A"))],
        [C(t("pdf_country")), C(report.get("geo_country", "N/A"))],
        [C(t("pdf_resolved")), C(report.get("resolved_domain", "N/A"))],
        [C(t("pdf_whois")), C(report.get("whois_info", "N/A"))],
        ["SSL", C(report.get("ssl_info", "N/A"))],
    ]
    nt = Table(context, colWidths=[110, 395])
    nt.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), reg), ("FONTNAME", (0, 0), (0, -1), bold),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#a78bfa")),
        ("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [nt, Spacer(1, 12)]

    story.append(Paragraph(escape(C(t("inc_notes"))), h))
    story.append(Paragraph(escape(C(scan.get("analyst_notes") or t("pdf_no_notes"))), body))
    doc.build(story)
    buffer.seek(0)
    return buffer


@app.route("/generate-report/<int:scan_id>")
def generate_report(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan or not scan.get("report"):
        return t("err_no_report"), 404
    pdf = build_pdf_report(scan)
    filename = f"truvex_report_{scan_id}.pdf"
    return send_file(pdf, mimetype="application/pdf", as_attachment=True, download_name=filename)


@app.route("/export-json/<int:scan_id>")
def export_json(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return t("err_scan_nf"), 404
    payload = {
        "scan_id": scan["id"],
        "target": scan["target"],
        "type": scan["type"],
        "score": scan["score"],
        "incident_id": scan["incident_id"],
        "timestamp": scan["timestamp"],
        "tags": scan["tags"],
        "analyst_notes": scan["analyst_notes"],
        "report": tx_deep(scan["report"])
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
    html = """<!DOCTYPE html><html lang="{{ lang }}"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{{ t('eh_title') }}</title><style>{{ app_css }}</style></head><body><div class="page" style="max-width:850px"><div class="top-bar"><h2>{{ t('eh_head') }}</h2>{{ lang_switch }}</div><p><a class="back" href="/">{{ t('inc_back') }}</a></p>{% for name,ok in status.items() %}<div class="engine-row"><span>{{ name }}</span><b class="{{ 'ok' if ok else 'off' }}">{{ t('eh_ready') if ok else t('eh_not') }}</b></div>{% endfor %}</div></body></html>"""
    return render_template_string(html, status=status)


# ============================================================
# DEMO / PRESENTATION MODE
# ============================================================

@app.route("/demo")
def demo_mode():
    target = "login-security-demo.example"
    cti = {
        "vt": {"engine":"VirusTotal","available":True,"malicious":True,"status":"MALICIOUS","positives":8,"suspicious":1,"total":70,"detail":M("demo_vt", p=8, t=70)},
        "urlhaus": {"engine":"URLhaus","available":True,"malicious":True,"status":"MALICIOUS","detail":M("demo_url")},
        "abuseipdb": {"engine":"AbuseIPDB","available":True,"malicious":False,"status":"CLEAN","confidence":0,"detail":M("demo_plain")},
        "otx": {"engine":"AlienVault OTX","available":True,"malicious":True,"status":"MALICIOUS","pulses":4,"detail":M("demo_pulses", n=4)},
        "phishtank": {"engine":"PhishTank","available":True,"malicious":True,"status":"MALICIOUS","detail":M("demo_phish")},
        "openphish": {"engine":"OpenPhish","available":True,"malicious":True,"status":"MALICIOUS","detail":M("demo_url")}
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
        "whois_info": M("demo_whois"),
        "ssl_info": M("demo_ssl"),
        "cti": cti,
        "evidence": evidence,
        "ai_analysis": M("ai_demo")
    }
    scan_id = save_scan_to_db(target, "demo", score, incident_id, tags, report_data=result)
    result["scan_id"] = scan_id
    update_report_json(scan_id, result)
    return redirect(url_for("view_result", scan_id=scan_id))


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