# update_status.py
import json
import time
import logging
from typing import Dict, Any, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup

# ---------- Config ----------
services: List[Dict[str, str]] = [
    {"name": "Azure", "url": "https://azure.status.microsoft/en-us/status", "type": "azure"},
    {"name": "Azure DevOps", "url": "https://status.dev.azure.com/", "type": "azure_devops"},

    # Statuspage-backed services (prefer /api/v2/summary.json)
    {"name": "Azure Databricks", "url": "https://status.azuredatabricks.net/", "type": "statuspage"},
    {"name": "JFrog", "url": "https://status.jfrog.io/", "type": "statuspage"},
    {"name": "Elastic", "url": "https://status.elastic.co/", "type": "statuspage"},
    {"name": "Octopus Deploy", "url": "https://status.octopus.com/", "type": "statuspage"},
    {"name": "Lucid", "url": "https://status.lucid.co/", "type": "statuspage"},
    {"name": "Jira", "url": "https://jira-software.status.atlassian.com/", "type": "statuspage"},
    {"name": "Confluence", "url": "https://confluence.status.atlassian.com/", "type": "statuspage"},
    {"name": "GitHub", "url": "https://www.githubstatus.com/", "type": "statuspage"},
    {"name": "CucumberStudio", "url": "https://status.cucumberstudio.com/", "type": "statuspage"},
    {"name": "Fivetran", "url": "https://status.fivetran.com/", "type": "statuspage"},
    {"name": "Brainboard", "url": "https://status.brainboard.co/", "type": "statuspage"},
    {"name": "Port", "url": "https://status.port.io/", "type": "statuspage"},

    # Anything left will fall back to simple HTML keyword scanning
]

KEYWORDS = ['operational', 'minor', 'major', 'degraded', 'outage']

# ---------- HTTP client with retries ----------
def http_session() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=3, backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(['GET'])
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.headers.update({
        "User-Agent": "status-dashboard/1.0 (+https://example.org)"
    })
    return s

session = http_session()

# ---------- Mappers ----------
def normalize_status_from_text(text: str) -> str:
    text = text.lower()
    if "operational" in text or "all systems" in text:
        return "Operational"
    if "minor" in text or "degraded" in text:
        return "Minor"
    if "major" in text or "critical" in text or "outage" in text:
        return "Major"
    return "Unknown"

def map_indicator(indicator: Optional[str]) -> str:
    ind = (indicator or "none").lower()
    if ind == "none":
        return "Operational"
    if ind in ("minor", "degraded"):
        return "Minor"
    if ind in ("major", "critical", "outage"):
        return "Major"
    return "Unknown"

# ---------- Providers ----------
def fetch_statuspage(url: str) -> Dict[str, Any]:
    """
    Use /api/v2/summary.json for richer data (falls back to /status.json).
    """
    base = url.rstrip("/")
    # 1) Try summary.json
    r = session.get(f"{base}/api/v2/summary.json", timeout=10)
    if r.ok:
        data = r.json()
        indicator = (data.get("status") or {}).get("indicator", "none")
        description = (data.get("status") or {}).get("description", "Unknown")
        incidents = []
        for inc in data.get("incidents", []) or []:
            incidents.append({
                "title": inc.get("name"),
                "impact": inc.get("impact"),
                "started_at": inc.get("started_at"),
                "updated_at": inc.get("updated_at"),
                "shortlink": inc.get("shortlink") or inc.get("shortlink_url") or inc.get("shortlink_uri")
            })
        return {
            "status": map_indicator(indicator),
            "description": description,
            "incidents": incidents
        }

    # 2) Fallback to status.json (rollup only)
    r = session.get(f"{base}/api/v2/status.json", timeout=10)
    if r.ok:
        data = r.json()
        indicator = (data.get("status") or {}).get("indicator", "none")
        description = (data.get("status") or {}).get("description", "Unknown")
        return {
            "status": map_indicator(indicator),
            "description": description,
            "incidents": []
        }

    # 3) Last resort
    return {"status": "Unknown", "description": "Status unknown", "incidents": []}

def fetch_azure_rollup() -> Dict[str, Any]:
    # Your original code used this endpoint successfully
    r = session.get("https://status.azure.com/api/v2/status.json", timeout=10)
    if r.ok:
        data = r.json()
        indicator = (data.get("status") or {}).get("indicator", "none")
        description = (data.get("status") or {}).get("description", "Unknown")
        return {"status": map_indicator(indicator), "description": description, "incidents": []}
    return {"status": "Unknown", "description": "Status unknown", "incidents": []}

def fetch_azure_devops() -> Dict[str, Any]:
    # Public health rollup (preview) – good enough for dashboard lights
    # https://status.dev.azure.com/_apis/status/health?api-version=7.0-preview.1
    r = session.get("https://status.dev.azure.com/_apis/status/health?api-version=7.0-preview.1", timeout=10)
    if r.ok:
        data = r.json()
        # Simplify: when overall status is 'healthy' -> Operational; otherwise Minor/Major based on 'degraded'/'unhealthy'
        overall = (data.get("status", {}) or {}).get("overallState", "unknown").lower()
        if overall == "healthy":
            return {"status": "Operational", "description": "All Systems Operational", "incidents": []}
        if overall in ("degraded", "advisory"):
            return {"status": "Minor", "description": "Degraded Performance", "incidents": []}
        if overall in ("unhealthy", "incident"):
            return {"status": "Major", "description": "Service Incident", "incidents": []}
    return {"status": "Unknown", "description": "Status unknown", "incidents": []}

def fetch_html_keywords(url: str) -> Dict[str, Any]:
    r = session.get(url, timeout=10)
    if not r.ok:
        return {"status": "Unknown", "description": "Status unknown", "incidents": []}
    soup = BeautifulSoup(r.text, "html.parser")
    text_candidates = [
        tag.get_text(strip=True) for tag in soup.find_all(['span', 'div', 'p', 'h1', 'h2'])
        if tag.get_text(strip=True)
    ]
    derived = "Unknown"
    for txt in text_candidates:
        if any(word in txt.lower() for word in KEYWORDS):
            derived = normalize_status_from_text(txt)
            break
    if derived == "Unknown":
        derived = "Operational"
        description = "All Systems Operational"
    else:
        # Keep a human-friendly generic when we don't have provider wording
        description = "Degraded Performance" if derived == "Minor" else ("Major Incident" if derived == "Major" else "All Systems Operational")
    return {"status": derived, "description": description, "incidents": []}

# ---------- Main ----------
def build_record(name: str, src: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": name,
        "status": payload.get("status", "Unknown"),
        "description": payload.get("description", "Status unknown"),
        "incidents": payload.get("incidents", []) or [],
        "source": src
    }

def main() -> None:
    updated: List[Dict[str, Any]] = []
    for svc in services:
        name = svc["name"]
        url = svc["url"]
        stype = svc.get("type", "html")
        try:
            if stype == "azure":
                result = fetch_azure_rollup()
            elif stype == "azure_devops":
                result = fetch_azure_devops()
            elif stype == "statuspage":
                result = fetch_statuspage(url)
            else:
                result = fetch_html_keywords(url)

            updated.append(build_record(name, url, result))
        except Exception as ex:
            logging.exception("Failed for %s: %s", name, ex)
            updated.append(build_record(name, url, {
                "status": "Unknown",
                "description": "Status unknown",
                "incidents": []
            }))

    with open("status.json", "w", encoding="utf-8") as f:
        json.dump({"services": updated, "generated_at": int(time.time())}, f, indent=2)

    print("✅ Updated: using Statuspage summary APIs where available; incident details added; safer HTTP; HTML fallback retained.")

if __name__ == "__main__":
    main()
