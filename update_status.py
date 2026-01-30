# update_status.py
# Near real-time service rollup with provider-authored descriptions & active incidents.
import json
import time
import logging
from typing import Dict, Any, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup

# ----------------------------
# Service catalog (edit here)
# ----------------------------
services: List[Dict[str, str]] = [
    {"name": "Azure", "url": "https://azure.status.microsoft/en-us/status", "type": "azure"},
    {"name": "Azure DevOps", "url": "https://status.dev.azure.com/", "type": "azure_devops"},

    # Statuspage-backed services
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

    # Brainboard doesn't appear to be Statuspage; let the generic probe detect
    {"name": "Brainboard", "url": "https://status.brainboard.co/", "type": "generic"},

    {"name": "Port", "url": "https://status.port.io/", "type": "statuspage"},
]

KEYWORDS = ['operational', 'minor', 'major', 'degraded', 'outage']


# ----------------------------
# Resilient HTTP session
# ----------------------------
def http_session() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(['GET'])
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.headers.update({
        # Friendly UA; some providers rate-limit or block unknown bots
        "User-Agent": "status-dashboard/1.1 (+https://markel.example)",
        "Accept": "application/json,text/html;q=0.8,*/*;q=0.5",
    })
    return s


session = http_session()


# ----------------------------
# Mappers & helpers
# ----------------------------
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


def build_record(name: str, src: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": name,
        "status": payload.get("status", "Unknown"),
        "description": payload.get("description", "Status unknown"),
        "incidents": payload.get("incidents", []) or [],
        "source": src
    }


# ----------------------------
# Providers
# ----------------------------
def fetch_statuspage(url: str) -> Dict[str, Any]:
    """
    Use /api/v2/summary.json (rich: incidents & components), fallback /api/v2/status.json (rollup only).
    """
    base = url.rstrip("/")
    for endpoint in ("/api/v2/summary.json", "/api/v2/status.json"):
        r = session.get(f"{base}{endpoint}", timeout=10, allow_redirects=True, headers={"Accept": "application/json"})
        if r.ok:
            data = r.json()
            status_node = (data.get("status") or {})
            indicator = status_node.get("indicator", "none")
            description = status_node.get("description", "Unknown")

            incidents = []
            for inc in (data.get("incidents") or []):
                incidents.append({
                    "title": inc.get("name"),
                    "impact": inc.get("impact"),
                    "started_at": inc.get("started_at"),
                    "updated_at": inc.get("updated_at"),
                    "shortlink": inc.get("shortlink") or inc.get("shortlink_url") or inc.get("shortlink_uri")
                })

            return {"status": map_indicator(indicator), "description": description, "incidents": incidents}

    return {"status": "Unknown", "description": "Status unknown", "incidents": []}


def fetch_azure_rollup() -> Dict[str, Any]:
    """
    Azure global status page: no documented public JSON roll-up -> parse headline text from HTML.
    """
    url = "https://azure.status.microsoft/en-us/status"
    r = session.get(url, timeout=10, allow_redirects=True, headers={"Accept": "text/html,application/xhtml+xml"})
    if r.ok:
        soup = BeautifulSoup(r.text, "html.parser")
        text = " ".join(
            t.get_text(strip=True)
            for t in soup.find_all(["h1", "h2", "p", "div", "span"])
            if t.get_text(strip=True)
        )
        derived = normalize_status_from_text(text)
        desc = (
            "All Systems Operational" if derived == "Operational"
            else "Degraded Performance" if derived == "Minor"
            else "Major Incident" if derived == "Major"
            else "Status unknown"
        )
        return {"status": derived, "description": desc, "incidents": []}

    return {"status": "Unknown", "description": "Status unknown", "incidents": []}


def fetch_azure_devops() -> Dict[str, Any]:
    """
    Use the public preview health endpoint and map conservatively.
    """
    url = "https://status.dev.azure.com/_apis/status/health?api-version=7.0-preview.1"
    r = session.get(url, timeout=10, allow_redirects=True, headers={"Accept": "application/json"})
    if r.ok:
        data = r.json() or {}
        rollup = (data.get("status") or {})
        # Try multiple fields; preview payloads can drift
        overall = (rollup.get("overallState") or rollup.get("overall") or "").lower()

        if overall in ("healthy", "ok", "none", "operational"):
            return {"status": "Operational", "description": "All Systems Operational", "incidents": []}
        if overall in ("degraded", "advisory", "warning"):
            return {"status": "Minor", "description": "Degraded Performance", "incidents": []}
        if overall in ("unhealthy", "incident", "outage", "major", "critical"):
            return {"status": "Major", "description": "Service Incident", "incidents": []}

    return {"status": "Unknown", "description": "Status unknown", "incidents": []}


def fetch_html_keywords(url: str) -> Dict[str, Any]:
    """
    Generic HTML keyword scan (last resort).
    """
    r = session.get(url, timeout=10, allow_redirects=True)
    if not r.ok:
        return {"status": "Unknown", "description": "Status unknown", "incidents": []}

    soup = BeautifulSoup(r.text, "html.parser")
    text_candidates = [
        tag.get_text(strip=True)
        for tag in soup.find_all(['span', 'div', 'p', 'h1', 'h2'])
        if tag.get_text(strip=True)
    ]

    derived = "Unknown"
    for txt in text_candidates:
        if any(word in txt.lower() for word in KEYWORDS):
            derived = normalize_status_from_text(txt)
            break

    if derived == "Unknown":
        derived = "Operational"
        desc = "All Systems Operational"
    else:
        desc = (
            "All Systems Operational" if derived == "Operational"
            else "Degraded Performance" if derived == "Minor"
            else "Major Incident"
        )

    return {"status": derived, "description": desc, "incidents": []}


def fetch_generic(url: str) -> Dict[str, Any]:
    """
    Provider-agnostic probe:
    1) Try Statuspage endpoints.
    2) Try common 'summary.json' pattern (some status platforms expose it).
    3) Fallback to HTML keywords.
    """
    sp = fetch_statuspage(url)
    if sp["status"] != "Unknown":
        return sp

    # Try a generic /summary.json (heuristic for non-Statuspage providers)
    try:
        r = session.get(url.rstrip("/") + "/summary.json", timeout=10, allow_redirects=True, headers={"Accept": "application/json"})
        if r.ok:
            data = r.json() or {}
            # Heuristic mappings
            status_node = data.get("status") or {}
            indicator = (status_node.get("indicator") or status_node.get("level") or "none")
            description = status_node.get("description") or data.get("overall") or data.get("description") or "Unknown"
            incidents = data.get("incidents") or []
            return {"status": map_indicator(indicator), "description": description, "incidents": incidents}
    except Exception:
        pass

    # Last resort
    return fetch_html_keywords(url)


# ----------------------------
# Main
# ----------------------------
def main() -> None:
    updated: List[Dict[str, Any]] = []

    for svc in services:
        name = svc["name"]
        url = svc["url"]
        stype = svc.get("type", "generic")

        try:
            if stype == "azure":
                result = fetch_azure_rollup()
            elif stype == "azure_devops":
                result = fetch_azure_devops()
            elif stype == "statuspage":
