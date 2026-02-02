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
import xml.etree.ElementTree as ET

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

    # Brainboard is not Statuspage; let the generic probe detect & then HTML fallback
    {"name": "Brainboard", "url": "https://status.brainboard.co/", "type": "generic"},

    {"name": "Port", "url": "https://status.port.io/", "type": "statuspage"},
]

# Extended keywords to catch common phrasing across providers
KEYWORDS = ['operational', 'online', 'minor', 'major', 'degraded', 'outage', 'incident', 'maintenance']


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
        "User-Agent": "status-dashboard/1.2 (+https://example.org)",
        "Accept": "application/json,text/html;q=0.8,*/*;q=0.5",
    })
    return s


session = http_session()


# ----------------------------
# Mappers & helpers
# ----------------------------
def normalize_status_from_text(text: str) -> str:
    t = text.lower()
    if ("operational" in t) or ("all systems" in t) or ("online" in t):
        return "Operational"
    if ("minor" in t) or ("degraded" in t) or ("advisory" in t) or ("warning" in t):
        return "Minor"
    if ("major" in t) or ("critical" in t) or ("outage" in t) or ("unhealthy" in t) or ("incident" in t):
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
    Azure global status page: use the official RSS feed to determine current incidents.
    If there are no recent items, treat as Operational. Fallback to explicit HTML phrase
    to avoid misclassifying legend text.
    """
    FEED = "https://rssfeed.azure.status.microsoft/en-us/status/feed/"
    try:
        r = session.get(FEED, timeout=10, allow_redirects=True, headers={"Accept": "application/rss+xml,application/xml;q=0.9"})
        if r.ok and r.text.strip():
            root = ET.fromstring(r.text)
            items = root.findall(".//item")
            if items:
                item = items[0]
                title = (item.findtext("title") or "").strip()
                link = (item.findtext("link") or "").strip()
                pub = (item.findtext("pubDate") or "").strip()
                lower = title.lower()

                # 'Active'/'Investigating' suggests an ongoing incident on the public page.
                if ("active" in lower) or ("investigating" in lower):
                    impact = "major" if any(w in lower for w in ["critical", "major", "outage"]) else "minor"
                    return {
                        "status": "Major" if impact == "major" else "Minor",
                        "description": title or "Service incident",
                        "incidents": [{
                            "title": title or "Azure incident",
                            "impact": impact,
                            "started_at": pub,
                            "updated_at": pub,
                            "shortlink": link
                        }]
                    }
            # No current items → healthy
            return {"status": "Operational", "description": "All Systems Operational", "incidents": []}
    except Exception:
        pass

    # Fallback: explicit phrase on the page indicating no active events
    page = "https://azure.status.microsoft/"
    r2 = session.get(page, timeout=10, allow_redirects=True, headers={"Accept": "text/html"})
    if r2.ok:
        soup = BeautifulSoup(r2.text, "html.parser")
        text = " ".join(t.get_text(strip=True) for t in soup.find_all(["h1", "h2", "p", "div", "span"]) if t.get_text(strip=True))
        if "there are currently no active events" in (text or "").lower():
            return {"status": "Operational", "description": "All Systems Operational", "incidents": []}

    return {"status": "Unknown", "description": "Status unknown", "incidents": []}


def fetch_azure_devops() -> Dict[str, Any]:
    """
    Azure DevOps public health endpoint: map status.health -> Operational/Minor/Major.
    """
    url = "https://status.dev.azure.com/_apis/status/health?api-version=7.1-preview.1"
    r = session.get(url, timeout=10, allow_redirects=True, headers={"Accept": "application/json"})
    if r.ok:
        data = r.json() or {}
        health = (data.get("status") or {}).get("health", "").lower()
        message = (data.get("status") or {}).get("message") or "Azure DevOps Health"
        if health in ("healthy", "ok", "operational", "none"):
            return {"status": "Operational", "description": message, "incidents": []}
        if health in ("degraded", "advisory", "warning"):
            return {"status": "Minor", "description": message or "Degraded Performance", "incidents": []}
        if health in ("unhealthy", "incident", "outage", "major", "critical"):
            return {"status": "Major", "description": message or "Service Incident", "incidents": []}
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
    2) Try generic 'summary.json' pattern (some providers expose this).
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
                result = fetch_statuspage(url)
                if result["status"] == "Unknown":
                    # Safety: try generic probe if Statuspage not responding
                    result = fetch_generic(url)
            elif stype == "generic":
                result = fetch_generic(url)
            else:
                result = fetch_html_keywords(url)

            # Light debugging for Unknowns (comment out if too chatty)
            if result["status"] == "Unknown":
                print(f"[WARN] {name}: could not determine status from {url}")

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

    print("✅ Updated: Statuspage summaries, Azure RSS parsing, Azure DevOps health mapping, generic provider probe, safer HTTP, incidents included.")


if __name__ == "__main__":
    main()
