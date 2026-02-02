# ============================================================
#  update_status.py  (FINAL VERSION)
#  Markel Services Dashboard – Reliable Multi‑Provider Status Fetcher
#
#  Covers:
#   - Azure (via official RSS feed)
#   - Azure DevOps (via documented health API)
#   - Statuspage vendors (GitHub, Atlassian, JFrog, Elastic, Databricks…)
#   - Brainboard (custom deterministic HTML parser)
#
# ============================================================

import json
import time
import logging
from typing import Dict, Any, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET

# ------------------------------------------------------------
# Services List (edit when adding/removing providers)
# ------------------------------------------------------------
services = [
    {"name": "Azure", "url": "https://azure.status.microsoft/en-us/status", "type": "azure"},
    {"name": "Azure DevOps", "url": "https://status.dev.azure.com/", "type": "azure_devops"},

    # Statuspage-backed vendors
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
    {"name": "Port", "url": "https://status.port.io/", "type": "statuspage"},

    # Brainboard is NOT Statuspage → Custom parser
    {"name": "Brainboard", "url": "https://status.brainboard.co/", "type": "brainboard"},
]

# Common keywords for HTML fallback
KEYWORDS = ["operational", "online", "minor", "major", "degraded", "outage", "incident", "maintenance"]


# ------------------------------------------------------------
# HTTP Session with retry/backoff
# ------------------------------------------------------------
def http_session() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=0.4,
        status_forcelist=(429, 500, 502, 503, 504)
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.headers.update({
        "User-Agent": "markel-status-dashboard/2.0",
        "Accept": "application/json,text/html,application/xml;q=0.9,*/*;q=0.5"
    })
    return s


session = http_session()


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def normalize_status_from_text(text: str) -> str:
    t = text.lower()
    if "all services are online" in t or "online" in t or "operational" in t:
        return "Operational"
    if "minor" in t or "degraded" in t or "advisory" in t or "warning" in t:
        return "Minor"
    if "major" in t or "critical" in t or "outage" in t or "incident" in t:
        return "Major"
    return "Unknown"


def map_indicator(indicator: Optional[str]) -> str:
    i = (indicator or "none").lower()
    if i == "none":
        return "Operational"
    if i in ("minor", "degraded"):
        return "Minor"
    if i in ("major", "critical", "outage"):
        return "Major"
    return "Unknown"


def build_record(name: str, src: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": name,
        "status": payload.get("status", "Unknown"),
        "description": payload.get("description", "Status unknown"),
        "incidents": payload.get("incidents", []),
        "source": src
    }


# ------------------------------------------------------------
# Statuspage API Handler
# ------------------------------------------------------------
def fetch_statuspage(url: str) -> Dict[str, Any]:
    base = url.rstrip("/")
    for endpoint in ("/api/v2/summary.json", "/api/v2/status.json"):
        r = session.get(base + endpoint, timeout=10)
        if r.ok:
            data = r.json()
            sn = data.get("status", {})
            indicator = sn.get("indicator", "none")
            desc = sn.get("description", "Unknown")

            incidents = []
            for inc in data.get("incidents") or []:
                incidents.append({
                    "title": inc.get("name"),
                    "impact": inc.get("impact"),
                    "started_at": inc.get("started_at"),
                    "updated_at": inc.get("updated_at"),
                    "shortlink": inc.get("shortlink")
                })

            return {
                "status": map_indicator(indicator),
                "description": desc,
                "incidents": incidents
            }
    return {"status": "Unknown", "description": "Status unknown", "incidents": []}


# ------------------------------------------------------------
# Azure (via RSS feed — official method)
# ------------------------------------------------------------
def fetch_azure_rollup() -> Dict[str, Any]:
    FEED = "https://rssfeed.azure.status.microsoft/en-us/status/feed/"
    try:
        r = session.get(FEED, timeout=10)
        if r.ok:
            root = ET.fromstring(r.text)
            items = root.findall(".//item")
            if items:
                item = items[0]
                title = (item.findtext("title") or "").strip()
                link = (item.findtext("link") or "").strip()
                pub = (item.findtext("pubDate") or "").strip()

                low = title.lower()
                if "active" in low or "investigating" in low:
                    impact = "major" if any(w in low for w in ["critical", "major", "outage"]) else "minor"
                    return {
                        "status": "Major" if impact == "major" else "Minor",
                        "description": title,
                        "incidents": [{
                            "title": title,
                            "impact": impact,
                            "started_at": pub,
                            "updated_at": pub,
                            "shortlink": link
                        }]
                    }

            return {"status": "Operational", "description": "All Systems Operational", "incidents": []}

    except Exception:
        pass

    # Fallback HTML phrase
    r2 = session.get("https://azure.status.microsoft/", timeout=10)
    if r2.ok:
        soup = BeautifulSoup(r2.text, "html.parser")
        text = soup.get_text(" ", strip=True).lower()
        if "there are currently no active events" in text:
            return {"status": "Operational", "description": "All Systems Operational", "incidents": []}

    return {"status": "Unknown", "description": "Status unknown", "incidents": []}


# ------------------------------------------------------------
# Azure DevOps (documented API)
# ------------------------------------------------------------
def fetch_azure_devops() -> Dict[str, Any]:
    url = "https://status.dev.azure.com/_apis/status/health?api-version=7.1-preview.1"
    r = session.get(url, timeout=10)
    if r.ok:
        data = r.json()
        health = (data.get("status") or {}).get("health", "").lower()
        msg = (data.get("status") or {}).get("message", "Azure DevOps Status")

        if health in ("healthy", "ok", "operational", "none"):
            return {"status": "Operational", "description": msg, "incidents": []}
        if health in ("degraded", "warning", "advisory"):
            return {"status": "Minor", "description": msg, "incidents": []}
        if health in ("unhealthy", "critical", "major", "outage", "incident"):
            return {"status": "Major", "description": msg, "incidents": []}

    return {"status": "Unknown", "description": "Status unknown", "incidents": []}


# ------------------------------------------------------------
# Brainboard (custom exact DOM parser)
# ------------------------------------------------------------
def fetch_brainboard(url: str) -> Dict[str, Any]:
    r = session.get(url, timeout=10)
    if not r.ok:
        return {"status": "Unknown", "description": "Status unknown", "incidents": []}

    soup = BeautifulSoup(r.text, "html.parser")
    text = soup.get_text(" ", strip=True).lower()

    # The Brainboard page literally says: "All services are online"
    if "all services are online" in text:
        return {
            "status": "Operational",
            "description": "All services are online",
            "incidents": []
        }

    if "operational" in text:
        return {
            "status": "Operational",
            "description": "Operational",
            "incidents": []
        }

    if any(w in text for w in ["degraded", "partial", "outage", "major", "incident"]):
        return {
            "status": "Major",
            "description": "Service issue detected",
            "incidents": []
        }

    return {"status": "Unknown", "description": "Status unknown", "incidents": []}


# ------------------------------------------------------------
# Generic fallback (HTML keyword scan)
# ------------------------------------------------------------
def fetch_html_keywords(url: str) -> Dict[str, Any]:
    r = session.get(url, timeout=10)
    if not r.ok:
        return {"status": "Unknown", "description": "Status unknown", "incidents": []}

    soup = BeautifulSoup(r.text, "html.parser")
    text = soup.get_text(" ", strip=True)

    derived = normalize_status_from_text(text)

    if derived == "Unknown":
        return {"status": "Operational", "description": "All Systems Operational", "incidents": []}

    desc = (
        "All Systems Operational" if derived == "Operational" else
        "Degraded Performance" if derived == "Minor" else
        "Major Incident"
    )
    return {"status": derived, "description": desc, "incidents": []}


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
def main():
    results = []

    for svc in services:
        name = svc["name"]
        url = svc["url"]
        stype = svc["type"]

        try:
            if stype == "azure":
                result = fetch_azure_rollup()
            elif stype == "azure_devops":
                result = fetch_azure_devops()
            elif stype == "statuspage":
                result = fetch_statuspage(url)
            elif stype == "brainboard":
                result = fetch_brainboard(url)
            else:
                result = fetch_html_keywords(url)

            results.append(build_record(name, url, result))

        except Exception as ex:
            logging.exception(f"Failed for {name}: {ex}")
            results.append(build_record(name, url, {
                "status": "Unknown",
                "description": "Status unknown",
                "incidents": []
            }))

    with open("status.json", "w", encoding="utf-8") as f:
        json.dump({"services": results, "generated_at": int(time.time())}, f, indent=2)

    print("✔ Status updated successfully.")


if __name__ == "__main__":
    main()
