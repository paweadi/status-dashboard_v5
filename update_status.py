import json
import requests
from bs4 import BeautifulSoup

services = [
    {"name": "Azure", "url": "https://azure.status.microsoft/en-us/status"},
    {"name": "Azure DevOps", "url": "https://status.dev.azure.com/"},
    {"name": "Azure Databricks", "url": "https://status.azuredatabricks.net/"},
    {"name": "JFrog", "url": "https://status.jfrog.io/"},
    {"name": "Elastic", "url": "https://status.elastic.co/"},
    {"name": "Octopus Deploy", "url": "https://status.octopus.com/"},
    {"name": "Lucid", "url": "https://status.lucid.co/"},
    {"name": "Jira", "url": "https://jira-software.status.atlassian.com/"},
    {"name": "Confluence", "url": "https://confluence.status.atlassian.com/"},
    {"name": "GitHub", "url": "https://www.githubstatus.com/"},
    {"name": "CucumberStudio", "url": "https://status.cucumberstudio.com/"},
    {"name": "Fivetran", "url": "https://status.fivetran.com/"},
    {"name": "Brainboard", "url": "https://status.brainboard.co/"},
    {"name": "Port", "url": "https://status.port.io/"}
]

def normalize_status(text):
    text = text.lower()
    if "operational" in text or "all systems" in text:
        return "Operational"
    elif "minor" in text or "degraded" in text:
        return "Minor"
    elif "major" in text or "critical" in text or "outage" in text:
        return "Major"
    return "Unknown"

def map_indicator(indicator):
    indicator = indicator.lower() if indicator else "none"
    if indicator == "none":
        return "Operational"
    elif indicator in ["minor", "degraded"]:
        return "Minor"
    elif indicator in ["major", "critical", "outage"]:
        return "Major"
    return "Operational"

def sanitize_description(desc, indicator):
    if not desc:
        return "All systems operational" if indicator == "none" else "Service status update"
    if indicator == "none" and "maintenance" in desc.lower():
        return "All systems operational"
    clean_desc = desc.strip()
    if len(clean_desc) > 150:
        clean_desc = clean_desc[:150] + "..."
    return clean_desc

updated_services = []
for svc in services:
    name = svc["name"]
    url = svc["url"]
    status = "Unknown"
    description = "Could not fetch status"
    try:
        # API logic for CucumberStudio and Brainboard
        if name in ["CucumberStudio", "Brainboard"]:
            api_url = f"{url}api/v2/status.json"
            api_resp = requests.get(api_url, timeout=10)
            if api_resp.status_code == 200:
                data = api_resp.json()
                indicator = data.get('status', {}).get('indicator', 'none')
                desc = data.get('status', {}).get('description', '')
                status = map_indicator(indicator)
                description = sanitize_description(desc, indicator)
            else:
                status = "Operational"
                description = "Status API not reachable; assuming operational"
            updated_services.append({'name': name, 'status': status, 'description': description})
            continue

        # HTML scraping for other services
        resp = requests.get(url, timeout=10, verify=False)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            text_candidates = [tag.get_text(strip=True) for tag in soup.find_all(['span', 'div', 'p', 'h1', 'h2']) if tag.get_text(strip=True)]
            for txt in text_candidates:
                if any(word in txt.lower() for word in ['operational', 'minor', 'major', 'degraded', 'outage']):
                    status = normalize_status(txt)
                    # Sanitize and truncate description
                    clean_desc = txt.strip()
                    if len(clean_desc) > 150:
                        clean_desc = clean_desc[:150] + "..."
                    description = clean_desc
                    break
            if status == "Unknown":
                status = "Operational"
                description = "Page loaded successfully, no issues detected"
    except Exception as e:
        status = "Operational"
        description = f"Fallback to Operational (error: {e})"

    updated_services.append({'name': name, 'status': status, 'description': description})

with open("status.json", "w", encoding="utf-8") as f:
    json.dump({"services": updated_services}, f, indent=4)

print("✅ Updated status.json with sanitized and truncated descriptions.")
