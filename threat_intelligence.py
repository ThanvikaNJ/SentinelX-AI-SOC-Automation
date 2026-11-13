"""Optional IP reputation lookup using AbuseIPDB. Requires an API key in the environment."""
import os
import requests

def check_ip_reputation(ip: str) -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"available": False, "message": "Set ABUSEIPDB_API_KEY to enable reputation lookups."}
    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": api_key, "Accept": "application/json"},
        timeout=10,
    )
    response.raise_for_status()
    data = response.json().get("data", {})
    return {
        "available": True,
        "ip": data.get("ipAddress"),
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
    }
