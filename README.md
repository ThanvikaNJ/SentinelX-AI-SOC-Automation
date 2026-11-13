# SentinelX — AI-Powered SOC Analyst & Threat Detection Automation

SentinelX is a defensive SOC triage lab that analyses authentication logs, detects repeated failed logins, flags possible successful access after failures, applies ML-assisted anomaly detection, prioritises alerts and generates incident reports.

## Features
- CSV-based security event ingestion
- Rolling-window brute-force detection
- Successful-login-after-failures correlation
- Isolation Forest anomaly triage
- Severity and risk scoring
- MITRE ATT&CK technique references
- Streamlit SOC dashboard
- Downloadable Markdown incident reports
- Optional AbuseIPDB reputation lookup
- Automated tests with GitHub Actions

## Architecture
CSV logs → validation → detection rules + Isolation Forest → risk-ranked alerts → analyst review → incident report

## Quick start
Python 3.10 or newer is recommended.

```bash
git clone https://github.com/ThanvikaNJ/SentinelX-AI-SOC-Automation.git
cd SentinelX-AI-SOC-Automation
python -m venv .venv
```

Activate the environment:

**macOS / Linux**
```bash
source .venv/bin/activate
```

**Windows PowerShell**
```powershell
.venv\Scripts\Activate.ps1
```

Install and run:
```bash
pip install -r requirements.txt
streamlit run app.py
```

Open the local URL printed by Streamlit (usually http://localhost:8501).

## Input CSV format
Required columns: `timestamp`, `source_ip`, `username`, `event_type`, `status`.

A sample dataset is included in `dataset/sample_security_logs.csv`. Its IP ranges are documentation-only TEST-NET ranges and do not identify real hosts.

## Detection logic
1. **Brute force:** counts failed authentication attempts per source IP in a rolling time window.
2. **Possible account compromise:** flags an IP with repeated failures and at least one success in the supplied data. Analysts should verify event order and identity context.
3. **ML anomaly:** Isolation Forest flags unusual aggregate IP behaviour relative to the current dataset. It is a triage hint, not a verdict.

Risk scores are heuristic prioritisation values, not calibrated probabilities.

## Optional IP reputation enrichment
Set `ABUSEIPDB_API_KEY` in your local environment using a key from AbuseIPDB. Never commit API keys. Example:
```bash
export ABUSEIPDB_API_KEY="your_key"
```

The lookup helper is intentionally separate from the dashboard so external enrichment is opt-in.

## Run tests
```bash
pytest -q
```

GitHub Actions runs the test suite on pushes and pull requests.

## Safety and limitations
- Built for defensive learning and controlled lab datasets.
- No exploit, scanning, credential collection or automatic blocking functionality.
- Response steps are recommendations only; an analyst must validate evidence and approve any containment.
- IP reputation results may be incomplete or stale.
- Do not upload confidential production logs or personal data to a public repository or third-party service.
- Validate detections against your environment before operational use.

## Future enhancements
- Splunk HEC integration for approved lab events
- Windows Event Log / Sysmon ingestion
- Alert deduplication and incident lifecycle tracking
- Analyst feedback loop and precision/recall evaluation
- Role-based access and audit trail
- Configurable MITRE ATT&CK data mapping

## Author
**Thanvika N. J.**  
Cybersecurity | SOC Analysis | AI-assisted Threat Detection
