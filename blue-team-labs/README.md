# Blue-Team Mini Projects

Three small, defensive SOC utilities added to complement SentinelX:

1. **Linux Authentication Log Analyzer** — parses sample SSH authentication events, detects repeated failures and flags a successful login following repeated failures.
2. **IOC Triage Workbench** — scores IPs, domains, URLs and file hashes against a user-maintained local watchlist. It performs no external lookups.
3. **Phishing Email Triage** — extracts sender, reply-to, URLs and attachment names from an email text/EML file and highlights suspicious indicators.

## Quick start

Use Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r blue-team-labs/requirements.txt
```

Run from the repository root:

```bash
python blue-team-labs/auth-log-analyzer/analyze_auth.py blue-team-labs/auth-log-analyzer/sample_auth.log
python blue-team-labs/ioc-triage/ioc_triage.py --input blue-team-labs/ioc-triage/sample_iocs.csv --watchlist blue-team-labs/ioc-triage/watchlist.txt
python blue-team-labs/phishing-triage/phishing_triage.py blue-team-labs/phishing-triage/sample_email.eml
```

All tools are local/offline by default. They are learning aids, not replacements for an EDR, SIEM, sandbox, or analyst review. Sample indicators and logs are synthetic.