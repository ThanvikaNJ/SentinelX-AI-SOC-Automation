from datetime import datetime, timezone

def build_incident_report(alert: dict) -> str:
    """Create a Markdown triage report; no containment action is performed."""
    return f"""# SentinelX Security Incident Report

- **Generated (UTC):** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}
- **Alert:** {alert.get('title', 'Unknown')}
- **Severity:** {alert.get('severity', 'Unrated')}
- **Risk score:** {alert.get('risk_score', 'N/A')}/100
- **Source IP:** {alert.get('source_ip', 'Unknown')}
- **Affected account(s):** {alert.get('username', 'Unknown')}
- **MITRE ATT&CK:** {alert.get('mitre_id', 'N/A')} — {alert.get('mitre_technique', 'N/A')}

## Evidence and analysis
{alert.get('explanation', 'No explanation available.')}

## Recommended analyst action
{alert.get('recommendation', 'Investigate manually.')}

## Analyst notes
- Validate timestamps and event source.
- Correlate with endpoint, firewall, VPN and identity-provider telemetry.
- Record disposition (true positive / false positive / benign positive).
- Obtain approval before any containment action.

> This report is generated automatically for defensive triage. It does not establish attribution or confirm compromise.
"""
