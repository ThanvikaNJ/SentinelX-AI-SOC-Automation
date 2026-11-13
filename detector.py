"""Rule-based and ML-assisted security log analysis for SentinelX."""
from __future__ import annotations
import pandas as pd
from sklearn.ensemble import IsolationForest

REQUIRED = {"timestamp", "source_ip", "username", "event_type", "status"}
MITRE = {
    "bruteforce": ("T1110", "Brute Force"),
    "suspicious_success": ("T1078", "Valid Accounts"),
    "port_scan": ("T1046", "Network Service Discovery"),
    "anomaly": ("T1078", "Valid Accounts"),
}

def _severity(score: int) -> str:
    if score >= 85: return "Critical"
    if score >= 65: return "High"
    if score >= 35: return "Medium"
    return "Low"

def analyze_logs(logs: pd.DataFrame, failed_threshold: int = 5,
                 window_minutes: int = 10) -> dict:
    missing = REQUIRED - set(logs.columns)
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(sorted(missing))}")
    df = logs.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df = df.dropna(subset=["timestamp"])
    df["status"] = df["status"].astype(str).str.lower()
    df["event_type"] = df["event_type"].astype(str).str.lower()
    alerts = []

    # Sliding-window failed-login detection per source IP.
    failed = df[(df["event_type"].str.contains("login|auth", regex=True)) &
                (df["status"].isin(["failed", "failure", "denied"]))]
    for ip, group in failed.groupby("source_ip"):
        group = group.sort_values("timestamp")
        times = group["timestamp"].tolist()
        left = 0
        max_count = 0
        for right, current in enumerate(times):
            while (current - times[left]).total_seconds() > window_minutes * 60:
                left += 1
            max_count = max(max_count, right - left + 1)
        if max_count >= failed_threshold:
            score = min(100, 55 + (max_count - failed_threshold) * 8)
            technique = MITRE["bruteforce"]
            alerts.append({
                "title": f"Repeated failed logins from {ip}",
                "source_ip": str(ip), "username": ", ".join(sorted(group["username"].astype(str).unique())[:5]),
                "event_count": int(max_count), "risk_score": score, "severity": _severity(score),
                "category": "Brute force", "mitre_id": technique[0], "mitre_technique": technique[1],
                "explanation": f"{max_count} failed authentication events from {ip} were observed within a {window_minutes}-minute rolling window.",
                "recommendation": "Review authentication logs, verify whether the source is expected, check for a subsequent successful login, and consider temporary blocking only after validation."
            })

    # Success after repeated failures from the same IP.
    for ip, group in df.groupby("source_ip"):
        failures = group[group["status"].isin(["failed", "failure", "denied"])]
        successes = group[group["status"].isin(["success", "succeeded", "allowed"])]
        if len(failures) >= failed_threshold and not successes.empty:
            technique = MITRE["suspicious_success"]
            score = 88
            alerts.append({
                "title": f"Successful login after failures from {ip}",
                "source_ip": str(ip), "username": ", ".join(sorted(successes["username"].astype(str).unique())[:5]),
                "event_count": int(len(group)), "risk_score": score, "severity": _severity(score),
                "category": "Possible account compromise", "mitre_id": technique[0], "mitre_technique": technique[1],
                "explanation": f"{ip} has {len(failures)} failed event(s) and at least one successful event in the supplied data. Confirm event ordering and account ownership.",
                "recommendation": "Prioritise account-owner verification, inspect the successful session and endpoint telemetry, and follow your organisation's account containment procedure if compromise is confirmed."
            })

    # Optional anomaly model on aggregate IP behaviour.
    if len(df) >= 12:
        agg = df.groupby("source_ip").agg(
            event_count=("source_ip", "size"),
            unique_users=("username", "nunique"),
            failed_count=("status", lambda s: s.isin(["failed", "failure", "denied"]).sum())
        )
        if len(agg) >= 5:
            model = IsolationForest(contamination=0.15, random_state=42)
            labels = model.fit_predict(agg[["event_count", "unique_users", "failed_count"]])
            for ip, label in zip(agg.index, labels):
                if label == -1 and not any(a["source_ip"] == str(ip) for a in alerts):
                    row = agg.loc[ip]
                    technique = MITRE["anomaly"]
                    score = 48
                    alerts.append({
                        "title": f"Unusual authentication pattern from {ip}",
                        "source_ip": str(ip), "username": "Multiple / review",
                        "event_count": int(row["event_count"]), "risk_score": score, "severity": _severity(score),
                        "category": "ML anomaly", "mitre_id": technique[0], "mitre_technique": technique[1],
                        "explanation": "Isolation Forest marked this IP's aggregated activity as unusual compared with other IPs in this dataset. This is a triage signal, not proof of malicious activity.",
                        "recommendation": "Compare with normal baselines, asset role, VPN/proxy ranges and change windows before escalating."
                    })

    alerts_df = pd.DataFrame(alerts)
    if not alerts_df.empty:
        alerts_df = alerts_df.sort_values(["risk_score", "event_count"], ascending=False).reset_index(drop=True)
    metrics = {
        "events": int(len(df)), "alerts": int(len(alerts_df)),
        "high_critical": int(alerts_df["severity"].isin(["High", "Critical"]).sum()) if not alerts_df.empty else 0,
        "unique_ips": int(df["source_ip"].nunique())
    }
    return {"alerts": alerts_df, "metrics": metrics}
