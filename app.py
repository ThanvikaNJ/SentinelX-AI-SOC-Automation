import streamlit as st
import pandas as pd
from pathlib import Path
from detector import analyze_logs
from incident_report import build_incident_report

st.set_page_config(page_title="SentinelX | AI SOC", page_icon="🛡️", layout="wide")
st.title("🛡️ SentinelX — AI-Powered SOC Analyst")
st.caption("Security log triage • anomaly detection • risk scoring • incident reporting")

sample_path = Path("dataset/sample_security_logs.csv")
uploaded = st.sidebar.file_uploader("Upload authentication/security logs (CSV)", type=["csv"])
if uploaded:
    logs = pd.read_csv(uploaded)
elif sample_path.exists():
    logs = pd.read_csv(sample_path)
    st.sidebar.info("Using included sample dataset.")
else:
    st.error("No dataset found. Upload a CSV file to begin.")
    st.stop()

st.sidebar.markdown("### Detection settings")
threshold = st.sidebar.slider("Failed logins threshold", 3, 15, 5)
window_minutes = st.sidebar.slider("Detection window (minutes)", 1, 60, 10)

required = {"timestamp", "source_ip", "username", "event_type", "status"}
missing = required - set(logs.columns)
if missing:
    st.error(f"CSV is missing required columns: {', '.join(sorted(missing))}")
    st.stop()

results = analyze_logs(logs, failed_threshold=threshold, window_minutes=window_minutes)
alerts = results["alerts"]
metrics = results["metrics"]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events analysed", metrics["events"])
c2.metric("Alerts generated", metrics["alerts"])
c3.metric("High / Critical", metrics["high_critical"])
c4.metric("Unique source IPs", metrics["unique_ips"])

st.subheader("Security events")
st.dataframe(logs, use_container_width=True, hide_index=True)

st.subheader("Prioritised alerts")
if alerts.empty:
    st.success("No alerts generated with the current detection settings.")
else:
    st.dataframe(alerts, use_container_width=True, hide_index=True)
    selected = st.selectbox("Select an alert to investigate", alerts.index.tolist(),
                            format_func=lambda i: f'{alerts.loc[i, "severity"]} — {alerts.loc[i, "title"]}')
    alert = alerts.loc[selected].to_dict()
    st.markdown("### Analyst investigation")
    st.write(alert["explanation"])
    st.write(f'**MITRE ATT&CK:** {alert["mitre_id"]} — {alert["mitre_technique"]}')
    st.write(f'**Recommended action:** {alert["recommendation"]}')
    report = build_incident_report(alert)
    st.download_button("Download incident report (Markdown)", report,
                       file_name=f"sentinelx-incident-{selected}.md", mime="text/markdown")

st.caption("Educational defensive tool. Validate alerts before taking action; response actions are recommendations only.")
