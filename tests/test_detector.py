import pandas as pd
from detector import analyze_logs

def test_bruteforce_alert_is_created():
    rows = []
    for i in range(6):
        rows.append({"timestamp": f"2026-11-13T08:0{i}:00Z", "source_ip": "198.51.100.9",
                     "username": "admin", "event_type": "login", "status": "failed"})
    result = analyze_logs(pd.DataFrame(rows), failed_threshold=5, window_minutes=10)
    assert not result["alerts"].empty
    assert "Repeated failed logins" in result["alerts"].iloc[0]["title"]

def test_clean_log_has_no_rule_alert():
    df = pd.DataFrame([{"timestamp": "2026-11-13T08:00:00Z", "source_ip": "203.0.113.1",
                        "username": "user", "event_type": "login", "status": "success"}])
    result = analyze_logs(df)
    assert result["metrics"]["alerts"] == 0
