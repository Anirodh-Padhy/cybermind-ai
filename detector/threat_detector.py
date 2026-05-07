def detect_threats(df):

    threats = []

    suspicious_logins = df[df["failed_logins"] >= 5]

    if not suspicious_logins.empty:

        threats.append({
            "type": "Brute Force Attempt",
            "severity": "High",
            "details": "Multiple failed login attempts detected"
        })

    malware_activity = df[df["malware_score"] >= 7]

    if not malware_activity.empty:

        threats.append({
            "type": "Malware Activity",
            "severity": "Critical",
            "details": "High malware score detected"
        })

    large_transfer = df[df["data_transfer"] >= 200]

    if not large_transfer.empty:

        threats.append({
            "type": "Suspicious Data Transfer",
            "severity": "High",
            "details": "Unusually large data transfer detected"
        })

    return threats