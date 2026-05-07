from sklearn.ensemble import IsolationForest

def calculate_severity(row):

    score = 0

    if row["failed_logins"] >= 5:
        score += 3

    if row["malware_score"] >= 7:
        score += 4

    if row["data_transfer"] >= 200:
        score += 3

    return min(score, 10)

def detect_anomalies(df):

    features = df[
        [
            "failed_logins",
            "file_access",
            "malware_score",
            "data_transfer"
        ]
    ]

    model = IsolationForest(
        contamination=0.2,
        random_state=42
    )

    predictions = model.fit_predict(features)

    df["anomaly"] = predictions

    df["severity_score"] = df.apply(
        calculate_severity,
        axis=1
    )

    return df