import streamlit as st
import pandas as pd
import plotly.express as px
import random

from streamlit_autorefresh import st_autorefresh

from parser.log_parser import load_logs
from detector.threat_detector import detect_threats
from detector.anomaly_detector import detect_anomalies
from ai.security_ai import generate_security_explanation

from auth.auth import login_ui
from database.db_manager import (
    save_alert,
    get_alerts,
    alert_exists
)

# ================= PAGE =================
st.set_page_config(
    page_title="CyberMind AI",
    layout="wide"
)

# ================= CUSTOM CSS =================
st.markdown("""
<style>

.main {
    background-color: #0E1117;
}

h1, h2, h3 {
    color: white;
}

.stMetric {
    background-color: #1E1E1E;
    padding: 15px;
    border-radius: 10px;
}

div[data-testid="stSidebar"] {
    background-color: #111827;
}

</style>
""", unsafe_allow_html=True)

# ================= AUTO REFRESH =================
st_autorefresh(
    interval=5000,
    limit=None,
    key="refresh"
)

# ================= SESSION =================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

# ================= LOGIN =================
if not st.session_state.logged_in:

    st.title("🛡️ CyberMind AI")

    login_ui()

    st.stop()

# ================= SIDEBAR =================
st.sidebar.title("🛡️ CyberMind AI")

st.sidebar.success(
    f"Logged in as {st.session_state.username}"
)

if st.sidebar.button("Logout"):

    st.session_state.logged_in = False
    st.rerun()

# ================= LOAD DATA =================
@st.cache_data
def cached_logs():
    return load_logs("data/sample_logs.csv")

df = cached_logs()

# Simulate live behavior
df["failed_logins"] = df["failed_logins"].apply(
    lambda x: x + random.randint(0, 2)
)

df["data_transfer"] = df["data_transfer"].apply(
    lambda x: x + random.randint(0, 20)
)

# ================= AI DETECTION =================
df = detect_anomalies(df)

anomalies = df[df["anomaly"] == -1]

critical_alerts = len(
    df[df["severity_score"] >= 7]
)

# ================= SIDEBAR STATUS =================
st.sidebar.markdown("---")

st.sidebar.subheader("🖥️ System Status")

if critical_alerts > 0:
    st.sidebar.error("CRITICAL ALERTS ACTIVE")
else:
    st.sidebar.success("SYSTEM SECURE")

st.sidebar.markdown("---")

# ================= TITLE =================
st.title("🛡️ CyberMind AI")
st.subheader("Enterprise AI Cybersecurity Monitoring Platform")

# ================= METRICS =================
st.subheader("📊 Security Dashboard")

c1, c2, c3 = st.columns(3)

c1.metric("Logs", len(df))
c2.metric("AI Threats", len(anomalies))
c3.metric("Critical Alerts", critical_alerts)

st.markdown("---")

# ================= CHARTS =================
st.subheader("📈 Security Analytics")

fig1 = px.bar(
    df,
    x="ip",
    y="failed_logins",
    color="failed_logins",
    title="Failed Login Attempts"
)

st.plotly_chart(fig1, use_container_width=True)

fig2 = px.line(
    df,
    x="ip",
    y="malware_score",
    markers=True,
    title="Malware Activity"
)

st.plotly_chart(fig2, use_container_width=True)

fig3 = px.scatter(
    df,
    x="ip",
    y="data_transfer",
    size="severity_score",
    color="severity_score",
    title="Suspicious Data Transfer"
)

st.plotly_chart(fig3, use_container_width=True)

st.markdown("---")

# ================= RULE ALERTS =================
st.subheader("🚨 Threat Alerts")

threats = detect_threats(df)

if threats:

    for threat in threats:

        severity = threat["severity"]

        if severity == "Critical":
            st.error(
                f"""
🚨 {threat['type']}

{threat['details']}
"""
            )

        elif severity == "High":
            st.warning(
                f"""
⚠️ {threat['type']}

{threat['details']}
"""
            )

else:
    st.success("✅ No rule-based threats detected")

st.markdown("---")

# ================= AI ALERTS =================
st.subheader("🤖 AI Threat Detection")

if not anomalies.empty:

    for _, row in anomalies.iterrows():

        severity = row["severity_score"]

        if severity >= 7:
            level = "CRITICAL"

        elif severity >= 4:
            level = "MEDIUM"

        else:
            level = "LOW"

        details = f"""
Failed Logins: {row['failed_logins']}
Malware Score: {row['malware_score']}
Data Transfer: {row['data_transfer']}
"""

        if not alert_exists(row["ip"], details):

            save_alert(
                row["ip"],
                level,
                details
            )

        st.error(
            f"""
🚨 Threat Level: {level}

IP Address: {row['ip']}

Severity Score: {severity}/10

{details}
"""
        )

        explanation = generate_security_explanation(
            details
        )

        st.info(explanation)

else:
    st.success("✅ No anomalies detected")

st.markdown("---")

# ================= ALERT HISTORY =================
st.subheader("🗂️ Stored Alert History")

alerts = get_alerts()

if alerts:

    for alert in alerts[-10:]:

        st.warning(
            f"""
IP: {alert[1]}

Severity: {alert[2]}

Details:
{alert[3]}
"""
        )

else:
    st.info("No stored alerts.")

st.markdown("---")

# ================= CHATBOT =================
st.subheader("💬 CyberMind Security Assistant")

question = st.text_input(
    "Ask a cybersecurity question"
)

if question:

    answer = generate_security_explanation(
        question
    )

    st.session_state.chat_history.append({
        "question": question,
        "answer": answer
    })

for chat in reversed(st.session_state.chat_history):

    st.markdown(
        f"**🧑 You:** {chat['question']}"
    )

    st.markdown(
        f"**🤖 CyberMind AI:** {chat['answer']}"
    )

    st.markdown("---")

# ================= FOOTER =================
st.caption(
    "CyberMind AI • Enterprise Cybersecurity Monitoring Platform"
)