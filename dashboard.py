import streamlit as st
import json
import pandas as pd

DATA_FILE = "final_report.json"

st.set_page_config(page_title="SOC Dashboard", layout="wide")

# ===============================
# STYLE
# ===============================
st.markdown("""
    <style>
    .critical {color: red; font-weight: bold;}
    .high {color: orange; font-weight: bold;}
    .medium {color: blue; font-weight: bold;}
    .low {color: green; font-weight: bold;}
    </style>
""", unsafe_allow_html=True)

st.title("🔐 SOC Dashboard - Cyber Threat Monitoring")

# ===============================
# LOAD DATA
# ===============================
def load_data():
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except:
        return []

data = load_data()

# ===============================
# SUMMARY CARDS
# ===============================
st.subheader("📊 Global Overview")

col1, col2 = st.columns(2)

total_incidents = len(data)
critical_count = sum(1 for i in data if i["severity"] == "CRITICAL")

col1.metric("Total Incidents", total_incidents)
col2.metric("Critical Incidents", critical_count)

# ===============================
# INCIDENT TABLE
# ===============================
st.subheader("📋 Incident List")

if data:
    df = pd.DataFrame([{
        "ID": i["incident_id"],
        "Type": i["attack_type"],
        "Severity": i["severity"],
        "IP": i["summary"]["attacker_ip"]
    } for i in data])

    st.dataframe(df)

# ===============================
# INCIDENT DETAILS
# ===============================
st.subheader("🚨 Incident Details")

for incident in data:
    severity = incident["severity"]

    color_class = severity.lower()

    with st.container():
        st.markdown(f"### Incident {incident['incident_id']}")

        st.markdown(f"**Severity:** <span class='{color_class}'>{severity}</span>", unsafe_allow_html=True)

        summary = incident["summary"]

        col1, col2 = st.columns(2)

        col1.write(f"**Attack Type:** {incident['attack_type']}")
        col1.write(f"**Attacker IP:** {summary.get('attacker_ip')}")

        col2.write(f"**Target:** {summary.get('target_agent')}")
        col2.write(f"**Alerts:** {summary.get('alert_count')}")

        # Threat Context
        st.write("### 🧠 Threat Context")
        st.info(incident.get("threat_context", {}).get("ip_reputation"))

        # AI Analysis
        st.write("### 🤖 AI Analysis")

        ai = incident.get("ai_analysis", {})

        st.success(ai.get("summary"))

        with st.expander("📖 Explanation"):
            st.write(ai.get("explanation"))

        with st.expander("⚠️ Recommendations"):
            for r in ai.get("recommendations", []):
                st.write(f"- {r}")

        st.divider()
