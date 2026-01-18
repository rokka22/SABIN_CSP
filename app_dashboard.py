"""
Streamlit Dashboard - Web-based Network Monitoring & Traffic Analysis Tool
Run with: streamlit run app_dashboard.py
Educational Project
"""

# =========================
# Imports (NO try/except)
# =========================
import streamlit as st
import json
import pandas as pd
import plotly.express as px
from datetime import datetime

#from network_scanner import NetworkScanner
#from packet_analyzer import PacketAnalyzer
#from traffic_analyzer import TrafficAnalyzer
#from anomaly_detector import AnomalyDetector

# =========================
# Page Config
# =========================
st.set_page_config(
    page_title="Network Monitoring Dashboard",
    layout="wide"
)

# =========================
# Helper Functions
# =========================
def load_json(file_path):
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except Exception:
        return []

# =========================
# Pages
# =========================
def home_page():
    st.title("📡 Network Monitoring & Traffic Analysis Tool")
    st.markdown(
        """
        This dashboard provides a visual interface for monitoring network activity,
        analysing traffic patterns, and detecting anomalies.

        **Features**
        - Network scanning
        - Packet & traffic analysis
        - Anomaly detection
        - Visual dashboards

        ⚠️ *Educational use only. Use on networks you own or have permission to test.*
        """
    )

def traffic_analysis_page():
    st.header("📊 Traffic Analysis")

    data = load_json("demo_traffic_analysis.json")

    if not data:
        st.warning("No traffic data found.")
        return

    df = pd.DataFrame(data)

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"])

    st.dataframe(df)

    if "protocol" in df.columns:
        fig = px.pie(df, names="protocol", title="Protocol Distribution")
        st.plotly_chart(fig, use_container_width=True)

def anomaly_detection_page():
    st.header("🚨 Anomaly Detection")

    data = load_json("demo_security_alerts.json")

    if not data:
        st.success("No anomalies detected.")
        return

    df = pd.DataFrame(data)
    st.dataframe(df)

    st.error("⚠️ Potential suspicious activity detected!")

def reports_page():
    st.header("📄 Reports")
    st.info("Reports module placeholder for future expansion.")

# =========================
# Sidebar Navigation
# =========================
st.sidebar.title("Navigation")
page = st.sidebar.radio(
    "Go to",
    ["Home", "Traffic Analysis", "Anomaly Detection", "Reports"]
)

# =========================
# Page Routing
# =========================
if page == "Home":
    home_page()
elif page == "Traffic Analysis":
    traffic_analysis_page()
elif page == "Anomaly Detection":
    anomaly_detection_page()
elif page == "Reports":
    reports_page()

# =========================
# Footer
# =========================
st.markdown("---")
st.markdown(
    """
    <div style="text-align: center;">
        <p>Network Monitoring & Traffic Analysis Tool | Educational Project</p>
        <p style="font-size: 0.8em;">⚠️ Use only on networks you own or have permission to test</p>
    </div>
    """,
    unsafe_allow_html=True
)

