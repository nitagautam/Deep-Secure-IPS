import streamlit as st
import pandas as pd
import time
import os

st.set_page_config(page_title="Deep Secure IPS Dashboard", layout="wide")

# ---------------- Sidebar ----------------
st.sidebar.title("Navigation")
menu = st.sidebar.radio(
    "Go to",
    ["Home", "Attacks Detected", "Suspicious Traffic", "Blocked Traffic"]
)

# -------------Reset logs in sidebar-----------
if st.sidebar.button("🔄 Reset Logs"):
    if os.path.exists("logs/ips_logs.csv"):
        os.remove("logs/ips_logs.csv")
    st.sidebar.success("Logs cleared. Restarting...")
    st.rerun()

# ---------Download logs button----------
if os.path.exists("logs/ips_logs.csv"):
    with open("logs/ips_logs.csv", "rb") as file:
        st.sidebar.download_button(
            label="⬇️ Download Logs",
            data=file,
            file_name="ips_logs.csv",
            mime="text/csv"
        )
else:
    st.sidebar.info("No logs available to download")

# Refresh rate in sidebar
refresh_rate = st.sidebar.slider("Refresh Rate (seconds)", 1, 10, 2)

st.title("Deep Secure Intrusion Prevention System")

# ---------------- Read Logs ----------------
if not os.path.exists("logs/ips_logs.csv"):
    st.warning("No logs yet. Start IPS engine...")
else:
    try:
        df = pd.read_csv("logs/ips_logs.csv")

        if df.empty:
            st.warning("No traffic detected yet...")
        else:
            # ---------------- HOME PAGE ----------------
            if menu == "Home":
                # Metrics ONLY on Home
                total = len(df)
                suspicious = len(df[df["Detection"] == "Suspicious"])
                attacks = len(df[df["Detection"] == "Attack"])
                blocked = len(df[df["Action"] == "BLOCK"])

                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Total Events", total)
                col2.metric("Suspicious Traffic", suspicious)
                col3.metric("Attacks", attacks)
                col4.metric("Blocked IPs", blocked)

                #Live Traffic
                st.subheader("Live Traffic Logs")
                st.dataframe(
                    df.drop(columns=["Confidence", "Action"], errors="ignore").tail(20),
                    use_container_width=True
                )

                # Alerts List
                st.subheader("⚠️ Alerts")
                alerts_df = df[df["Action"] == "ALERT"]
                if alerts_df.empty:
                    st.success("No alerts")
                else:
                    for index, row in alerts_df.tail(10).iterrows():
                        st.markdown(
                            f"**{row['Attack_Type']}** detected from **{row['Source_IP']}**"
                        )

                # Blocked IP List
                st.subheader("🚫 Blocked IPs")
                blocked_df = df[df["Action"] == "BLOCK"]
                if blocked_df.empty:
                    st.success("No blocked IPs")
                else:
                    for index, row in blocked_df.tail(10).iterrows():
                        st.markdown(
                            f"**{row['Source_IP']}** blocked ({row['Attack_Type']})"
                        )

                # Attack Distribution
                st.subheader("📊 Attack Distribution")
                st.bar_chart(df["Attack_Type"].value_counts())

            # ---------------- ATTACKS PAGE ----------------
            elif menu == "Attacks Detected":
                st.subheader("⚠️ All Detected Attacks")
                alerts_df = df[df["Detection"] == "Attack"]
                if alerts_df.empty:
                    st.success("No attacks detected")
                else:
                    st.dataframe(
                        alerts_df.drop(columns=["Confidence", "Action"], errors="ignore"),
                        use_container_width=True
                )
            

            # ---------------- SUSPICIOUS PAGE ----------------
            elif menu == "Suspicious Traffic":
                st.subheader("⚠️ Suspicious Traffic")
                suspicious_df = df[df["Detection"] == "Suspicious"]

                if suspicious_df.empty:
                    st.success("No suspicious traffic detected")

                else:
                    st.dataframe(
                        suspicious_df.drop(columns=["Confidence", "Action"], errors="ignore"),
                        use_container_width=True
                )
             # ---------------- VISUALIZATION ----------------
                st.subheader("📊 Top Suspicious Source IPs")
                ip_counts = suspicious_df["Source_IP"].value_counts().head(10)
                st.bar_chart(ip_counts)
                

            # ---------------- BLOCKED PAGE ----------------
            elif menu == "Blocked Traffic":
                st.subheader("🚫 Blocked Traffic / IPs")
                blocked_df = df[df["Action"] == "BLOCK"]
                if blocked_df.empty:
                    st.success("No blocked traffic")
                else:
                    st.dataframe(
                    blocked_df.drop(columns=["Confidence", "Action"], errors="ignore"),
                    use_container_width=True
                )
            
                

    except Exception as e:
        st.error("Error reading logs")

# Auto refresh
if menu == "Home":
    time.sleep(refresh_rate)
    st.rerun()
