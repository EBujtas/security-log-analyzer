import streamlit as st
import pandas as pd

EVENT_FILE = "security_report.csv"
ALERT_FILE = "alerts.csv"

# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="SOC Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Security Operations Center")
st.subheader("Authentication Threat Detection Dashboard")

st.caption(
    "Python-based authentication log analysis "
    "and security detection system"
)

# --------------------------------------------------
# LOAD DATA
# --------------------------------------------------

try:
    events = pd.read_csv(EVENT_FILE)
    alerts = pd.read_csv(ALERT_FILE)

except FileNotFoundError:
    st.error(
        "Security report files were not found. "
        "Run analyzer.py first."
    )
    st.stop()


events["timestamp"] = pd.to_datetime(
    events["timestamp"]
)

if not alerts.empty:
    alerts["timestamp"] = pd.to_datetime(
        alerts["timestamp"]
    )

# --------------------------------------------------
# CALCULATE METRICS
# --------------------------------------------------

total_events = len(events)

successful_logins = len(
    events[
        events["event_type"] == "LOGIN_SUCCESS"
    ]
)

failed_logins = len(
    events[
        events["event_type"] == "LOGIN_FAILED"
    ]
)

total_alerts = len(alerts)

high_alerts = len(
    alerts[
        alerts["severity"] == "HIGH"
    ]
)

medium_alerts = len(
    alerts[
        alerts["severity"] == "MEDIUM"
    ]
)

notice_alerts = len(
    alerts[
        alerts["severity"] == "NOTICE"
    ]
)

# --------------------------------------------------
# EVENT SUMMARY
# --------------------------------------------------

st.divider()

st.header("SOC Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Events Analyzed",
    total_events
)

col2.metric(
    "Successful Logins",
    successful_logins
)

col3.metric(
    "Failed Logins",
    failed_logins
)

col4.metric(
    "Security Alerts",
    total_alerts
)

# --------------------------------------------------
# ALERT SUMMARY
# --------------------------------------------------

st.divider()

st.header("Alert Summary")

col1, col2, col3 = st.columns(3)

col1.metric(
    "🔴 High",
    high_alerts
)

col2.metric(
    "🟠 Medium",
    medium_alerts
)

col3.metric(
    "🔵 Notice",
    notice_alerts
)

# --------------------------------------------------
# SECURITY ALERTS
# --------------------------------------------------

st.divider()

st.header("🚨 Active Security Alerts")

if alerts.empty:

    st.success(
        "No suspicious authentication "
        "patterns detected."
    )

else:

    sorted_alerts = alerts.sort_values(
        "timestamp",
        ascending=False
    )

    for _, alert in sorted_alerts.iterrows():

        message = (
            f"**{alert['alert_type']}**\n\n"
            f"Source IP: `{alert['source_ip']}`  \n"
            f"User: `{alert['username']}`  \n"
            f"Events: `{alert['event_count']}`  \n"
            f"{alert['description']}"
        )

        if alert["severity"] == "HIGH":

            st.error(
                f"🔴 HIGH — {message}"
            )

        elif alert["severity"] == "MEDIUM":

            st.warning(
                f"🟠 MEDIUM — {message}"
            )

        elif alert["severity"] == "NOTICE":

            st.info(
                f"🔵 NOTICE — {message}"
            )

# --------------------------------------------------
# FAILED AUTHENTICATION ACTIVITY
# --------------------------------------------------

st.divider()

st.header("Failed Authentication Activity")

failed_events = events[
    events["event_type"] == "LOGIN_FAILED"
]

if not failed_events.empty:

    failed_by_ip = (
        failed_events
        .groupby("source_ip")
        .size()
        .sort_values(ascending=False)
    )

    st.bar_chart(
        failed_by_ip
    )

else:

    st.success(
        "No failed authentication "
        "attempts detected."
    )

# --------------------------------------------------
# TARGETED ACCOUNTS
# --------------------------------------------------

st.divider()

st.header("Targeted Accounts")

if not failed_events.empty:

    targeted_accounts = (
        failed_events
        .groupby("username")
        .size()
        .sort_values(ascending=False)
    )

    st.bar_chart(
        targeted_accounts
    )

# --------------------------------------------------
# EVENT TIMELINE
# --------------------------------------------------

st.divider()

st.header("Authentication Timeline")

timeline = (
    events
    .set_index("timestamp")
    .resample("1min")
    .size()
)

st.line_chart(
    timeline
)

# --------------------------------------------------
# INVESTIGATION TOOL
# --------------------------------------------------

st.divider()

st.header("🔎 Investigate Source IP")

ip_addresses = sorted(
    events["source_ip"]
    .dropna()
    .unique()
)

selected_ip = st.selectbox(
    "Select a source IP address",
    ip_addresses
)

ip_events = events[
    events["source_ip"] == selected_ip
]

st.write(
    f"**{len(ip_events)} events found "
    f"for {selected_ip}**"
)

st.dataframe(
    ip_events,
    use_container_width=True,
    hide_index=True
)

# Show alerts associated with selected IP

ip_alerts = alerts[
    alerts["source_ip"] == selected_ip
]

if not ip_alerts.empty:

    st.subheader(
        "Associated Security Alerts"
    )

    st.dataframe(
        ip_alerts,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No security alerts associated "
        "with this IP."
    )

# --------------------------------------------------
# RAW EVENT LOG
# --------------------------------------------------

st.divider()

st.header("Raw Authentication Events")

st.dataframe(
    events.sort_values(
        "timestamp",
        ascending=False
    ),
    use_container_width=True,
    hide_index=True
)

# --------------------------------------------------
# DETECTION LOG
# --------------------------------------------------

st.divider()

st.header("Detection Log")

st.dataframe(
    alerts.sort_values(
        "timestamp",
        ascending=False
    ),
    use_container_width=True,
    hide_index=True
)

# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "Security Log Analyzer V5 | "
    "Python Detection Engine + Streamlit"
)