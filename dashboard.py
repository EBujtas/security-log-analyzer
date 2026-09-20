import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime

DATABASE_FILE = "security.db"

st.set_page_config(
    page_title="Security Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)


# ---------------------------------------------------------
# DATABASE FUNCTIONS
# ---------------------------------------------------------

def load_events():
    connection = sqlite3.connect(DATABASE_FILE)

    events = pd.read_sql_query(
        """
        SELECT
            id,
            timestamp,
            source_ip,
            username,
            event_type
        FROM events
        ORDER BY timestamp DESC
        """,
        connection
    )

    connection.close()

    events["timestamp"] = pd.to_datetime(events["timestamp"])

    return events


def load_alerts():
    connection = sqlite3.connect(DATABASE_FILE)

    alerts = pd.read_sql_query(
        """
        SELECT
            id,
            timestamp,
            severity,
            alert_type,
            source_ip,
            username,
            event_count,
            description
        FROM alerts
        ORDER BY timestamp DESC
        """,
        connection
    )

    connection.close()

    alerts["timestamp"] = pd.to_datetime(alerts["timestamp"])

    return alerts


# ---------------------------------------------------------
# LOAD DATA
# ---------------------------------------------------------

events = load_events()
alerts = load_alerts()


# ---------------------------------------------------------
# HEADER
# ---------------------------------------------------------

st.title("🛡️ Security Log Analyzer")
st.caption("SOC Authentication Monitoring Dashboard — V6")


# ---------------------------------------------------------
# DATE FILTERS
# ---------------------------------------------------------

st.subheader("Log Date Filter")

if not events.empty:

    events["year"] = events["timestamp"].dt.year
    events["month"] = events["timestamp"].dt.month
    events["month_name"] = events["timestamp"].dt.month_name()
    events["day"] = events["timestamp"].dt.day

    alerts["year"] = alerts["timestamp"].dt.year
    alerts["month"] = alerts["timestamp"].dt.month
    alerts["day"] = alerts["timestamp"].dt.day

    year_options = ["All"] + sorted(
        events["year"].unique().tolist(),
        reverse=True
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        selected_year = st.selectbox(
            "Year",
            year_options
        )

    working_events = events.copy()
    working_alerts = alerts.copy()

    if selected_year != "All":

        working_events = working_events[
            working_events["year"] == selected_year
        ]

        working_alerts = working_alerts[
            working_alerts["year"] == selected_year
        ]

    month_lookup = (
        working_events[
            ["month", "month_name"]
        ]
        .drop_duplicates()
        .sort_values("month")
    )

    month_options = ["All"] + month_lookup[
        "month_name"
    ].tolist()

    with col2:
        selected_month = st.selectbox(
            "Month",
            month_options
        )

    if selected_month != "All":

        month_number = datetime.strptime(
            selected_month,
            "%B"
        ).month

        working_events = working_events[
            working_events["month"] == month_number
        ]

        working_alerts = working_alerts[
            working_alerts["month"] == month_number
        ]

    day_options = ["All"] + sorted(
        working_events["day"].unique().tolist()
    )

    with col3:
        selected_day = st.selectbox(
            "Day",
            day_options
        )

    if selected_day != "All":

        working_events = working_events[
            working_events["day"] == selected_day
        ]

        working_alerts = working_alerts[
            working_alerts["day"] == selected_day
        ]

else:

    working_events = events.copy()
    working_alerts = alerts.copy()

    st.warning("No events are currently stored in the database.")


# ---------------------------------------------------------
# SOC OVERVIEW
# ---------------------------------------------------------

st.divider()

st.subheader("SOC Overview")

successful_logins = len(
    working_events[
        working_events["event_type"] == "LOGIN_SUCCESS"
    ]
)

failed_logins = len(
    working_events[
        working_events["event_type"] == "LOGIN_FAILED"
    ]
)

total_alerts = len(working_alerts)

metric1, metric2, metric3, metric4 = st.columns(4)

metric1.metric(
    "Events Analyzed",
    len(working_events)
)

metric2.metric(
    "Successful Logins",
    successful_logins
)

metric3.metric(
    "Failed Logins",
    failed_logins
)

metric4.metric(
    "Security Alerts",
    total_alerts
)


# ---------------------------------------------------------
# ALERT SUMMARY
# ---------------------------------------------------------

st.subheader("Alert Summary")

high_alerts = len(
    working_alerts[
        working_alerts["severity"] == "HIGH"
    ]
)

medium_alerts = len(
    working_alerts[
        working_alerts["severity"] == "MEDIUM"
    ]
)

notice_alerts = len(
    working_alerts[
        working_alerts["severity"] == "NOTICE"
    ]
)

alert1, alert2, alert3 = st.columns(3)

alert1.metric("HIGH", high_alerts)
alert2.metric("MEDIUM", medium_alerts)
alert3.metric("NOTICE", notice_alerts)


# ---------------------------------------------------------
# ACTIVE SECURITY ALERTS
# ---------------------------------------------------------

st.subheader("Security Alerts")

if working_alerts.empty:

    st.success(
        "No security alerts detected for the selected period."
    )

else:

    for _, alert in working_alerts.iterrows():

        message = (
            f"{alert['alert_type']} | "
            f"{alert['source_ip']} | "
            f"{alert['username']} | "
            f"{alert['description']}"
        )

        if alert["severity"] == "HIGH":
            st.error(message)

        elif alert["severity"] == "MEDIUM":
            st.warning(message)

        else:
            st.info(message)


# ---------------------------------------------------------
# FAILED AUTHENTICATION ACTIVITY
# ---------------------------------------------------------

st.subheader("Failed Authentication Activity")

failed_events = working_events[
    working_events["event_type"] == "LOGIN_FAILED"
]

if not failed_events.empty:

    failed_by_ip = (
        failed_events["source_ip"]
        .value_counts()
        .rename_axis("Source IP")
        .to_frame("Failed Attempts")
    )

    st.bar_chart(failed_by_ip)

else:

    st.info(
        "No failed authentication events for this period."
    )


# ---------------------------------------------------------
# TARGETED ACCOUNTS
# ---------------------------------------------------------

st.subheader("Targeted Accounts")

if not failed_events.empty:

    targeted_accounts = (
        failed_events["username"]
        .value_counts()
        .rename_axis("Username")
        .to_frame("Failed Attempts")
    )

    st.bar_chart(targeted_accounts)

else:

    st.info(
        "No targeted accounts for this period."
    )


# ---------------------------------------------------------
# AUTHENTICATION TIMELINE
# ---------------------------------------------------------

st.subheader("Authentication Timeline")

if not working_events.empty:

    timeline = (
        working_events
        .set_index("timestamp")
        .resample("1min")
        .size()
        .to_frame("Events")
    )

    st.line_chart(timeline)


# ---------------------------------------------------------
# SOURCE IP INVESTIGATION
# ---------------------------------------------------------

st.subheader("Investigate Source IP")

if not working_events.empty:

    ip_options = sorted(
        working_events["source_ip"]
        .dropna()
        .unique()
        .tolist()
    )

    selected_ip = st.selectbox(
        "Select Source IP",
        ip_options
    )

    ip_events = working_events[
        working_events["source_ip"] == selected_ip
    ]

    st.write("Events")

    st.dataframe(
        ip_events[
            [
                "timestamp",
                "username",
                "event_type"
            ]
        ],
        use_container_width=True,
        hide_index=True
    )

    ip_alerts = working_alerts[
        working_alerts["source_ip"] == selected_ip
    ]

    st.write("Associated Alerts")

    if ip_alerts.empty:

        st.info(
            "No alerts associated with this source IP."
        )

    else:

        st.dataframe(
            ip_alerts[
                [
                    "timestamp",
                    "severity",
                    "alert_type",
                    "username",
                    "event_count",
                    "description"
                ]
            ],
            use_container_width=True,
            hide_index=True
        )


# ---------------------------------------------------------
# RAW EVENTS
# ---------------------------------------------------------

st.subheader("Authentication Events")

st.dataframe(
    working_events[
        [
            "timestamp",
            "source_ip",
            "username",
            "event_type"
        ]
    ],
    use_container_width=True,
    hide_index=True
)


# ---------------------------------------------------------
# DETECTION LOG
# ---------------------------------------------------------

st.subheader("Detection Log")

st.dataframe(
    working_alerts[
        [
            "timestamp",
            "severity",
            "alert_type",
            "source_ip",
            "username",
            "event_count",
            "description"
        ]
    ],
    use_container_width=True,
    hide_index=True
)