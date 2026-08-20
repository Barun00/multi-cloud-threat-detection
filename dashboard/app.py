import streamlit as st
import pandas as pd
import plotly.express as px


DATA_PATH = "data/processed/correlated_threats.csv"


st.set_page_config(
    page_title="Multi-Cloud Threat Detection",
    page_icon="🛡️",
    layout="wide"
)


@st.cache_data
def load_data():
    df = pd.read_csv(DATA_PATH)
    return df


df = load_data()


# --------------------------------------------------
# HEADER
# --------------------------------------------------

st.title("🛡️ Multi-Cloud Threat Detection")
st.caption(
    "Machine Learning driven anomaly detection "
    "across AWS, Azure and GCP"
)


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

st.sidebar.header("Filters")

cloud_options = ["All"] + sorted(
    df["cloud_provider"].dropna().unique().tolist()
)

selected_cloud = st.sidebar.selectbox(
    "Cloud Provider",
    cloud_options
)

severity_options = ["All"] + sorted(
    df["severity"].dropna().unique().tolist()
)

selected_severity = st.sidebar.selectbox(
    "Severity",
    severity_options
)


filtered_df = df.copy()

if selected_cloud != "All":
    filtered_df = filtered_df[
        filtered_df["cloud_provider"] == selected_cloud
    ]

if selected_severity != "All":
    filtered_df = filtered_df[
        filtered_df["severity"] == selected_severity
    ]


# --------------------------------------------------
# METRICS
# --------------------------------------------------

total_events = len(filtered_df)

anomalies = (
    filtered_df["risk"]
    .eq("Suspicious")
    .sum()
)

critical = (
    filtered_df["severity"]
    .eq("CRITICAL")
    .sum()
)

high = (
    filtered_df["severity"]
    .eq("HIGH")
    .sum()
)


col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Events",
    f"{total_events:,}"
)

col2.metric(
    "Suspicious Events",
    f"{anomalies:,}"
)

col3.metric(
    "Critical Threats",
    f"{critical:,}"
)

col4.metric(
    "High Risk",
    f"{high:,}"
)


st.divider()


# --------------------------------------------------
# CHARTS
# --------------------------------------------------

left, right = st.columns(2)


with left:

    st.subheader("Threat Severity")

    severity_counts = (
        filtered_df["severity"]
        .value_counts()
        .reset_index()
    )

    severity_counts.columns = [
        "severity",
        "count"
    ]

    fig = px.bar(
        severity_counts,
        x="severity",
        y="count",
        title="Threat Severity Distribution"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )


with right:

    st.subheader("Cloud Activity")

    cloud_counts = (
        filtered_df["cloud_provider"]
        .value_counts()
        .reset_index()
    )

    cloud_counts.columns = [
        "cloud_provider",
        "count"
    ]

    fig = px.pie(
        cloud_counts,
        names="cloud_provider",
        values="count",
        title="Events by Cloud Provider"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )


# --------------------------------------------------
# THREAT TYPES
# --------------------------------------------------

st.subheader("Threat Types")

threat_counts = (
    filtered_df["predicted_threat"]
    .value_counts()
    .reset_index()
)

threat_counts.columns = [
    "threat_type",
    "count"
]

fig = px.bar(
    threat_counts,
    x="threat_type",
    y="count",
    title="Detected Threat Types"
)

st.plotly_chart(
    fig,
    use_container_width=True
)


# --------------------------------------------------
# CROSS-CLOUD
# --------------------------------------------------

st.subheader("🌐 Cross-Cloud Activity")

cross_cloud = filtered_df[
    filtered_df["cross_cloud_activity"] == 1
]

st.metric(
    "Multi-Cloud Events",
    f"{len(cross_cloud):,}"
)


# --------------------------------------------------
# TOP THREATS
# --------------------------------------------------

st.subheader("🚨 Highest Risk Events")

top_threats = (
    filtered_df
    .sort_values(
        "risk_score",
        ascending=False
    )
    [
        [
            "user_id",
            "cloud_provider",
            "action",
            "predicted_threat",
            "threat_confidence",
            "risk_score",
            "severity",
            "cross_cloud_activity"
        ]
    ]
    .head(20)
)

st.dataframe(
    top_threats,
    use_container_width=True,
    hide_index=True
)


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "Multi-Cloud Threat Detection | "
    "Isolation Forest + Random Forest + "
    "Cross-Cloud Correlation"
)