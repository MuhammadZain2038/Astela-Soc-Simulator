import os
import json
import streamlit as st
import pandas as pd
import altair as alt
from opensearchpy import OpenSearch
import redis
from dotenv import load_dotenv
from urllib.parse import urlparse

load_dotenv()

# Same variables the launcher and pipeline read, so changing a port in
# .env applies to the whole stack and not just one script.
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://localhost:9200")
REDIS_PORT = int(os.getenv("REDIS_DOCKER_PORT", "6379"))

def clean_malware_name(name):
    if not name:
        return None

    name = str(name).strip().lower()

    bad_values = [
        "unknown", "unknown malware", "unknown payload",
        "unknown file download", "", "none"
    ]
    if name in bad_values:
        return None

    if "tier 1 flag" in name or "brute" in name:
        return None

    name = name.replace("trojan.", "").replace("msil/", "")
    name = name.replace("_", "").replace("-", "").strip()

    return name.capitalize()

# --- Page Configuration ---
st.set_page_config(page_title="ASTELA Command Center", page_icon="🛡️", layout="wide")

# --- Custom CSS: Slate Cyber minimal SOC theme ---
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Manrope:wght@400;500;600;700;800&display=swap');

    html, body, [class*="css"], .stMarkdown, .stText, p, span, div {
        font-family: 'Manrope', 'Segoe UI', sans-serif;
    }
    [data-testid="stMetricValue"], .mono-chip, code {
        font-family: 'JetBrains Mono', 'Courier New', monospace !important;
    }

    .stApp {
        background-color: #0b1220;
        background-image:
            linear-gradient(rgba(34,211,238,0.04) 1px, transparent 1px),
            linear-gradient(90deg, rgba(34,211,238,0.04) 1px, transparent 1px);
        background-size: 44px 44px;
        color: #cbd5e1;
    }

    /* Header */
    .astela-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        border-bottom: 1px solid #1e293b;
        padding-bottom: 14px;
        margin-bottom: 8px;
    }
    .astela-title {
        font-size: 26px;
        font-weight: 800;
        color: #e2e8f0;
        letter-spacing: 0.3px;
        margin: 0;
    }
    .astela-sub {
        color: #64748b;
        font-size: 13px;
        margin-top: 3px;
        font-weight: 500;
    }
    .live-dot {
        display: inline-block;
        width: 9px; height: 9px;
        border-radius: 50%;
        background: #22d3ee;
        box-shadow: 0 0 8px #22d3ee;
        margin-right: 6px;
        animation: pulse 1.6s infinite;
    }
    @keyframes pulse {
        0% { opacity: 1; } 50% { opacity: 0.35; } 100% { opacity: 1; }
    }

    /* Metric cards */
    .stMetric {
        background-color: #111a2e;
        padding: 14px 16px;
        border-radius: 10px;
        border: 1px solid #1e293b;
        border-left: 3px solid #22d3ee;
        box-shadow: 0 4px 14px rgba(0,0,0,0.35);
        transition: transform .15s ease, box-shadow .15s ease;
    }
    .stMetric:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 22px rgba(34,211,238,0.18);
    }
    /* Each KPI card in the top metric row gets its own accent color. */
    div[data-testid="stHorizontalBlock"] div[data-testid="column"]:nth-of-type(1) .stMetric { border-left-color: #22d3ee; }
    div[data-testid="stHorizontalBlock"] div[data-testid="column"]:nth-of-type(2) .stMetric { border-left-color: #f43f5e; }
    div[data-testid="stHorizontalBlock"] div[data-testid="column"]:nth-of-type(3) .stMetric { border-left-color: #60a5fa; }
    div[data-testid="stHorizontalBlock"] div[data-testid="column"]:nth-of-type(4) .stMetric { border-left-color: #8b5cf6; }
    [data-testid="stMetricLabel"] { color: #64748b; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600; }
    [data-testid="stMetricValue"] { color: #f1f5f9; font-weight: 700; }

    /* Overall threat-level gauge */
    .threat-gauge-wrap { margin: 6px 0 22px 0; }
    .threat-gauge-label {
        display: flex; justify-content: space-between; align-items: baseline;
        font-size: 12px; color: #8fa3bf; text-transform: uppercase;
        letter-spacing: 1.5px; font-weight: 700; margin-bottom: 8px;
    }
    .threat-gauge-label span:last-child { font-size: 14px; color: #f1f5f9; letter-spacing: 0.5px; }
    .threat-gauge-track {
        position: relative;
        height: 14px;
        border-radius: 8px;
        overflow: visible;
        background-image: linear-gradient(90deg, #22d3ee 0%, #60a5fa 25%, #34d399 50%, #f59e0b 75%, #f43f5e 100%);
        border: 1px solid #1e293b;
        box-shadow: inset 0 0 8px rgba(0,0,0,0.4);
    }
    .threat-gauge-marker {
        position: absolute; top: -5px;
        width: 3px; height: 24px; border-radius: 2px;
        background: #f8fafc;
        box-shadow: 0 0 8px #f8fafc, 0 0 2px #f8fafc;
        transform: translateX(-50%);
    }
    .threat-gauge-scale {
        display: flex; justify-content: space-between;
        font-size: 10px; color: #475569; margin-top: 6px;
    }
    .severity-legend {
        display: flex; align-items: center; gap: 6px;
        margin: -4px 0 16px 0; flex-wrap: wrap;
    }
    .severity-legend span.lbl {
        font-size: 11px; color: #64748b; letter-spacing: 1px; text-transform: uppercase; margin-right: 2px;
    }
    .severity-legend span.swatch {
        width: 15px; height: 8px; border-radius: 2px; display: inline-block;
    }

    /* Section labels */
    .section-label {
        color: #22d3ee;
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 2px;
        text-transform: uppercase;
        border-left: 3px solid #22d3ee;
        padding-left: 8px;
        margin: 20px 0 10px 0;
    }

    /* Severity badges */
    .badge {
        display: inline-block;
        padding: 2px 9px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.5px;
        margin-right: 6px;
    }
    .badge-critical { background: #2a0f16; color: #f43f5e; border: 1px solid #f43f5e; }
    .badge-warn { background: #2a1f0a; color: #f59e0b; border: 1px solid #f59e0b; }
    .badge-t1 { background: #0a2233; color: #22d3ee; border: 1px solid #22d3ee; }
    .badge-t2 { background: #1b1030; color: #8b5cf6; border: 1px solid #8b5cf6; }
    .badge-unk { background: #151d2e; color: #64748b; border: 1px solid #334155; }
    .mono-chip {
        background: #111a2e;
        border: 1px solid #1e293b;
        border-radius: 5px;
        padding: 4px 10px;
        margin: 3px 4px 3px 0;
        display: inline-block;
        font-size: 12px;
        color: #22d3ee;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #0d1526;
        border-right: 1px solid #1e293b;
    }

    /* Expander (triage feed rows) */
    .streamlit-expanderHeader, [data-testid="stExpander"] {
        background-color: #111a2e !important;
        border: 1px solid #1e293b !important;
        border-radius: 8px !important;
        font-size: 13px;
        transition: border-color .15s ease;
    }
    [data-testid="stExpander"]:hover {
        border-color: #22d3ee !important;
    }

    /* Dataframe */
    [data-testid="stDataFrame"] {
        border: 1px solid #1e293b;
        border-radius: 8px;
        box-shadow: 0 4px 14px rgba(0,0,0,0.3);
    }

    hr, .stDivider { border-color: #1e293b !important; }
    </style>
""", unsafe_allow_html=True)

# --- Database Connections ---
@st.cache_resource
def get_os_client():
    parsed = urlparse(OPENSEARCH_URL)
    # No credentials are sent: the compose file runs OpenSearch with the
    # security plugin disabled, so there is nothing to authenticate against.
    return OpenSearch(
        hosts=[{'host': parsed.hostname or 'localhost', 'port': parsed.port or 9200}],
        use_ssl=(parsed.scheme == "https"),
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False
    )

@st.cache_resource
def get_redis_client():
    try:
        r = redis.Redis(host='localhost', port=REDIS_PORT, db=0, decode_responses=True)
        r.ping()
        return r
    except Exception:
        return None

os_client = get_os_client()
r = get_redis_client()

# Repeat-offender records written by astela_pipeline.py live in their own
# Redis database. These values must match the pipeline's settings.
REPEAT_REDIS_DB = int(os.getenv("REPEAT_REDIS_DB", 1))
REPEAT_KEY_PREFIX = "offense"

# How often (seconds) the dashboard checks OpenSearch for new alerts. The
# page only reruns when something actually changed, so this is cheap.
REFRESH_SECONDS = int(os.getenv("DASHBOARD_REFRESH_SECONDS", 5))

def get_log_count():
    """Cheap document count for the logs index, used to detect new alerts
    without re-downloading them. Returns None if OpenSearch is unreachable."""
    try:
        return os_client.count(index="logs")["count"]
    except Exception:
        return None

def fetch_repeat_offenders(min_count=2):
    """IP + threat pairs that have triggered min_count+ times inside the
    pipeline's tracking window, read from the same Redis database the
    pipeline writes to. Returns None if Redis can't be reached."""
    try:
        tracker = redis.Redis(host='localhost', port=REDIS_PORT, db=REPEAT_REDIS_DB, decode_responses=True)
        offenders = []
        for key in tracker.scan_iter(match=f"{REPEAT_KEY_PREFIX}:*"):
            count, summary_json = tracker.hmget(key, "count", "summary")
            try:
                count = int(count or 0)
            except ValueError:
                continue
            if count < min_count:
                continue

            # Key layout: offense:<ip>:<threat>. maxsplit=2 keeps threat
            # names that contain a colon (e.g. "Rule Match: x") intact.
            parts = key.split(":", 2)
            ip = parts[1] if len(parts) > 1 else "-"
            threat = parts[2] if len(parts) > 2 else "-"

            # The key is lowercased; the cached scoring keeps the proper
            # capitalization of the family / MITRE rule name.
            if summary_json:
                try:
                    threat = json.loads(summary_json).get("malware_family") or threat
                except ValueError:
                    pass

            offenders.append({"ip": ip, "threat": threat, "count": count})

        offenders.sort(key=lambda o: (-o["count"], o["ip"]))
        return offenders
    except Exception:
        return None

def format_time_safe(ts):
    if pd.isna(ts):
        return "Unknown Time"
    try:
        return ts.strftime('%H:%M:%S')
    except:
        return "Invalid Time"

# --- Data Fetching ---
def _first_present(*values):
    """Return the first truthy value from a list of candidates, else None."""
    for v in values:
        if v:
            return v
    return None

def fetch_logs():
    query = {
        "size": 100,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"match_all": {}}
    }
    try:
        res = os_client.search(index="logs", body=query)
        hits = res['hits']['hits']

        data = []
        for hit in hits:
            source = hit['_source']
            ai = source.get('ai_summary', {})
            detection = source.get('detection', {})
            network = source.get('network', {}) if isinstance(source.get('network'), dict) else {}

            # Source IP isn't in a fixed location across alert docs, so check
            # every field name/path it could reasonably live under. Falls
            # back to "-" if none match, in which case IP-based features
            # (grid column, quick filter, search) simply show nothing.
            source_ip = _first_present(
                source.get('src_ip'),
                source.get('source_ip'),
                source.get('ip'),
                detection.get('src_ip'),
                detection.get('source_ip'),
                ai.get('src_ip'),
                network.get('src_ip'),
                network.get('source_ip'),
            ) or "-"

            # Raw log lines/events behind a Tier-2 behavioral alert. Not
            # currently populated by the pipeline under any of these keys,
            # so this stays an empty list until an alert doc carries it.
            evidence = _first_present(
                detection.get('evidence'),
                detection.get('matched_events'),
                detection.get('related_logs'),
                detection.get('raw_logs'),
                source.get('raw_logs'),
            ) or []

            data.append({
                "Time": source.get('timestamp', None),
                "Score": ai.get('threat_score', 0),
                "Target": ai.get('name', 'Unknown'),
                "Family": ai.get('malware_family', 'Unknown'),
                "Hash": ai.get('file_hash', '-'),
                "Recommendation": ai.get('recommendation', 'N/A'),
                "Tier": detection.get("tier", 0),
                "DetectionType": detection.get("type", "unknown"),
                "Reason": detection.get("reason", "N/A"),
                "SourceIP": source_ip,
                "Evidence": evidence
            })

        df = pd.DataFrame(data)
        if not df.empty:
            df['Time'] = pd.to_datetime(df['Time'], errors='coerce')
        return df

    except Exception as e:
        st.error(f"Failed to connect to OpenSearch: {e}")
        return pd.DataFrame()

st.session_state.seen_log_count = get_log_count()
df = fetch_logs()

# --- FILTER STATE ---
if "search" not in st.session_state:
    st.session_state.search = ""
if "tier_filter" not in st.session_state:
    st.session_state.tier_filter = []
if "family_filter" not in st.session_state:
    st.session_state.family_filter = []
if "min_score" not in st.session_state:
    st.session_state.min_score = 0

def set_search(value):
    st.session_state.search = value

def severity_badge(score, tier):
    if score >= 8:
        sev = '<span class="badge badge-critical">CRITICAL</span>'
    elif score >= 5:
        sev = '<span class="badge badge-warn">ELEVATED</span>'
    else:
        sev = '<span class="badge badge-unk">LOW</span>'
    if tier == 1:
        tier_b = '<span class="badge badge-t1">T1 · SIGNATURE</span>'
    elif tier == 2:
        tier_b = '<span class="badge badge-t2">T2 · BEHAVIORAL</span>'
    else:
        tier_b = '<span class="badge badge-unk">UNCLASSIFIED</span>'
    return sev + tier_b

# --- Header ---
st.markdown("""
    <div class="astela-header">
        <div>
            <p class="astela-title">🛡️ ASTELA TACTICAL DASHBOARD</p>
            <p class="astela-sub"><span class="live-dot"></span>LIVE TELEMETRY &nbsp;·&nbsp; AI BEHAVIORAL ANALYSIS &nbsp;·&nbsp; THREAT TRIAGE CONSOLE</p>
        </div>
    </div>
""", unsafe_allow_html=True)

# Result message from the last "Clear All Data" action, shown once.
clear_notice = st.session_state.pop("clear_notice", None)
if clear_notice:
    ok, message = clear_notice
    if ok:
        st.success(message)
    else:
        st.warning(message)

if not df.empty:

    # --- METRICS ---
    st.markdown('<p class="section-label">Live Threat Metrics</p>', unsafe_allow_html=True)

    st.markdown("""
        <div class="severity-legend">
            <span class="lbl">Low → Critical</span>
            <span class="swatch" style="background:#22d3ee;"></span>
            <span class="swatch" style="background:#60a5fa;"></span>
            <span class="swatch" style="background:#34d399;"></span>
            <span class="swatch" style="background:#f59e0b;"></span>
            <span class="swatch" style="background:#f43f5e;"></span>
        </div>
    """, unsafe_allow_html=True)

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("🛰️ Total Events", len(df))
    col2.metric("🚨 Critical Alerts", len(df[df['Score'] >= 8]))
    col3.metric("🧬 Tier 1 Hits", len(df[df['Tier'] == 1]), help="Signature-based detection (YARA, ClamAV, known hashes). Fast and precise.")
    col4.metric("🧠 Tier 2 Hits", len(df[df['Tier'] == 2]), help="Behavioral detection (CSP patterns, anomaly sequences). Detects unknown attacks.")

    # Overall threat-level gauge — visual summary of the same Score column
    # used everywhere else (df['Score']); doesn't touch or rename anything.
    avg_score = df['Score'].mean() if not df['Score'].dropna().empty else 0
    gauge_pct = min(max((avg_score / 10) * 100, 0), 100)
    st.markdown(f"""
        <div class="threat-gauge-wrap">
            <div class="threat-gauge-label"><span>⚡ Overall Threat Level</span><span>{avg_score:.1f} / 10</span></div>
            <div class="threat-gauge-track">
                <div class="threat-gauge-marker" style="left:{gauge_pct:.1f}%;"></div>
            </div>
            <div class="threat-gauge-scale"><span>0</span><span>2.5</span><span>5</span><span>7.5</span><span>10</span></div>
        </div>
    """, unsafe_allow_html=True)

    # --- CHART AREA ---
    # Three row-pairs so each left/right pair starts at the same vertical
    # position:
    #   Threat Severity Timeline  <->  Detection Breakdown
    #   Top Targets               <->  Malware Families
    #   Threat Intelligence Snapshot <-> IP Activity Map
    row1_a, row1_b = st.columns([2, 1])

    with row1_a:
        st.markdown('<p class="section-label">Threat Severity Timeline</p>', unsafe_allow_html=True)
        chart_df = df.dropna(subset=['Time']).sort_values('Time')
        if not chart_df.empty:
            severity_area = alt.Chart(chart_df).mark_area(
                line={'color': '#22d3ee', 'strokeWidth': 2},
                color=alt.Gradient(
                    gradient='linear',
                    stops=[
                        alt.GradientStop(color='#0b1220', offset=0),
                        alt.GradientStop(color='#22d3ee', offset=1)
                    ],
                    x1=1, x2=1, y1=1, y2=0
                ),
                interpolate='monotone'
            ).encode(
                x=alt.X('Time:T', title=None, axis=alt.Axis(labelColor='#64748b', gridColor='#1e293b', domainColor='#1e293b')),
                y=alt.Y('Score:Q', title='Threat Score', axis=alt.Axis(labelColor='#64748b', gridColor='#1e293b', domainColor='#1e293b')),
                tooltip=[alt.Tooltip('Time:T', title='Time'), alt.Tooltip('Score:Q', title='Score')]
            ).properties(height=230, background='transparent').configure_view(strokeWidth=0)

            st.altair_chart(severity_area, use_container_width=True)

    with row1_b:
        st.markdown('<p class="section-label">Detection Breakdown</p>', unsafe_allow_html=True)
        breakdown_df = pd.DataFrame({
            "Layer": ["Tier 1 · Signature", "Tier 2 · Behavioral"],
            "Count": [len(df[df['Tier'] == 1]), len(df[df['Tier'] == 2])]
        })
        breakdown_chart = alt.Chart(breakdown_df).mark_bar(cornerRadiusEnd=6, size=28).encode(
            x=alt.X('Count:Q', title=None, axis=alt.Axis(labelColor='#64748b', gridColor='#1e293b', domainColor='#1e293b')),
            y=alt.Y('Layer:N', title=None, axis=alt.Axis(labelColor='#cbd5e1')),
            color=alt.Color(
                'Layer:N',
                scale=alt.Scale(domain=["Tier 1 · Signature", "Tier 2 · Behavioral"], range=['#22d3ee', '#8b5cf6']),
                legend=None
            ),
            tooltip=['Layer', 'Count']
        ).properties(height=150, background='transparent').configure_view(strokeWidth=0)
        st.altair_chart(breakdown_chart, use_container_width=True)
        st.caption("🧬 Signature-based (YARA / ClamAV)  ·  🧠 Behavioral (CSP / attack sequences)")

    row2_a, row2_b = st.columns([2, 1])

    with row2_a:
        st.markdown('<p class="section-label">Top Targets</p>', unsafe_allow_html=True)
        top_targets = df['Target'].value_counts().head(10)
        top_targets_chart_df = top_targets.reset_index()
        top_targets_chart_df.columns = ['Target', 'Count']
        targets_bar = alt.Chart(top_targets_chart_df).mark_bar(cornerRadiusEnd=4).encode(
            x=alt.X('Count:Q', title=None, axis=alt.Axis(labelColor='#64748b', gridColor='#1e293b', domainColor='#1e293b')),
            y=alt.Y('Target:N', sort='-x', title=None, axis=alt.Axis(labelColor='#cbd5e1')),
            color=alt.Color('Count:Q', scale=alt.Scale(scheme='teals'), legend=None),
            tooltip=[alt.Tooltip('Target:N', title='Target'), alt.Tooltip('Count:Q', title='Events')]
        ).properties(height=230, background='transparent').configure_view(strokeWidth=0)
        st.altair_chart(targets_bar, use_container_width=True)

    with row2_b:
        st.markdown('<p class="section-label">Malware Families</p>', unsafe_allow_html=True)
        clean_families = set()
        for fam in df['Family'].dropna():
            cleaned = clean_malware_name(fam)
            # MITRE technique tags (e.g. "Mitre t1003 t1003credentialdumping")
            # land in the Family field for Tier-2/behavioral alerts. Those
            # aren't malware family names, so exclude them from this chip
            # list only — the underlying Family value on each row/table
            # entry is untouched.
            if cleaned and not cleaned.lower().startswith("mitre"):
                clean_families.add(cleaned)

        chips_html = "".join(f'<span class="mono-chip">🦠 {f}</span>' for f in sorted(clean_families))
        st.markdown(chips_html if chips_html else "<span style='color:#64748b'>None observed</span>", unsafe_allow_html=True)

    row3_a, row3_b = st.columns([2, 1])

    with row3_a:
        st.markdown('<p class="section-label">Threat Intelligence Snapshot</p>', unsafe_allow_html=True)
        latest = df.sort_values("Time", ascending=False).iloc[0]

        colx, coly = st.columns([1, 2])
        with colx:
            st.metric("Threat Score", f"{latest['Score']}/10")
            st.markdown(severity_badge(latest['Score'], latest['Tier']), unsafe_allow_html=True)
        with coly:
            st.markdown(f"**Name:** {latest['Target']}")
            st.markdown(f"**Family:** {latest['Family']}")
            st.markdown(f"**Trigger:** {latest['Reason']}")
            st.markdown("**🧠 AI Recommendation**")
            st.info(latest['Recommendation'])

    with row3_b:
        # IP activity map: this is a timeline, not a geographic map. Sample
        # source IPs are private/internal (192.168.x.x, 10.0.0.x) with no
        # lat/long in the pipeline, so a real geo map would be empty.
        # Plots one dot per event along a time axis for a given IP,
        # color-coded by severity and sized by threat score, with full
        # detail on hover. Reads from the full `df`, not `filtered_df`, so
        # it never affects the Triage Feed table or any other filter.
        st.markdown('<p class="section-label">🌐 IP Activity Map</p>', unsafe_allow_html=True)

        ip_options = sorted([ip for ip in df['SourceIP'].dropna().unique() if ip and ip != '-'])

        if not ip_options:
            st.caption("No source IP field found in the alert documents yet. Once the pipeline includes src_ip on each alert, IP timelines will appear here automatically.")
        else:
            # Auto-selects whichever IP is currently active via the sidebar's
            # Quick Filters -> IP Activity buttons (they populate the search
            # box). A manual picker is also here so this works without
            # needing to click a quick filter first.
            current_search = st.session_state.get("search", "").strip()
            matched_ip = next((ip for ip in ip_options if ip.lower() == current_search.lower()), None)

            selected_ip = st.selectbox(
                "Select IP to inspect",
                options=ip_options,
                index=ip_options.index(matched_ip) if matched_ip else 0,
                key="ip_map_select"
            )

            ip_events = df[df['SourceIP'] == selected_ip].dropna(subset=['Time']).sort_values('Time').copy()

            if ip_events.empty:
                st.caption(f"No timestamped events for {selected_ip}.")
            else:
                ip_events['SeverityLabel'] = ip_events['Score'].apply(
                    lambda s: 'Critical' if s >= 8 else ('Elevated' if s >= 5 else 'Low')
                )

                # Faint baseline rule gives it a timeline feel; a soft glow
                # sits beneath the main dot, dots sit on top sized by threat
                # score so the worst events read larger, colored by
                # severity, full detail on hover.
                baseline = alt.Chart(ip_events).mark_rule(
                    color='#1e293b', strokeWidth=2
                ).encode(y=alt.Y('SourceIP:N', title=None, axis=alt.Axis(labelColor='#64748b')))

                glow = alt.Chart(ip_events).mark_circle(
                    opacity=0.18
                ).encode(
                    x=alt.X('Time:T', title='Time'),
                    y=alt.Y('SourceIP:N', title=None),
                    size=alt.Size('Score:Q', scale=alt.Scale(range=[400, 1400]), legend=None),
                    color=alt.Color(
                        'SeverityLabel:N',
                        scale=alt.Scale(domain=['Critical', 'Elevated', 'Low'], range=['#f43f5e', '#f59e0b', '#22d3ee']),
                        legend=None
                    )
                )

                dots = alt.Chart(ip_events).mark_circle(
                    opacity=0.95, stroke='#0b1220', strokeWidth=1.5
                ).encode(
                    x=alt.X('Time:T', title='Time', axis=alt.Axis(labelColor='#64748b', titleColor='#64748b', gridColor='#1e293b')),
                    y=alt.Y('SourceIP:N', title=None, axis=alt.Axis(labelColor='#64748b')),
                    size=alt.Size('Score:Q', scale=alt.Scale(range=[150, 600]), legend=None),
                    color=alt.Color(
                        'SeverityLabel:N',
                        scale=alt.Scale(domain=['Critical', 'Elevated', 'Low'], range=['#f43f5e', '#f59e0b', '#22d3ee']),
                        legend=alt.Legend(title=None, labelColor='#cbd5e1', orient='top', direction='horizontal')
                    ),
                    tooltip=[
                        alt.Tooltip('Time:T', title='Time'),
                        alt.Tooltip('Target:N', title='Target'),
                        alt.Tooltip('Family:N', title='Family'),
                        alt.Tooltip('Score:Q', title='Score'),
                        alt.Tooltip('Tier:N', title='Tier'),
                        alt.Tooltip('DetectionType:N', title='Type'),
                        alt.Tooltip('Reason:N', title='Reason'),
                    ]
                )

                ip_chart = (baseline + glow + dots).properties(
                    height=230, background='transparent'
                ).configure_view(strokeWidth=0).configure_axis(domainColor='#1e293b')

                st.altair_chart(ip_chart, use_container_width=True)
                st.caption(f"{len(ip_events)} event(s) for {selected_ip} · hover a dot for full detail")

    st.divider()

    # --- SIDEBAR: UNIFIED FILTER PANEL ---
    st.sidebar.markdown('<p class="section-label">🔎 Filter Console</p>', unsafe_allow_html=True)

    st.sidebar.text_input(
        "Search (target / family / hash / reason)",
        key="search",
        placeholder="e.g. 185.23.x.x, emotet, ..."
    )

    tier_options = sorted([t for t in df['Tier'].dropna().unique() if t in (1, 2)])
    st.sidebar.multiselect(
        "Detection Tier",
        options=tier_options,
        format_func=lambda t: "Tier 1 · Signature" if t == 1 else "Tier 2 · Behavioral",
        key="tier_filter"
    )

    family_options = sorted(clean_families) if 'clean_families' in dir() else []
    st.sidebar.multiselect(
        "Malware Family",
        options=family_options,
        key="family_filter"
    )

    st.sidebar.slider("Minimum Threat Score", 0, 10, key="min_score")

    st.sidebar.divider()
    st.sidebar.markdown('<p class="section-label">⚡ Quick Filters</p>', unsafe_allow_html=True)

    with st.sidebar.expander("🌐 IP Activity", expanded=False):
        # Sourced from the SourceIP column built in fetch_logs(). If this
        # stays empty, none of the field names checked there matched the
        # actual source-IP field in the OpenSearch alert docs.
        ip_counts = df[df['SourceIP'] != '-']['SourceIP'].value_counts()
        if ip_counts.empty:
            st.caption("No source IP field found in the alert documents.")
        for i, (ip, count) in enumerate(ip_counts.items()):
            st.button(f"{ip}  ({count})", key=f"ip_{i}_{ip}", on_click=set_search, args=(ip,), use_container_width=True)

    with st.sidebar.expander("🦠 Malware Activity", expanded=False):
        malware_counts = df[df['Tier'] != 2]['Family'].value_counts()
        for i, (mal, count) in enumerate(malware_counts.items()):
            st.button(f"{mal}  ({count})", key=f"mal_{i}_{mal}", on_click=set_search, args=(mal,), use_container_width=True)

    with st.sidebar.expander("🧠 Behavior Activity", expanded=False):
        behavior_counts = df[df['Tier'] == 2]['Reason'].value_counts()
        for i, (beh, count) in enumerate(behavior_counts.items()):
            st.button(f"{beh}  ({count})", key=f"beh_{i}_{beh}", on_click=set_search, args=(beh,), use_container_width=True)

    with st.sidebar.expander("🔁 Repeat Offenders", expanded=False):
        offenders = fetch_repeat_offenders()
        if offenders is None:
            st.caption("Repeat-offender tracker unavailable (Redis not reachable).")
        elif not offenders:
            st.caption("No repeat offenders in the current tracking window.")
        for i, o in enumerate(offenders or []):
            st.button(
                f"{o['ip']} · {o['threat']}  (×{o['count']})",
                key=f"rep_{i}_{o['ip']}",
                on_click=set_search, args=(o['ip'],),
                use_container_width=True,
            )

    def reset_filters():
        # Runs as an on_click callback, i.e. before the widgets below are
        # re-instantiated on the next run. Setting session_state directly
        # in the normal script body (after the widgets exist) raises
        # StreamlitWidgetAlreadyInstantiatedError.
        st.session_state.search = ""
        st.session_state.tier_filter = []
        st.session_state.family_filter = []
        st.session_state.min_score = 0

    def clear_all_data():
        """Empties the logs index in OpenSearch (the index itself and its
        mapping are kept) and removes the repeat-offender records from
        Redis, so the next pipeline run starts from a clean slate. Runs as
        an on_click callback, so the page reloads with fresh data after."""
        ok = True
        parts = []

        try:
            result = os_client.delete_by_query(
                index="logs",
                body={"query": {"match_all": {}}},
                refresh=True,
                conflicts="proceed",
            )
            parts.append(f"{result.get('deleted', 0)} log(s) deleted from OpenSearch")
        except Exception as e:
            ok = False
            parts.append(f"OpenSearch logs not cleared ({str(e)[:150]})")

        try:
            tracker = redis.Redis(host='localhost', port=REDIS_PORT, db=REPEAT_REDIS_DB, decode_responses=True)
            removed = 0
            for key in tracker.scan_iter(match=f"{REPEAT_KEY_PREFIX}:*"):
                tracker.delete(key)
                removed += 1
            parts.append(f"{removed} repeat-offender record(s) cleared")
        except Exception as e:
            ok = False
            parts.append(f"repeat-offender records not cleared ({str(e)[:150]})")

        st.session_state.clear_notice = (ok, "Clear finished: " + "; ".join(parts) + ".")
        st.session_state.clear_confirm = False

    st.sidebar.divider()
    fc1, fc2 = st.sidebar.columns(2)
    fc1.button("🔄 Reset Filters", use_container_width=True, on_click=reset_filters)
    if fc2.button("↻ Refresh", use_container_width=True):
        st.rerun()

    with st.sidebar.expander("🗑️ Clear All Data", expanded=False):
        st.caption(
            "Deletes every log in OpenSearch and resets the repeat-offender "
            "counts. The index itself is kept. This cannot be undone."
        )
        st.checkbox("I understand this permanently deletes all logs", key="clear_confirm")
        st.button(
            "Clear Logs",
            use_container_width=True,
            disabled=not st.session_state.get("clear_confirm", False),
            on_click=clear_all_data,
        )

    # --- APPLY FILTERS (all AND-combined) ---
    filtered_df = df.copy()

    active_filters = []

    if st.session_state.search:
        term = st.session_state.search.strip().lower()
        mask = (
            filtered_df['Target'].astype(str).str.lower().str.contains(term, na=False) |
            filtered_df['Family'].astype(str).str.lower().str.contains(term, na=False) |
            filtered_df['Hash'].astype(str).str.lower().str.contains(term, na=False) |
            filtered_df['Reason'].astype(str).str.lower().str.contains(term, na=False) |
            filtered_df['SourceIP'].astype(str).str.lower().str.contains(term, na=False)
        )
        filtered_df = filtered_df[mask]
        active_filters.append(f"search:'{st.session_state.search}'")

    if st.session_state.tier_filter:
        filtered_df = filtered_df[filtered_df['Tier'].isin(st.session_state.tier_filter)]
        active_filters.append(f"tier:{st.session_state.tier_filter}")

    if st.session_state.family_filter:
        cleaned_col = filtered_df['Family'].apply(clean_malware_name)
        filtered_df = filtered_df[cleaned_col.isin(st.session_state.family_filter)]
        active_filters.append(f"family:{st.session_state.family_filter}")

    if st.session_state.min_score > 0:
        filtered_df = filtered_df[filtered_df['Score'] >= st.session_state.min_score]
        active_filters.append(f"score>={st.session_state.min_score}")

    # --- TRIAGE FEED ---
    st.markdown('<p class="section-label">Live Triage Feed</p>', unsafe_allow_html=True)

    if active_filters:
        st.markdown(
            f"<span style='color:#64748b;font-size:12px;'>ACTIVE FILTERS → {' | '.join(active_filters)} &nbsp;·&nbsp; {len(filtered_df)} / {len(df)} events</span>",
            unsafe_allow_html=True
        )
    else:
        st.markdown(f"<span style='color:#64748b;font-size:12px;'>{len(df)} events</span>", unsafe_allow_html=True)

    # Alert grid (SIEM-style table)
    if not filtered_df.empty:
        grid_df = filtered_df.sort_values('Time', ascending=False).copy()
        grid_df['Time'] = grid_df['Time'].apply(format_time_safe)
        grid_df['Tier'] = grid_df['Tier'].map({1: "T1 · SIG", 2: "T2 · BEHAV"}).fillna("UNK")
        display_cols = ['Time', 'SourceIP', 'Score', 'Tier', 'Target', 'Family', 'DetectionType', 'Reason']

        def highlight_score_col(series):
            styles = []
            for val in series:
                if isinstance(val, (int, float)) and val >= 8:
                    styles.append("color: #f43f5e; font-weight: 700;")
                elif isinstance(val, (int, float)) and val >= 5:
                    styles.append("color: #f59e0b; font-weight: 700;")
                else:
                    styles.append("color: #22d3ee;")
            return styles

        def highlight_tier_col(series):
            styles = []
            for val in series:
                if "T1" in str(val):
                    styles.append("color: #22d3ee; font-weight: 700;")
                elif "T2" in str(val):
                    styles.append("color: #8b5cf6; font-weight: 700;")
                else:
                    styles.append("color: #64748b;")
            return styles

        def tint_row_by_score(row):
            score = row['Score']
            if isinstance(score, (int, float)) and score >= 8:
                bg = "background-color: rgba(244,63,94,0.08);"
            elif isinstance(score, (int, float)) and score >= 5:
                bg = "background-color: rgba(245,158,11,0.06);"
            else:
                bg = "background-color: rgba(34,211,238,0.04);"
            return [bg] * len(row)

        # Styler.apply (column-wise / row-wise) is stable across pandas
        # versions; Styler.map / .applymap have changed between versions,
        # so avoid them. Row tint is applied first, then the two column
        # colorings layer their font color on top of the same cells.
        styled = (
            grid_df[display_cols].style
            .apply(tint_row_by_score, axis=1)
            .apply(highlight_score_col, subset=['Score'])
            .apply(highlight_tier_col, subset=['Tier'])
        )
        st.dataframe(styled, use_container_width=True, height=360, hide_index=True)
    else:
        st.warning("No events match the current filters.")

    st.markdown('<p class="section-label">Event Detail / Drill-down</p>', unsafe_allow_html=True)

    for _, row in filtered_df.sort_values('Time', ascending=False).iterrows():
        icon = "🚨" if row['Score'] >= 8 else "⚠️"
        time_str = format_time_safe(row['Time'])
        tier_badge = "T1" if row['Tier'] == 1 else "T2" if row['Tier'] == 2 else "??"

        feed_title = f"{icon} [{tier_badge}] {time_str}  ·  {row['Target']}  ·  {row['Family']}  ·  score {row['Score']}/10"

        with st.expander(feed_title):
            st.markdown(severity_badge(row['Score'], row['Tier']), unsafe_allow_html=True)
            st.markdown(f"**Source IP:** {row['SourceIP']}")
            st.markdown(f"**Detection Layer:** {row['Tier']}")
            st.markdown(f"**Type:** {row['DetectionType']}")
            st.markdown(f"**Reason:** {row['Reason']}")

            st.markdown("**🧠 AI Recommendation**")
            st.info(row['Recommendation'])

            if row['Hash'] != '-':
                st.code(row['Hash'])
                st.markdown(f"[🔍 MalwareBazaar Lookup](https://bazaar.abuse.ch/sample/{row['Hash']}/)")

            # Only renders if the alert doc carries one of the evidence
            # fields checked in fetch_logs(). None of the current alert
            # documents have this yet, so this section stays hidden.
            if row['Evidence']:
                st.markdown("**📋 Attack Evidence / Matched Log Events**")
                for ev in row['Evidence']:
                    st.code(str(ev))

else:
    st.info("Waiting for telemetry...")

# --- LIVE AUTO-REFRESH ---
# Every REFRESH_SECONDS this small fragment compares the current alert count
# in OpenSearch with the count the page was built from, and reruns the whole
# page only when they differ - so new alerts appear on their own, and the
# page stays still (no flicker, filters and search kept) when nothing changed.
if hasattr(st, "fragment"):
    @st.fragment(run_every=REFRESH_SECONDS)
    def _live_refresh():
        current = get_log_count()
        if current is not None and current != st.session_state.get("seen_log_count"):
            st.rerun()

    _live_refresh()