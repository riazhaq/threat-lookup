#!/usr/bin/env python3
"""Threat Lookup — Executive SOC Dashboard"""
import asyncio
import io
import importlib
import os
import sys
import time
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# ── Import core logic ──────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
import threat_lookup as tl

# Ensure Streamlit reruns use the latest local module code.
tl = importlib.reload(tl)


def refresh_lookup_config() -> None:
    """Refresh env-backed keys even if an older module version is loaded."""
    if hasattr(tl, "refresh_runtime_config"):
        tl.refresh_runtime_config()
        return

    # Backward-compatible fallback for older cached modules.
    if hasattr(tl, "load_local_env"):
        try:
            tl.load_local_env(override=True)
        except TypeError:
            tl.load_local_env()

    tl.VT_API_KEY = os.getenv("VT_API_KEY")
    tl.OTX_API_KEY = os.getenv("OTX_API_KEY")
    tl.ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
    tl.THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")
    tl.SILENTPUSH_API_KEY = os.getenv("SILENTPUSH_API_KEY")
    tl.SILENTPUSH_DATA_SOURCE = os.getenv("SILENTPUSH_DATA_SOURCE", "iofa")
    tl.SILENTPUSH_API_BASE_URL = os.getenv("SILENTPUSH_API_BASE_URL", "https://api.silentpush.com/api/v1/merge-api").strip().rstrip("/")
    tl.SPUR_API_KEY = os.getenv("SPUR_API_KEY")
    tl.RL_SPECTRA_BASE_URL = os.getenv("RL_SPECTRA_BASE_URL", "").strip().rstrip("/")
    tl.RL_SPECTRA_TOKEN = os.getenv("RL_SPECTRA_TOKEN")

# Always refresh env-backed keys on Streamlit reruns.
refresh_lookup_config()

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Threat Lookup",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
html, body, [class*="css"] { font-family: 'Inter', 'Segoe UI', sans-serif; }

:root {
    --source-unified-color: #0f172a;
    --hero-title-color: #0f172a;
}

@media (prefers-color-scheme: dark) {
    :root {
        --source-unified-color: #e5e7eb;
        --hero-title-color: #f8fafc;
    }
}

[data-testid="stDeployButton"] {
    display: none !important;
}

.kpi-card {
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 12px;
    padding: 20px 24px;
    box-shadow: 0 1px 3px rgba(0,0,0,.07);
    text-align: center;
    margin-bottom: 8px;
}
.kpi-number { font-size: 2.4rem; font-weight: 700; line-height: 1.1; }
.kpi-label  { font-size: .83rem; color: #6b7280; margin-top: 4px; letter-spacing:.01em; }

.section-title {
    font-size: 1.05rem; font-weight: 650; color: #111827;
    margin: 1.5rem 0 .75rem;
    padding-bottom: .4rem;
    border-bottom: 2px solid #e5e7eb;
}
.verdict-bar {
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 1rem;
    border-left: 5px solid;
}
.source-meta { font-size:.82rem; color:#6b7280; }
</style>
""", unsafe_allow_html=True)

# ── Verdict palette ────────────────────────────────────────────────────────────
VERDICT_STYLE = {
    "Malicious":  {"bg": "#fee2e2", "fg": "#dc2626", "border": "#dc2626"},
    "Suspicious": {"bg": "#fef3c7", "fg": "#d97706", "border": "#d97706"},
    "Low Risk":   {"bg": "#dbeafe", "fg": "#2563eb", "border": "#2563eb"},
    "Benign":     {"bg": "#dcfce7", "fg": "#16a34a", "border": "#16a34a"},
}

SOURCE_ICONS = {
    "virustotal": "🔬",
    "alienvault": "👾",
    "threatfox":  "🕷️",
    "abuseipdb":  "🚨",
    "silentpush": "🛰️",
    "spur": "🧭",
    "reversinglabs": "🧪",
}

SOURCE_BRAND = {
    "VirusTotal": "var(--source-unified-color)",
    "AlienVault OTX": "var(--source-unified-color)",
    "ThreatFox": "var(--source-unified-color)",
    "AbuseIPDB": "var(--source-unified-color)",
    "Silent Push": "var(--source-unified-color)",
    "Spur": "var(--source-unified-color)",
    "ReversingLabs": "var(--source-unified-color)",
}

SOURCE_DISPLAY = {
    "virustotal": "VirusTotal",
    "alienvault": "AlienVault OTX",
    "threatfox": "ThreatFox",
    "abuseipdb": "AbuseIPDB",
    "silentpush": "Silent Push",
    "spur": "Spur",
    "reversinglabs": "ReversingLabs",
}

PROVIDER_OPTIONS = [
    ("virustotal", "VirusTotal", False),
    ("alienvault", "AlienVault OTX", False),
    ("threatfox", "ThreatFox", False),
    ("abuseipdb", "AbuseIPDB", True),
    ("silentpush", "Silent Push", False),
    ("spur", "Spur", True),
    ("reversinglabs", "ReversingLabs", False),
]

# ── Helpers ────────────────────────────────────────────────────────────────────
def api_health() -> dict:
    refresh_lookup_config()
    spur_status = tl.get_spur_token_status() if getattr(tl, "SPUR_API_KEY", None) else {"active": False, "error": "no_api_key"}
    rl_status = tl.get_reversinglabs_token_status()
    st.session_state["spur_status"] = spur_status
    st.session_state["rl_status"] = rl_status
    return {
        "VirusTotal": bool(tl.VT_API_KEY),
        "AlienVault OTX": bool(tl.OTX_API_KEY),
        "AbuseIPDB":  bool(tl.ABUSE_API_KEY),
        "ThreatFox":  bool(tl.THREATFOX_API_KEY),
        "Silent Push": bool(tl.SILENTPUSH_API_KEY),
        "Spur": bool(spur_status.get("active")),
        "ReversingLabs": bool(rl_status.get("active")),
    }


def results_to_df(results: list) -> pd.DataFrame:
    rows = []
    for r in results:
        if r is None:
            continue
        top_reason = ""
        reasons = r.get("reasons") or []
        if reasons:
            top_reason = reasons[0]
        elif r.get("reason"):
            top_reason = r["reason"]
        rows.append({
            "IOC":        r.get("ioc", ""),
            "Type":       (r.get("type") or "—").upper(),
            "Verdict":    r.get("verdict", "—"),
            "Score":      r.get("score", 0),
            "Top Reason": top_reason,
            "Time (s)":   r.get("time_taken", 0),
        })
    return pd.DataFrame(rows)


def color_verdict_cell(val):
    style = VERDICT_STYLE.get(val)
    if style:
        return f"background-color:{style['bg']}; color:{style['fg']}; font-weight:600"
    return ""


def run_analysis(iocs, workers, delay, jitter, enabled_sources):
    refresh_lookup_config()
    return asyncio.run(tl.analyze_bulk(iocs, workers, delay, jitter, enabled_sources=enabled_sources))


def _fmt_simple_value(value):
    if value in (None, "", []):
        return "n/a"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


def _render_silentpush_source(src: dict) -> None:
    risk_score = src.get("sp_risk_score")
    verdict = src.get("sp_verdict") or "Unknown"
    listed = bool(src.get("is_listed"))
    asn = src.get("asn_lookup") or src.get("asn") or src.get("answer_asn")
    country = src.get("country") or src.get("country_code")
    bulletproof_signal = src.get("bulletproof_hosting_likelihood")
    reverse_domain_count = src.get("padns_reverse_a_domains_count")
    bulletproof_reason = src.get("bulletproof_hosting_reason")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Verdict", _fmt_simple_value(verdict))
    c2.metric("Risk Score", _fmt_simple_value(risk_score))
    c3.metric("Listed", "Yes" if listed else "No")
    c4.metric("ASN", _fmt_simple_value(asn))
    c5.metric("Country", _fmt_simple_value(country))

    if bulletproof_signal not in (None, ""):
        b1, b2, b3 = st.columns(3)
        b1.metric("Bulletproof Hosting", _fmt_simple_value(bulletproof_signal).replace("_", " ").title())
        b2.metric("Reverse A Domains", _fmt_simple_value(reverse_domain_count))
        b3.metric("Signal Source", "Silent Push PADNS")
        if bulletproof_reason:
            st.markdown(f"- **Hosting pattern note:** {bulletproof_reason}")

    st.markdown("**Primary context:**")
    primary_rows = [
        ("Endpoint", src.get("endpoint")),
        ("Query", src.get("query")),
        ("Query Type", src.get("query_type")),
        ("Risk Decider", src.get("sp_risk_score_decider")),
        ("Subnet", src.get("subnet")),
        ("AS Org", src.get("as_org") or src.get("answer_as_name")),
        ("Threat Rank", src.get("threat_rank")),
    ]
    for label, value in primary_rows:
        if value not in (None, "", []):
            st.markdown(f"- **{label}:** {value}")

    available_endpoints = src.get("available_endpoints") or []
    available_apis = src.get("non_explore_available_apis") or []
    api_status = src.get("non_explore_status") or {}
    unavailable = [
        f"{name} ({status})"
        for name, status in api_status.items()
        if isinstance(status, str) and status.startswith("unavailable")
    ]

    st.markdown("**API coverage:**")
    st.markdown(f"- **Explore endpoints available:** {len(available_endpoints)}")
    if available_endpoints:
        st.markdown(f"- **Explore used:** {', '.join(str(e) for e in available_endpoints[:3])}")
    st.markdown(f"- **Additional APIs available:** {', '.join(str(a) for a in available_apis) if available_apis else 'none'}")
    if unavailable:
        st.markdown(f"- **Unavailable APIs:** {', '.join(unavailable[:4])}")

    tech_details = {
        "listed_txt": src.get("listed_txt"),
        "threat_check_listed": src.get("threat_check_listed"),
        "padns_reverse_a_domains_sample": src.get("padns_reverse_a_domains_sample"),
        "asn_ip_reputation": src.get("asn_ip_reputation"),
        "asn_takedown_reputation": src.get("asn_takedown_reputation"),
    }
    compact_details = {k: v for k, v in tech_details.items() if v not in (None, "", [], {})}
    if compact_details:
        with st.expander("Silent Push technical details", expanded=False):
            st.json(compact_details)


# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ Threat Lookup")
    st.caption("IOC Reputation Dashboard")
    st.divider()

    st.markdown("**Source Toggles**")
    selected_sources = []
    for source_key, source_name, ip_only in PROVIDER_OPTIONS:
        icon = SOURCE_ICONS.get(source_key, "📡")
        label = f"{icon} {source_name}"
        if ip_only:
            label = f"{label} (IP-only)"
        enabled = st.checkbox(label, value=True, key=f"source_enabled_{source_key}")
        if enabled:
            selected_sources.append(source_key)

    if not selected_sources:
        st.caption("Enable at least one source to run analysis.")

    st.divider()

    # API health
    st.markdown("**API Status**")
    for name, ok in api_health().items():
        dot = "🟢" if ok else "🔴"
        name_color = SOURCE_BRAND.get(name, "#111827")
        st.markdown(
            f"{dot} &nbsp;<span style='color:{name_color}; font-weight:700;'>{name}</span>",
            unsafe_allow_html=True,
        )
    spur_status = st.session_state.get("spur_status") or {}
    if spur_status.get("active"):
        remaining = spur_status.get("queries_remaining")
        tier = spur_status.get("service_tier") or "unknown"
        if remaining is not None:
            st.caption(f"Spur: {remaining} queries remaining ({tier})")
        else:
            st.caption(f"Spur: active ({tier})")
    elif spur_status.get("error"):
        st.caption(f"Spur status: {spur_status.get('error')}")

    rl_status = st.session_state.get("rl_status") or {}
    if rl_status.get("active"):
        rl_stat = rl_status.get("status") or "ok"
        st.caption(f"ReversingLabs status: {rl_stat}")
    elif rl_status.get("error"):
        st.caption(f"ReversingLabs status: {rl_status.get('error')}")

    st.divider()

    # Input
    st.markdown("**Input IOCs**")
    input_mode = st.radio("Mode", ["Upload File", "Paste IOCs"], label_visibility="collapsed")

    ioc_list: list = []
    if input_mode == "Upload File":
        uploaded = st.file_uploader(
            "TXT or Excel file", type=["txt", "xlsx", "xls"],
            label_visibility="collapsed"
        )
        if uploaded:
            if uploaded.name.lower().endswith((".xlsx", ".xls")):
                tmp = Path("_tmp_upload.xlsx")
                tmp.write_bytes(uploaded.read())
                ioc_list = tl._read_iocs_excel(str(tmp))
                tmp.unlink(missing_ok=True)
            else:
                text = uploaded.read().decode("utf-8-sig", errors="replace")
                ioc_list = [
                    ln.strip() for ln in text.splitlines()
                    if ln.strip() and not ln.strip().startswith("#")
                ]
            st.success(f"{len(ioc_list)} IOC(s) loaded")
    else:
        raw = st.text_area(
            "One IOC per line", height=160,
            placeholder="185.220.101.1\nevil-domain.com\nabc123hash...",
            label_visibility="collapsed"
        )
        ioc_list = [
            ln.strip() for ln in raw.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        if ioc_list:
            st.caption(f"{len(ioc_list)} IOC(s) detected")

    st.divider()

    with st.expander("⚙️ Settings"):
        workers = st.slider("Concurrent workers", 1, 5, 5,
                            help="Higher = faster but more API pressure")
        delay   = st.slider("Delay between starts (s)", 0.2, 3.0, 0.2, 0.1,
                            help="Minimum pause between IOC batches")
        jitter  = st.slider("Jitter (s)", 0.0, 1.0, 0.05, 0.05,
                            help="Random extra delay to avoid burst patterns")

    st.divider()
    run_btn = st.button(
        "🔍  Run Analysis",
        type="primary",
        disabled=(len(ioc_list) == 0 or len(selected_sources) == 0),
        use_container_width=True,
    )
    if st.session_state.get("results"):
        if st.button("🗑️  Clear Results", use_container_width=True):
            st.session_state.results = None
            st.session_state.run_time = None
            st.rerun()

# ── Init session state ─────────────────────────────────────────────────────────
if "results" not in st.session_state:
    st.session_state.results = None
if "run_time" not in st.session_state:
    st.session_state.run_time = None
if "selected_ioc" not in st.session_state:
    st.session_state.selected_ioc = None

# ── Run analysis ───────────────────────────────────────────────────────────────
if run_btn and ioc_list:
    with st.spinner(f"Analyzing {len(ioc_list)} IOC(s) across {len(selected_sources)} enabled source(s)…"):
        try:
            st.session_state.results = run_analysis(ioc_list, workers, delay, jitter, selected_sources)
            st.session_state.run_time = time.strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            st.error(f"Analysis failed: {e}")
    st.rerun()

# ── Landing screen ─────────────────────────────────────────────────────────────
if st.session_state.results is None:
    st.markdown("""
    <div style="text-align:center; padding:70px 0 30px;">
        <div style="font-size:3.5rem;">🛡️</div>
        <h1 style="font-size:1.9rem; font-weight:700; margin-top:.4rem; color:var(--hero-title-color);">
            Threat Lookup Dashboard
        </h1>
        <p style="color:#6b7280; max-width:500px; margin:1rem auto 0; font-size:.95rem;">
            Upload a TXT or Excel file with IOCs, or paste them directly in the sidebar.
            Click <strong>Run Analysis</strong> to check reputation across multiple sources.
        </p>
    </div>
    """, unsafe_allow_html=True)

    cols = st.columns(7)
    source_info = [
        ("🔬", "VirusTotal",    "IPs · Domains · URLs · Hashes"),
        ("👾", "AlienVault OTX","IPs · Domains · URLs · Hashes"),
        ("🕷️", "ThreatFox",     "IPs · Domains · URLs · Hashes"),
        ("🚨", "AbuseIPDB",     "IPs only"),
        ("🛰️", "Silent Push",   "IPs · Domains · URL hostnames"),
        ("🧭", "Spur",          "IPs only"),
        ("🧪", "ReversingLabs", "IPs · Domains · URLs · Hashes"),
    ]
    health = api_health()
    for col, (icon, name, coverage) in zip(cols, source_info):
        ok = health.get(name, False)
        color = "#16a34a" if ok else "#dc2626"
        status = "✓ Connected" if ok else "✗ No API Key"
        source_color = SOURCE_BRAND.get(name, "#111827")
        col.markdown(f"""
        <div class="kpi-card">
            <div style="font-size:2rem;">{icon}</div>
            <div style="font-weight:700; margin-top:.4rem; color:{source_color};">{name}</div>
            <div style="color:#6b7280; font-size:.78rem; margin-top:.2rem;">{coverage}</div>
            <div style="color:{color}; font-size:.8rem; margin-top:.4rem; font-weight:600;">{status}</div>
        </div>
        """, unsafe_allow_html=True)

    st.stop()

# ── Results ────────────────────────────────────────────────────────────────────
results = st.session_state.results
df = results_to_df(results)
counts = df["Verdict"].value_counts().to_dict()
timeout_count = sum(
    1 for r in results if r
    for s in r.get("sources", [])
    if s.get("error") == "timeout"
)

# Run timestamp
if st.session_state.run_time:
    st.markdown(
        f"<p style='color:#9ca3af; font-size:.82rem; margin-bottom:.25rem;'>"
        f"Last run: {st.session_state.run_time}</p>",
        unsafe_allow_html=True
    )

# ── KPI cards ──────────────────────────────────────────────────────────────────
k1, k2, k3, k4, k5, k6 = st.columns(6)
kpis = [
    ("Total IOCs",  len(results),                "#111827"),
    ("Malicious",   counts.get("Malicious", 0),  "#dc2626"),
    ("Suspicious",  counts.get("Suspicious", 0), "#d97706"),
    ("Low Risk",    counts.get("Low Risk", 0),   "#2563eb"),
    ("Benign",      counts.get("Benign", 0),     "#16a34a"),
    ("API Timeouts",timeout_count,               "#9333ea"),
]
for col, (label, val, color) in zip([k1, k2, k3, k4, k5, k6], kpis):
    col.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-number" style="color:{color};">{val}</div>
        <div class="kpi-label">{label}</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='margin-top:1rem'/>", unsafe_allow_html=True)

# ── Results table ──────────────────────────────────────────────────────────────
st.markdown('<div class="section-title">📋 Results</div>', unsafe_allow_html=True)

# Export buttons
exp_col, json_col, _ = st.columns([1, 1, 5])
with exp_col:
    csv_buf = io.StringIO()
    df.to_csv(csv_buf, index=False)
    st.download_button(
        "⬇️ Export CSV", csv_buf.getvalue(),
        "threat_results.csv", "text/csv", use_container_width=True
    )
with json_col:
    st.download_button(
        "⬇️ Export JSON", data=__import__("json").dumps(results, indent=2),
        file_name="threat_results.json", mime="application/json",
        use_container_width=True
    )

table_event = st.dataframe(
    df,
    use_container_width=True,
    hide_index=True,
    height=min(420, 58 + 36 * len(df)),
    on_select="rerun",
    selection_mode="single-row",
    key="results_table",
)

selected_rows = []
if isinstance(table_event, dict):
    selected_rows = (table_event.get("selection") or {}).get("rows") or []

if selected_rows:
    selected_idx = selected_rows[0]
    if 0 <= selected_idx < len(df):
        st.session_state.selected_ioc = str(df.iloc[selected_idx]["IOC"])

# ── IOC Detail ─────────────────────────────────────────────────────────────────
st.markdown('<div class="section-title">🔎 IOC Detail</div>', unsafe_allow_html=True)

ioc_options = [r["ioc"] for r in results if r]
if st.session_state.selected_ioc not in ioc_options:
    st.session_state.selected_ioc = ioc_options[0] if ioc_options else None

selected_ioc = st.selectbox(
    "Select IOC",
    ioc_options,
    index=(ioc_options.index(st.session_state.selected_ioc) if st.session_state.selected_ioc in ioc_options else 0),
    label_visibility="collapsed",
)
st.session_state.selected_ioc = selected_ioc
detail = next((r for r in results if r and r.get("ioc") == selected_ioc), None)

if detail:
    v = detail.get("verdict", "Benign")
    vs = VERDICT_STYLE.get(v, {"bg": "#f3f4f6", "fg": "#111827", "border": "#d1d5db"})

    # Verdict banner
    st.markdown(f"""
    <div class="verdict-bar" style="
        background:{vs['bg']};
        border-left-color:{vs['border']};
    ">
        <span style="font-size:1.15rem; font-weight:700; color:{vs['fg']};">{v}</span>
        &nbsp;&nbsp;
        <span style="color:#374151; font-size:.95rem; font-weight:500;">
            {detail.get('ioc', '')}
        </span>
        <span style="float:right; color:#6b7280; font-size:.82rem;">
            Score: <strong>{detail.get('score', 0)}/100</strong>
            &nbsp;·&nbsp; Type: <strong>{(detail.get('type') or '—').upper()}</strong>
            &nbsp;·&nbsp; {detail.get('time_taken', 0):.1f}s
        </span>
    </div>
    """, unsafe_allow_html=True)

    # Reasons
    reasons = detail.get("reasons") or ([detail.get("reason")] if detail.get("reason") else [])
    if reasons:
        st.markdown("**Assessment rationale:**")
        for r in reasons:
            st.markdown(f"- {r}")

    st.markdown("---")

    rl_src = next((s for s in detail.get("sources", []) if s.get("source") == "reversinglabs"), None)
    if rl_src and not rl_src.get("error"):
        st.markdown("**ReversingLabs Summary:**")
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("RL Verdict", rl_src.get("rl_verdict") or "Unknown")
        c2.metric("Classification", rl_src.get("classification") or "n/a")
        c3.metric("Threat Level", rl_src.get("threat_level") or "n/a")
        c4.metric("Risk Score", rl_src.get("risk_score") if rl_src.get("risk_score") is not None else "n/a")
        c5.metric("Malicious Signals", rl_src.get("malicious_signals") or 0)

        tp1, tp2, tp3, tp4, tp5 = st.columns(5)
        tp1.metric("3P Malicious", rl_src.get("third_party_malicious") or 0)
        tp2.metric("3P Suspicious", rl_src.get("third_party_suspicious") or 0)
        tp3.metric("3P Clean", rl_src.get("third_party_clean") or 0)
        tp4.metric("3P Total", rl_src.get("third_party_total") or 0)
        ratio = rl_src.get("third_party_detection_ratio")
        tp5.metric("3P Detect Ratio", f"{ratio:.3f}" if isinstance(ratio, (int, float)) else "n/a")

        c6, c7, c8 = st.columns(3)
        c6.metric("Related URLs", rl_src.get("related_urls_count") or 0)
        c7.metric("Resolutions", rl_src.get("resolutions_count") or 0)
        c8.metric("Downloaded Files", rl_src.get("downloaded_files_count") or 0)

        whois_fields = {
            "Registrar": rl_src.get("registrar"),
            "Registrant": rl_src.get("registrant"),
            "Organization": rl_src.get("organization"),
            "Country": rl_src.get("country"),
            "Created": rl_src.get("created"),
            "Updated": rl_src.get("updated"),
            "Expires": rl_src.get("expires"),
            "ASN": rl_src.get("asn"),
            "AS Owner": rl_src.get("as_owner"),
            "Network": rl_src.get("network"),
            "Registry": rl_src.get("registry"),
        }
        whois_nameservers = rl_src.get("nameservers") or []
        has_whois = any(whois_fields.values()) or bool(whois_nameservers)
        if has_whois:
            with st.expander("ReversingLabs WHOIS / Registration Context", expanded=False):
                for label, value in whois_fields.items():
                    if value:
                        st.markdown(f"**{label}:** {value}")
                if whois_nameservers:
                    st.markdown(f"**Nameservers:** {', '.join(str(v) for v in whois_nameservers)}")

        highlights = rl_src.get("highlights") or {}
        if highlights:
            with st.expander("ReversingLabs Highlights", expanded=False):
                for hk, hv in highlights.items():
                    label = str(hk).replace("_", " ").replace(".", " > ").title()
                    if isinstance(hv, list):
                        st.markdown(f"**{label}:** {', '.join(str(x) for x in hv)}")
                    else:
                        st.markdown(f"**{label}:** {hv}")

    # Per-source breakdown
    for src in detail.get("sources", []):
        src_name = src.get("source", "")
        has_error = bool(src.get("error"))
        icon = SOURCE_ICONS.get(src_name, "📡")
        display_name = SOURCE_DISPLAY.get(src_name, src_name.replace("_", " ").title())
        display_color = SOURCE_BRAND.get(display_name, "#111827")
        err_icon = "⚠️ " if has_error else ""
        with st.expander(f"{err_icon}{icon} **{display_name}**", expanded=not has_error):
            st.markdown(
                f"<span style='color:{display_color}; font-weight:700;'>{display_name}</span>",
                unsafe_allow_html=True,
            )

            if src_name == "silentpush" and not has_error:
                _render_silentpush_source(src)
                continue

            skip = {"source", "score"}
            fields = {k: v for k, v in src.items() if k not in skip}
            if not fields:
                st.caption("No data returned.")
            for k, v in fields.items():
                label = k.replace("_", " ").title()
                if isinstance(v, list):
                    if v:
                        st.markdown(f"**{label}:** {', '.join(str(x) for x in v)}")
                elif isinstance(v, dict):
                    st.markdown(f"**{label}:**")
                    for dk, dv in v.items():
                        st.markdown(f"&nbsp;&nbsp;&nbsp;• `{dk}` → `{dv}`",
                                    unsafe_allow_html=True)
                elif isinstance(v, bool):
                    st.markdown(f"**{label}:** {'Yes ⚠️' if v else 'No'}")
                else:
                    st.markdown(f"**{label}:** `{v}`")

# ── Charts ─────────────────────────────────────────────────────────────────────
st.markdown('<div class="section-title">📊 Summary Charts</div>', unsafe_allow_html=True)

ch1, ch2, ch3 = st.columns(3)

with ch1:
    vc = df["Verdict"].value_counts().reset_index()
    vc.columns = ["Verdict", "Count"]
    color_map = {
        "Malicious": "#dc2626", "Suspicious": "#d97706",
        "Low Risk":  "#2563eb", "Benign":     "#16a34a",
    }
    fig1 = px.pie(
        vc, names="Verdict", values="Count",
        title="Verdict Distribution",
        color="Verdict", color_discrete_map=color_map,
        hole=0.45,
    )
    fig1.update_traces(textposition="inside", textinfo="percent+label")
    fig1.update_layout(showlegend=False, margin=dict(t=44, b=4, l=4, r=4), height=290)
    st.plotly_chart(fig1, use_container_width=True)

with ch2:
    tc = df["Type"].value_counts().reset_index()
    tc.columns = ["Type", "Count"]
    fig2 = px.bar(
        tc, x="Type", y="Count",
        title="IOC Types",
        color="Type",
        color_discrete_sequence=["#6366f1", "#06b6d4", "#f59e0b", "#10b981"],
        text="Count",
    )
    fig2.update_traces(textposition="outside")
    fig2.update_layout(
        showlegend=False, margin=dict(t=44, b=4, l=4, r=4),
        height=290, xaxis_title="", yaxis_title="",
    )
    st.plotly_chart(fig2, use_container_width=True)

with ch3:
    fig3 = px.histogram(
        df, x="Score", nbins=10,
        title="Score Distribution",
        color_discrete_sequence=["#6366f1"],
    )
    fig3.update_layout(
        margin=dict(t=44, b=4, l=4, r=4),
        height=290, xaxis_title="Risk Score", yaxis_title="IOC Count",
    )
    st.plotly_chart(fig3, use_container_width=True)
