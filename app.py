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

# Keep card labels high-contrast on white tile backgrounds in both light/dark themes.
SOURCE_BRAND_CARD = {
    "VirusTotal": "#111827",
    "AlienVault OTX": "#111827",
    "ThreatFox": "#111827",
    "AbuseIPDB": "#111827",
    "Silent Push": "#111827",
    "Spur": "#111827",
    "ReversingLabs": "#111827",
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
    ("reversinglabs", "ReversingLabs", False),
    ("spur", "Spur", True),
    ("silentpush", "Silent Push", False),
    ("virustotal", "VirusTotal", False),
    ("alienvault", "AlienVault OTX", False),
    ("threatfox", "ThreatFox", False),
    ("abuseipdb", "AbuseIPDB", True),
]

DEFAULT_ENABLED_SOURCES = {
    "reversinglabs",
    "spur",
    "silentpush",
}

# ── Helpers ────────────────────────────────────────────────────────────────────
def api_health() -> dict:
    refresh_lookup_config()
    spur_status = tl.get_spur_token_status() if getattr(tl, "SPUR_API_KEY", None) else {"active": False, "error": "no_api_key"}
    rl_status = tl.get_reversinglabs_token_status()
    st.session_state["spur_status"] = spur_status
    st.session_state["rl_status"] = rl_status
    return {
        "ReversingLabs": bool(rl_status.get("active")),
        "Spur": bool(spur_status.get("active")),
        "Silent Push": bool(tl.SILENTPUSH_API_KEY),
        "VirusTotal": bool(tl.VT_API_KEY),
        "AlienVault OTX": bool(tl.OTX_API_KEY),
        "AbuseIPDB":  bool(tl.ABUSE_API_KEY),
        "ThreatFox":  bool(tl.THREATFOX_API_KEY),
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


def _fmt_reversinglabs_value(value):
    if value in (None, "", [], {}):
        return "not reported"
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".")
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


def _api_usage_value(src: dict, key: str):
    usage = src.get("api_usage") or {}
    if isinstance(usage, dict):
        val = usage.get(key)
        if val not in (None, "", []):
            return val

    fallback_map = {
        "remaining": src.get("balance_remaining"),
        "used": None,
        "limit": None,
        "reset": src.get("result_dt"),
        "window": None,
    }
    return fallback_map.get(key)


def _render_api_usage_indicator(src: dict, provider_label: str) -> None:
    remaining = _api_usage_value(src, "remaining")
    used = _api_usage_value(src, "used")
    limit = _api_usage_value(src, "limit")
    reset = _api_usage_value(src, "reset")
    window = _api_usage_value(src, "window")

    st.markdown("**API usage:**")
    u1, u2, u3, u4 = st.columns(4)
    u1.metric("Remaining", _fmt_simple_value(remaining))
    u2.metric("Used", _fmt_simple_value(used))
    u3.metric("Limit", _fmt_simple_value(limit))
    u4.metric("Reset/Window", _fmt_simple_value(reset or window))

    if all(v in (None, "", []) for v in (remaining, used, limit, reset, window)):
        st.caption(f"{provider_label} did not return usage-limit headers for this request.")


def _render_unavailable_api_usage_indicator(provider_label: str, reason: str) -> None:
    st.markdown("**API usage:**")
    st.caption(f"{provider_label}: {reason}")


def _labelize_reversinglabs_key(key: str) -> str:
    text = str(key).replace("_", " ").replace(".", " > ")
    return text[:1].upper() + text[1:] if text else text


def _render_reversinglabs_source(src: dict) -> None:
    if src.get("error"):
        st.warning(f"ReversingLabs error: {src.get('error')}")
        if src.get("hint"):
            st.caption(str(src.get("hint")))
        return

    verdict = src.get("rl_verdict") or "Unknown"
    classification = src.get("classification")
    threat_level = src.get("threat_level")
    risk_score = src.get("risk_score")
    malicious_signals = src.get("malicious_signals") or 0
    tp_malicious = src.get("third_party_malicious") or 0
    tp_suspicious = src.get("third_party_suspicious") or 0
    tp_clean = src.get("third_party_clean") or 0
    tp_total = src.get("third_party_total") or 0
    detection_ratio = src.get("third_party_detection_ratio")
    confidence = src.get("confidence")
    severity = src.get("severity")

    first_seen = src.get("first_seen")
    last_seen = src.get("last_seen")
    status = src.get("status")
    threat_name = src.get("threat_name")
    malware_family = src.get("malware_family")
    campaign = src.get("campaign")
    threat_actor = src.get("threat_actor")

    file_type = src.get("file_type")
    mime_type = src.get("mime_type")
    file_size = src.get("file_size")

    tags = src.get("tags") or []
    categories = src.get("categories") or []
    ttps = src.get("ttps") or []
    cves = src.get("cves") or []

    endpoint = src.get("endpoint")

    st.markdown("**Assessment snapshot:**")
    if endpoint not in (None, "", []):
        st.caption(f"Endpoint used: {endpoint}")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Verdict", _fmt_reversinglabs_value(verdict))
    c2.metric("Classification", _fmt_reversinglabs_value(classification))
    c3.metric("Threat Level", _fmt_reversinglabs_value(threat_level))
    c4.metric("Risk Score", _fmt_reversinglabs_value(risk_score))

    c5, c6, c7, c8 = st.columns(4)
    c5.metric("Malicious Signals", _fmt_reversinglabs_value(malicious_signals))
    c6.metric("3P Malicious", _fmt_reversinglabs_value(tp_malicious))
    c7.metric("3P Total", _fmt_reversinglabs_value(tp_total))
    c8.metric("3P Detect Ratio", _fmt_reversinglabs_value(detection_ratio))

    extra1, extra2, extra3, extra4 = st.columns(4)
    extra1.metric("Confidence", _fmt_reversinglabs_value(confidence))
    extra2.metric("Severity", _fmt_reversinglabs_value(severity))
    extra3.metric("First Seen", _fmt_reversinglabs_value(first_seen))
    extra4.metric("Last Seen", _fmt_reversinglabs_value(last_seen))

    st.markdown("**Third-party reputation breakdown:**")
    if isinstance(detection_ratio, (int, float)) and isinstance(tp_total, int) and tp_total > 0:
        detected = int(tp_malicious) + int(tp_suspicious)
        st.caption(f"Detection summary: {detected}/{tp_total} sources flagged this IOC ({detection_ratio * 100:.1f}%).")
    rep1, rep2, rep3 = st.columns(3)
    rep1.metric("Malicious", _fmt_reversinglabs_value(tp_malicious))
    rep2.metric("Suspicious", _fmt_reversinglabs_value(tp_suspicious))
    rep3.metric("Clean", _fmt_reversinglabs_value(tp_clean))

    st.markdown("**Threat metadata:**")
    meta1, meta2 = st.columns(2)
    with meta1:
        st.markdown(f"- **Status:** {_fmt_reversinglabs_value(status)}")
        st.markdown(f"- **Threat Name:** {_fmt_reversinglabs_value(threat_name)}")
        st.markdown(f"- **Malware Family:** {_fmt_reversinglabs_value(malware_family)}")
        st.markdown(f"- **Campaign:** {_fmt_reversinglabs_value(campaign)}")
        st.markdown(f"- **Threat Actor:** {_fmt_reversinglabs_value(threat_actor)}")
    with meta2:
        st.markdown(f"- **File Type:** {_fmt_reversinglabs_value(file_type)}")
        st.markdown(f"- **MIME Type:** {_fmt_reversinglabs_value(mime_type)}")
        st.markdown(f"- **File Size (bytes):** {_fmt_reversinglabs_value(file_size)}")

    if tags:
        st.markdown(f"- **Tags:** {', '.join(str(v) for v in tags[:10])}")
    if categories:
        st.markdown(f"- **Categories:** {', '.join(str(v) for v in categories[:10])}")
    if ttps:
        st.markdown(f"- **TTPs:** {', '.join(str(v) for v in ttps[:10])}")
    if cves:
        st.markdown(f"- **CVEs:** {', '.join(str(v) for v in cves[:10])}")

    st.markdown("**Network and ownership context:**")
    ctx_col1, ctx_col2 = st.columns(2)
    with ctx_col1:
        st.markdown(f"- **Organization:** {_fmt_reversinglabs_value(src.get('organization'))}")
        st.markdown(f"- **Country:** {_fmt_reversinglabs_value(src.get('country'))}")
        st.markdown(f"- **AS Owner:** {_fmt_reversinglabs_value(src.get('as_owner'))}")
        st.markdown(f"- **Network:** {_fmt_reversinglabs_value(src.get('network'))}")
        st.markdown(f"- **ASN:** {_fmt_reversinglabs_value(src.get('asn'))}")
        st.markdown(f"- **Registry:** {_fmt_reversinglabs_value(src.get('registry'))}")
    with ctx_col2:
        st.markdown(f"- **Registrar:** {_fmt_reversinglabs_value(src.get('registrar'))}")
        st.markdown(f"- **Registrant:** {_fmt_reversinglabs_value(src.get('registrant'))}")
        st.markdown(f"- **Created:** {_fmt_reversinglabs_value(src.get('created'))}")
        st.markdown(f"- **Updated:** {_fmt_reversinglabs_value(src.get('updated'))}")
        st.markdown(f"- **Expires:** {_fmt_reversinglabs_value(src.get('expires'))}")

    st.markdown("**Related activity counts:**")
    a1, a2, a3 = st.columns(3)
    a1.metric("Related URLs", _fmt_reversinglabs_value(src.get("related_urls_count")))
    a2.metric("Resolutions", _fmt_reversinglabs_value(src.get("resolutions_count")))
    a3.metric("Downloaded Files", _fmt_reversinglabs_value(src.get("downloaded_files_count")))

    b1, b2, b3, b4, b5 = st.columns(5)
    b1.metric("Related IPs", _fmt_reversinglabs_value(src.get("related_ip_count")))
    b2.metric("Related Domains", _fmt_reversinglabs_value(src.get("related_domain_count")))
    b3.metric("Payload URLs", _fmt_reversinglabs_value(src.get("related_url_payload_count")))
    b4.metric("Related Hashes", _fmt_reversinglabs_value(src.get("related_hash_count")))
    b5.metric("File Names", _fmt_reversinglabs_value(src.get("related_file_name_count")))

    relation_samples = {
        "Related IP sample": src.get("related_ip_sample") or [],
        "Related domain sample": src.get("related_domain_sample") or [],
        "Payload URL sample": src.get("related_url_payload_sample") or [],
        "Related hash sample": src.get("related_hash_sample") or [],
        "Related file-name sample": src.get("related_file_name_sample") or [],
        "Related URLs endpoint sample": src.get("related_urls_sample") or [],
        "Resolutions sample": src.get("resolutions_sample") or [],
        "Downloaded files sample": src.get("downloaded_files_sample") or [],
    }
    compact_samples = {k: v for k, v in relation_samples.items() if v}
    if compact_samples:
        with st.expander("ReversingLabs related entity samples", expanded=False):
            for label, values in compact_samples.items():
                st.markdown(f"- **{label}:** {', '.join(str(x) for x in values[:10])}")

    highlights = src.get("highlights") or {}
    if highlights:
        with st.expander("ReversingLabs highlights (plain language)", expanded=False):
            sorted_keys = sorted(highlights.keys())
            for hk in sorted_keys[:20]:
                hv = highlights.get(hk)
                label = _labelize_reversinglabs_key(hk)
                if isinstance(hv, list):
                    st.markdown(f"- **{label}:** {', '.join(str(x) for x in hv)}")
                else:
                    st.markdown(f"- **{label}:** {_fmt_reversinglabs_value(hv)}")

    whois_fields = {
        "Registrar": src.get("registrar"),
        "Registrant": src.get("registrant"),
        "Organization": src.get("organization"),
        "Country": src.get("country"),
        "Created": src.get("created"),
        "Updated": src.get("updated"),
        "Expires": src.get("expires"),
        "ASN": src.get("asn"),
        "AS Owner": src.get("as_owner"),
        "Network": src.get("network"),
        "Registry": src.get("registry"),
    }
    whois_nameservers = src.get("nameservers") or []
    has_whois = any(whois_fields.values()) or bool(whois_nameservers)
    if has_whois:
        with st.expander("ReversingLabs WHOIS / Registration Context", expanded=False):
            for label, value in whois_fields.items():
                if value not in (None, "", [], {}):
                    st.markdown(f"- **{label}:** {_fmt_reversinglabs_value(value)}")
            if whois_nameservers:
                st.markdown(f"- **Nameservers:** {', '.join(str(v) for v in whois_nameservers)}")


def _render_silentpush_source(src: dict) -> None:
    if src.get("api_usage"):
        _render_api_usage_indicator(src, "Silent Push")
    else:
        _render_unavailable_api_usage_indicator(
            "Silent Push",
            "usage/quota amounts are not exposed by the current Explore/API family responses.",
        )

    if src.get("error"):
        st.warning(f"Silent Push error: {src.get('error')}")
        if src.get("hint"):
            st.caption(str(src.get("hint")))
        return

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


def _render_spur_source(src: dict) -> None:
    _render_api_usage_indicator(src, "Spur")

    if src.get("error"):
        st.warning(f"Spur error: {src.get('error')}")
        if src.get("hint"):
            st.caption(str(src.get("hint")))
        return

    verdict = src.get("spur_verdict") or "Unknown"
    risks = src.get("risks") or []
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Verdict", _fmt_simple_value(verdict))
    c2.metric("Risk Signals", len(risks))
    c3.metric("Tunnels", _fmt_simple_value(src.get("tunnel_count")))
    c4.metric("Proxies", _fmt_simple_value(src.get("proxy_count")))

    st.markdown("**Primary context:**")
    rows = [
        ("Infrastructure", src.get("infrastructure")),
        ("Organization", src.get("organization")),
        ("AS Organization", src.get("as_organization")),
        ("ASN", src.get("asn")),
        ("Country", src.get("country")),
        ("City", src.get("city")),
    ]
    for label, value in rows:
        if value not in (None, "", []):
            st.markdown(f"- **{label}:** {value}")

    if risks:
        st.markdown(f"- **Risks:** {', '.join(str(r) for r in risks[:10])}")

    with st.expander("Spur technical details", expanded=False):
        st.json({k: v for k, v in src.items() if k not in {"source"}})


def _source_by_name(detail: dict, source_name: str) -> dict:
    for src in detail.get("sources", []) or []:
        if src.get("source") == source_name:
            return src
    return {}


def _order_sources_for_display(sources: list) -> list:
    # Analyst-requested source order: ReversingLabs, Spur, Silent Push, then others.
    priority = {
        "reversinglabs": 0,
        "spur": 1,
        "silentpush": 2,
    }
    return sorted(
        sources,
        key=lambda s: (priority.get(str(s.get("source") or "").lower(), 99), str(s.get("source") or "")),
    )


def _collect_flagging_sources(detail: dict) -> list:
    flagged = []

    for src in detail.get("sources", []) or []:
        if src.get("error"):
            continue

        source_name = str(src.get("source") or "").strip()
        display_name = SOURCE_DISPLAY.get(source_name, source_name.replace("_", " ").title())

        if source_name == "virustotal":
            malicious = int(src.get("malicious") or 0)
            suspicious = int(src.get("suspicious") or 0)
            if malicious > 0 or suspicious > 0:
                flagged.append(f"{display_name}: malicious={malicious}, suspicious={suspicious}")
            continue

        if source_name == "alienvault":
            pulses = int(src.get("pulses") or 0)
            if pulses > 0:
                flagged.append(f"{display_name}: {pulses} threat pulse(s)")
            continue

        if source_name == "threatfox":
            matches = int(src.get("matches") or 0)
            confidence = int(src.get("max_confidence") or 0)
            if matches > 0:
                flagged.append(f"{display_name}: {matches} match(es), max confidence={confidence}/100")
            continue

        if source_name == "abuseipdb":
            abuse_score = int(src.get("abuse_score") or 0)
            if abuse_score > 0:
                flagged.append(f"{display_name}: abuse confidence={abuse_score}/100")
            continue

        if source_name == "silentpush":
            risk_score = int(src.get("sp_risk_score") or 0)
            verdict = str(src.get("sp_verdict") or "Unknown")
            listed = bool(src.get("is_listed")) or bool(src.get("threat_check_listed"))
            bph = str(src.get("bulletproof_hosting_likelihood") or "").lower()
            if listed or risk_score >= 50 or bph in {"suspected", "likely"}:
                suffix = []
                if listed:
                    suffix.append("listed")
                if bph in {"suspected", "likely"}:
                    suffix.append(f"bulletproof={bph}")
                suffix_txt = f" ({', '.join(suffix)})" if suffix else ""
                flagged.append(f"{display_name}: verdict={verdict}, risk score={risk_score}/100{suffix_txt}")
            continue

        if source_name == "spur":
            verdict = str(src.get("spur_verdict") or "Unknown")
            risks = len(src.get("risks") or [])
            tunnels = int(src.get("tunnel_count") or 0)
            proxies = int(src.get("proxy_count") or 0)
            if verdict in {"Malicious", "Suspicious"} or risks > 0 or tunnels > 0 or proxies > 0:
                flagged.append(
                    f"{display_name}: verdict={verdict}, risks={risks}, tunnels={tunnels}, proxies={proxies}"
                )
            continue

        if source_name == "reversinglabs":
            verdict = str(src.get("rl_verdict") or "Unknown")
            malicious = int(src.get("third_party_malicious") or 0)
            suspicious = int(src.get("third_party_suspicious") or 0)
            if verdict in {"Malicious", "Suspicious"} or malicious > 0 or suspicious > 0:
                flagged.append(
                    f"{display_name}: verdict={verdict}, third-party flags m={malicious} s={suspicious}"
                )
            continue

    return flagged


def _collect_quick_whois_summary(detail: dict) -> list:
    rl = _source_by_name(detail, "reversinglabs")
    sp = _source_by_name(detail, "silentpush")
    vt = _source_by_name(detail, "virustotal")
    abuse = _source_by_name(detail, "abuseipdb")

    def first_non_empty(*values):
        for v in values:
            if v not in (None, "", [], {}):
                return v
        return None

    org = first_non_empty(rl.get("organization"), rl.get("as_owner"), sp.get("as_org"), vt.get("as_owner"), abuse.get("isp"))
    country = first_non_empty(rl.get("country"), sp.get("country"), sp.get("country_code"), vt.get("country"), abuse.get("country"))
    asn = first_non_empty(rl.get("asn"), sp.get("asn_lookup"), sp.get("asn"), sp.get("answer_asn"), vt.get("asn"), abuse.get("asn"))
    network = first_non_empty(rl.get("network"), sp.get("subnet"), vt.get("network"))
    registrar = first_non_empty(rl.get("registrar"), sp.get("registrar"), vt.get("registrar"))
    registrant = first_non_empty(rl.get("registrant"), rl.get("organization"))
    created = first_non_empty(rl.get("created"), sp.get("registration_date"), vt.get("creation_date"))
    updated = first_non_empty(rl.get("updated"), sp.get("last_changed_date"))
    expires = first_non_empty(rl.get("expires"), sp.get("expiration_date"))
    whois_server = first_non_empty(sp.get("whois_server"))

    nameservers = first_non_empty(rl.get("nameservers"), sp.get("nameservers"))
    nameserver_txt = None
    if isinstance(nameservers, list) and nameservers:
        nameserver_txt = ", ".join(str(v) for v in nameservers[:4])

    summary_lines = []
    if org is not None:
        summary_lines.append(f"Owner/Org: {org}")
    if country is not None:
        summary_lines.append(f"Country: {country}")
    if asn is not None:
        summary_lines.append(f"ASN: {asn}")
    if network is not None:
        summary_lines.append(f"Network/Subnet: {network}")
    if registrar is not None:
        summary_lines.append(f"Registrar: {registrar}")
    if registrant is not None:
        summary_lines.append(f"Registrant: {registrant}")
    if created is not None:
        summary_lines.append(f"Created: {created}")
    if updated is not None:
        summary_lines.append(f"Updated: {updated}")
    if expires is not None:
        summary_lines.append(f"Expires: {expires}")
    if whois_server is not None:
        summary_lines.append(f"WHOIS Server: {whois_server}")
    if nameserver_txt is not None:
        summary_lines.append(f"Nameservers: {nameserver_txt}")

    return summary_lines


def _build_ioc_summary(detail: dict) -> str:
    verdict = str(detail.get("verdict") or "Unknown")
    score = detail.get("score", 0)
    reasons = detail.get("reasons") or ([detail.get("reason")] if detail.get("reason") else [])
    flagged_sources = _collect_flagging_sources(detail)

    if reasons:
        lead_reason = str(reasons[0]).strip().rstrip(".")
        if lead_reason:
            return f"{verdict} based on {lead_reason.lower()}."

    if flagged_sources:
        first_source = str(flagged_sources[0]).strip().rstrip(".")
        return f"{verdict} with score {score}/100, primarily influenced by {first_source}."

    return f"{verdict} with score {score}/100 based on the currently available provider evidence."


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
        enabled = st.checkbox(
            label,
            value=source_key in DEFAULT_ENABLED_SOURCES,
            key=f"source_enabled_{source_key}",
        )
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
        workers = st.slider("Concurrent workers", 1, 20, 10,
                    help="Higher = faster but increases API pressure (recommended: 8-12 for paid tiers)")
        delay   = st.slider("Delay between starts (s)", 0.01, 3.0, 0.01, 0.01,
                    help="Minimum pause between IOC starts")
        jitter  = st.slider("Jitter (s)", 0.0, 1.0, 0.0, 0.01,
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
        ("🧪", "ReversingLabs", "IPs · Domains · URLs · Hashes"),
        ("🧭", "Spur",          "IPs only"),
        ("🛰️", "Silent Push",   "IPs · Domains · URL hostnames"),
        ("🔬", "VirusTotal",    "IPs · Domains · URLs · Hashes"),
        ("👾", "AlienVault OTX","IPs · Domains · URLs · Hashes"),
        ("🕷️", "ThreatFox",     "IPs · Domains · URLs · Hashes"),
        ("🚨", "AbuseIPDB",     "IPs only"),
    ]
    health = api_health()
    for col, (icon, name, coverage) in zip(cols, source_info):
        ok = health.get(name, False)
        color = "#16a34a" if ok else "#dc2626"
        status = "✓ Connected" if ok else "✗ No API Key"
        source_color = SOURCE_BRAND_CARD.get(name, "#111827")
        col.markdown(f"""
        <div class="kpi-card">
            <div style="font-size:2rem;">{icon}</div>
            <div style="font-weight:700; margin-top:.4rem; color:{source_color};">{name}</div>
            <div style="color:#374151; font-size:.78rem; margin-top:.2rem;">{coverage}</div>
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
    csv_output = tl.format_results(results, "csv")
    st.download_button(
        "⬇️ Export CSV", csv_output,
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
    reasons = detail.get("reasons") or ([detail.get("reason")] if detail.get("reason") else [])
    flagged_sources = _collect_flagging_sources(detail)
    quick_whois = _collect_quick_whois_summary(detail)
    summary_text = _build_ioc_summary(detail)

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

    st.markdown("**Assessment overview:**")
    ov1, ov2, ov3 = st.columns(3)
    ov1.metric("Final Verdict", str(v))
    ov2.metric("Risk Score", f"{detail.get('score', 0)}/100")
    ov3.metric("IOC Type", str((detail.get('type') or '—').upper()))

    if flagged_sources:
        st.markdown("- **Key contributing sources:**")
        for line in flagged_sources[:5]:
            st.markdown(f"  - {line}")

    if quick_whois:
        st.markdown("- **WHOIS / network context:**")
        for line in quick_whois[:8]:
            st.markdown(f"  - {line}")

    if reasons:
        st.markdown("**Assessment rationale:**")
        for r in reasons:
            st.markdown(f"- {r}")

    st.markdown("---")

    # Per-source breakdown
    for src in _order_sources_for_display(detail.get("sources", []) or []):
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

            if src_name == "silentpush":
                _render_silentpush_source(src)
                continue

            if src_name == "reversinglabs":
                _render_reversinglabs_source(src)
                continue

            if src_name == "spur":
                _render_spur_source(src)
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
