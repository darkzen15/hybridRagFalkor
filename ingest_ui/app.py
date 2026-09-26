import os
import time
import streamlit as st
import requests
import json

API_URL = os.getenv("API_URL", "http://graphiti-worker:8000")

# ==========================================
# 1. CLANDESTINE UI STYLING (CSS INJECTION)
# ==========================================
st.set_page_config(page_title="TIIS - Secure Terminal", layout="wide", initial_sidebar_state="collapsed")

st.markdown("""
<style>
    /* Global Terminal Aesthetic */
    .stApp {
        background-color: #0b1120;
        color: #cbd5e1;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }

    /* Official Classification Banner */
    .classification-banner {
        background-color: #991b1b;
        color: #ffffff;
        text-align: center;
        padding: 6px;
        font-weight: bold;
        font-size: 13px;
        letter-spacing: 2px;
        margin-bottom: 20px;
        border: 1px solid #7f1d1d;
    }

    /* Header Styling */
    .gov-header {
        border-bottom: 2px solid #334155;
        padding-bottom: 15px;
        margin-bottom: 30px;
    }
    .gov-title {
        color: #f8fafc;
        font-size: 22px;
        font-weight: 600;
        letter-spacing: 1px;
        text-transform: uppercase;
    }
    .gov-subtitle {
        color: #64748b;
        font-size: 11px;
        letter-spacing: 2px;
        text-transform: uppercase;
        margin-bottom: 5px;
    }
    .status-text { font-size: 11px; color: #64748b; letter-spacing: 1px; }
    .status-ok { color: #22c55e; font-weight: bold; }

    /* Strict Data Tables & Metrics */
    .stMetric {
        background-color: #1e293b;
        padding: 15px;
        border-radius: 0;
        border-left: 3px solid #3b82f6;
        box-shadow: none;
    }
    .stDataFrame { border: 1px solid #334155; border-radius: 0; }
    .stDataFrame thead { background-color: #0f172a; }

    /* Bureaucratic Tabs */
    button[kind="secondary"] {
        background-color: transparent !important;
        color: #64748b !important;
        border: none !important;
        border-bottom: 2px solid transparent !important;
        border-radius: 0 !important;
        font-size: 12px !important;
        letter-spacing: 1px !important;
        text-transform: uppercase !important;
        padding: 10px 15px !important;
    }
    button[kind="secondary"][aria-selected="true"] {
        color: #f8fafc !important;
        border-bottom: 2px solid #3b82f6 !important;
    }

    /* Strict Buttons */
    .stButton > button {
        background-color: #1e293b !important;
        color: #f8fafc !important;
        border: 1px solid #475569 !important;
        border-radius: 0 !important;
        text-transform: uppercase !important;
        font-size: 12px !important;
        letter-spacing: 1px !important;
        padding: 8px 16px !important;
    }
    .stButton > button:hover {
        background-color: #334155 !important;
        border-color: #94a3b8 !important;
    }

    /* Hide Streamlit Footer & Menu */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# ==========================================
# 2. OFFICIAL HEADER & STATUS BAR
# ==========================================
st.markdown('<div class="classification-banner">UNOFFICIAL // UNCLASS // OPEN SOURCE // ORCON</div>', unsafe_allow_html=True)

st.markdown("""
<div class="gov-header">
    <div class="gov-subtitle">Long Term Intelligence Correlation Project</div>
    <div class="gov-title">TACTICAL INTELLIGENCE INGESTION SYSTEM (TIIS) v2.1</div>
    <div style="display: flex; justify-content: space-between; margin-top: 15px;" class="status-text">
        <span>[FALKORDB] <span class="status-ok">● ONLINE</span></span>
        <span>[OLLAMA] <span class="status-ok">● CONNECTED</span></span>
        <span>[GRAPHITI] <span class="status-ok">● ACTIVE</span></span>
        <span>[USER] <span style="color:#f8fafc">ADMINISTRATOR</span></span>
    </div>
</div>
""", unsafe_allow_html=True)

# ==========================================
# 3. SECURE TAB NAVIGATION
# ==========================================
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "01 // SYSTEM OVERVIEW",
    "02 // DOCUMENT INGESTION",
    "03 // OSINT COLLECTION",
    "04 // AUTOMATED FEEDS",
    "05 // AUDIT LOG"
])

# ==========================================
# TAB 1: SYSTEM OVERVIEW
# ==========================================
with tab1:
    st.header(">> SYSTEM METRICS")
    try:
        stats = requests.get(f"{API_URL}/stats", timeout=30).json()
        col1, col2, col3, col4 = st.columns(4)
        with col1: st.metric("NODES", stats.get("nodes", 0))
        with col2: st.metric("EDGES", stats.get("edges", 0))
        with col3: st.metric("EPISODES", stats.get("episodes", 0))
        with col4: st.metric("ACTIVE JOBS", stats.get("active_jobs", 0))
    except Exception as e: st.error(f"Telemetry failure: {e}")

    st.divider()
    st.subheader(">> RECENT TELEMETRY")
    try:
        recent = requests.get(f"{API_URL}/recent?limit=10", timeout=5).json().get("recent_episodes", [])
        for ep in recent:
            with st.expander(f"📄 {ep.get('name', 'UNKNOWN')}"):
                st.write(f"**DESCRIPTION:** {ep.get('description', 'N/A')}")
                st.write(f"**TIMESTAMP:** {ep.get('time', 'UNKNOWN')}")
    except Exception as e: st.error(f"Telemetry failure: {e}")

    st.divider()
    st.subheader(">> ENTITY & RELATIONSHIP SAMPLE")
    try:
        entities = requests.get(f"{API_URL}/entities?limit=15", timeout=5).json().get("entities", [])
        if entities: st.write(", ".join([e.get("name", "?") for e in entities]))
    except: pass
    try:
        rels = requests.get(f"{API_URL}/relationships?limit=10", timeout=5).json().get("relationships", [])
        for r in rels: st.write(f"**{r.get('source')}** → {r.get('relationship')} → **{r.get('target')}**")
    except: pass

# ==========================================
# TAB 2: DOCUMENT INGESTION
# ==========================================
with tab2:
    st.header(">> DOCUMENT INGESTION PROTOCOL")
    st.caption("Supported formats: PDF, TXT, JSON, MD. Batch processing enabled.")

    uploaded_files = st.file_uploader("SELECT TARGET DOCUMENTS", type=["pdf", "txt", "json", "md"], accept_multiple_files=True)
    source_type = st.selectbox("SOURCE CLASSIFICATION", ["OSINT", "CTI/MISP", "HUMINT", "INTERNAL REPORT"], key="file_source")
    custom_prompt = st.text_area("CUSTOM EXTRACTION DIRECTIVES (OPTIONAL)", placeholder="e.g., Focus on extracting IP addresses, CVEs, and MITRE ATT&CK TTPs.", height=80, key="file_prompt")

    if st.button("INITIATE PROCESSING"):
        if uploaded_files:
            files_payload = [("files", (f.name, f.getvalue(), f.type)) for f in uploaded_files]
            data = {"source_type": source_type, "custom_prompt": custom_prompt, "force": "false"}

            resp = requests.post(f"{API_URL}/upload", files=files_payload, data=data)

            if resp.status_code == 409:
                st.session_state['dup_files_payload'] = files_payload
                st.session_state['dup_files_data'] = {"source_type": source_type, "custom_prompt": custom_prompt, "force": "true"}
                st.warning(f"⚠️ CONFLICT DETECTED: {resp.json()['detail']}. AUTHORIZE FORCE RE-INGESTION?")
                if st.button("AUTHORIZE FORCE RE-INGEST"): st.rerun()
            elif resp.status_code == 200:
                res = resp.json()
                jobs = res["jobs"]
                st.info(f"✅ SUCCESSFULLY QUEUED {len(jobs)} DOCUMENTS.")

                job_ui_elements = []
                for job in jobs:
                    st.markdown(f"** {job['filename']}**")
                    col1, col2 = st.columns([3, 1])
                    with col1: bar = st.progress(0)
                    with col2: txt = st.empty()
                    job_ui_elements.append({"job_id": job["job_id"], "total": job["total_chunks"], "bar": bar, "txt": txt})

                st.divider()
                st.subheader(">> LIVE PROCESSING STATUS")
                while True:
                    all_done = True
                    for item in job_ui_elements:
                        p = requests.get(f"{API_URL}/progress/{item['job_id']}", timeout=5).json()
                        pct = int((p["current"] / item["total"]) * 100) if item["total"] > 0 else 0
                        item["bar"].progress(pct)
                        if p["status"] == "processing":
                            all_done = False; item["txt"].info(f"⏳ {p['current']}/{item['total']}")
                        elif p["status"] == "complete": item["txt"].success("✅ COMPLETE")
                        elif p["status"] == "error": item["txt"].error(f"❌ FAILED")
                    if all_done:
                        st.success("🎉 ALL DOCUMENTS PROCESSED SUCCESSFULLY."); break
                    time.sleep(1)
            else: st.error(f"INGESTION FAILED: {resp.text}")
        else: st.warning("NO DOCUMENTS SELECTED.")

    if 'dup_files_payload' in st.session_state and 'dup_files_data' in st.session_state:
        st.info("EXECUTING FORCE RE-INGESTION...")
        resp = requests.post(f"{API_URL}/upload", files=st.session_state['dup_files_payload'], data=st.session_state['dup_files_data'])
        if resp.status_code == 200: st.success("RE-INGESTION COMPLETE."); st.rerun()
        else: st.error(f"FORCE INGESTION FAILED: {resp.text}")
        del st.session_state['dup_files_payload']; del st.session_state['dup_files_data']

# ==========================================
# TAB 3: OSINT COLLECTION
# ==========================================
with tab3:
    st.header(">> OSINT COLLECTION PROTOCOL")
    st.caption("Extract and ingest main article content from target URLs.")

    url_input = st.text_input("TARGET URL", placeholder="https://example.com/threat-report")
    url_source_type = st.selectbox("SOURCE CLASSIFICATION", ["OSINT", "NEWS ARTICLE", "RESEARCH PAPER", "BLOG POST"], key="url_source")
    url_custom_prompt = st.text_area("CUSTOM EXTRACTION DIRECTIVES (OPTIONAL)", placeholder="e.g., Only extract entities related to Russian threat actors.", height=80, key="url_prompt")

    if st.button("INITIATE COLLECTION"):
        if url_input:
            data = {"url": url_input, "source_type": url_source_type, "custom_prompt": url_custom_prompt, "force": "false"}
            resp = requests.post(f"{API_URL}/ingest-url", data=data)

            if resp.status_code == 409:
                st.session_state['dup_url_data'] = {"url": url_input, "source_type": url_source_type, "custom_prompt": url_custom_prompt, "force": "true"}
                st.warning(f"⚠️ CONFLICT DETECTED: {resp.json()['detail']}. AUTHORIZE FORCE RE-INGESTION?")
                if st.button("AUTHORIZE FORCE RE-INGEST"): st.rerun()
            elif resp.status_code == 200:
                res = resp.json()
                job_id, total = res["job_id"], res["total_chunks"]
                st.info(f"TARGET SPLIT INTO {total} CHUNKS. PROCESSING...")
                bar, txt = st.progress(0), st.empty()
                while True:
                    p = requests.get(f"{API_URL}/progress/{job_id}", timeout=5).json()
                    pct = int((p["current"] / total) * 100) if total > 0 else 0
                    bar.progress(pct)
                    if p["status"] == "complete": txt.success("✅ COMPLETE"); break
                    elif p["status"] == "error": txt.error(f"❌ FAILED: {p.get('error')}"); break
                    else: txt.info(f"⏳ CHUNK {p['current']}/{total}...")
                    time.sleep(0.5)
            else: st.error(f"COLLECTION FAILED: {resp.text}")
        else: st.warning("NO URL PROVIDED.")

    if 'dup_url_data' in st.session_state:
        st.info("EXECUTING FORCE RE-INGESTION...")
        resp = requests.post(f"{API_URL}/ingest-url", data=st.session_state['dup_url_data'])
        if resp.status_code == 200: st.success("RE-INGESTION COMPLETE."); st.rerun()
        else: st.error(f"FORCE INGESTION FAILED: {resp.text}")
        del st.session_state['dup_url_data']

# ==========================================
# TAB 4: AUTOMATED FEEDS
# ==========================================
with tab4:
    st.header(">> AUTOMATED FEED MANAGEMENT")
    st.caption("System polls registered RSS/URL feeds every 30 minutes.")
    try: sources = requests.get(f"{API_URL}/sources").json().get("rss_feeds", [])
    except: st.error("API CONNECTION FAILURE."); sources = []

    col1, col2 = st.columns([2, 1])
    with col1:
        new_name = st.text_input("FEED DESIGNATION")
        new_url = st.text_input("FEED URL")
    with col2:
        st.write(""); st.write("")
        if st.button("REGISTER FEED"):
            if new_name and new_url:
                requests.post(f"{API_URL}/sources", data={"name": new_name, "url": new_url})
                st.rerun()

    st.divider()
    st.subheader(">> ACTIVE FEEDS")
    for feed in sources:
        col_a, col_b = st.columns([4, 1])
        with col_a: st.write(f"**{feed['name']}**\n`{feed['url']}`")
        with col_b:
            if st.button("TERMINATE", key=feed['url']):
                requests.delete(f"{API_URL}/sources", params={"url": feed['url']}); st.rerun()

# ==========================================
# TAB 5: AUDIT LOG
# ==========================================
with tab5:
    st.header(">> INGESTION AUDIT LOG")
    st.caption("Persistent record of all processed intelligence.")

    try:
        history = requests.get(f"{API_URL}/history", timeout=5).json()
        col1, col2 = st.columns(2)

        with col1:
            st.subheader(" DOCUMENTS")
            if history.get("files"):
                file_data = [{"FILENAME": f["name"], "CLASSIFICATION": f["type"], "CHUNKS": f["chunks"], "TIMESTAMP": f["timestamp"].split("T")[0]} for f in history["files"]]
                st.dataframe(file_data, use_container_width=True, hide_index=True)
            else: st.info("NO DOCUMENTS IN LOG.")

        with col2:
            st.subheader("🌐 URLS")
            if history.get("urls"):
                url_data = [{"URL": u["url"], "CLASSIFICATION": u["type"], "CHUNKS": u["chunks"], "TIMESTAMP": u["timestamp"].split("T")[0]} for u in history["urls"]]
                st.dataframe(url_data, use_container_width=True, hide_index=True)
            else: st.info("NO URLS IN LOG.")
    except Exception as e: st.error(f"AUDIT LOG RETRIEVAL FAILED: {e}")
