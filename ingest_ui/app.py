import os
import time
import requests
import streamlit as st
import pandas as pd

API_URL = os.getenv("API_URL", "http://graphiti-worker:8000")

st.set_page_config(page_title="TIIS v2.1", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")

# ==========================================
# CLASSIFIED THEME
# ==========================================
st.markdown("""
<style>
#MainMenu, footer, header {visibility: hidden;}
.stApp {background-color: #0b0f14; color: #c9d1d9; font-family: Consolas, 'Courier New', monospace;}
div[data-testid='stHeader'] {background: transparent;}
.classbanner {background:#7a0000; color:#ffffff; text-align:center; font-weight:bold;
                padding:6px 0; letter-spacing:3px; border:1px solid #ff5555; margin-bottom:6px;}
.agencyhead {text-align:center; color:#8b949e; letter-spacing:2px; margin:2px 0;}
.sysTitle {text-align:center; color:#58a6ff; letter-spacing:4px; font-weight:700; margin:6px 0 14px 0;}
div[data-testid='stTabs'] button {font-family: Consolas, monospace; letter-spacing:1px;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="classbanner">OSINT // TLP:AMBER // ORCON</div>', unsafe_allow_html=True)
st.markdown('<div class="agencyhead"> VIMES NIGHTWATCHER </div>', unsafe_allow_html=True)
st.markdown('<div class="sysTitle">TACTICAL INTELLIGENCE INGESTION SYSTEM (TIIS) v2.1</div>', unsafe_allow_html=True)

tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "01 // SYSTEM OVERVIEW",
    "02 // DOCUMENT INGESTION",
    "03 // OSINT COLLECTION",
    "04 // AUTOMATED FEEDS",
    "05 // AUDIT LOG",
    "06 // GRAPH ENRICHMENT",
    "07 // RAW INTEL PASTE",
])

# ==========================================
# HELPERS
# ==========================================
def api_get(path, **kw):
    return requests.get(f"{API_URL}{path}", timeout=15, **kw)

def show_job_progress(jobs):
    for j in jobs:
        try:
            p = api_get(f"/progress/{j['job_id']}").json()
        except Exception:
            continue
        total = p.get("total") or 1
        frac = min((p.get("current") or 0) / total, 1.0)
        label = f"{j['filename']} — {p.get('current', 0)}/{p.get('total', 0)} [{p.get('status', '?')}]"
        if p.get("status") == "error":
            st.error(f"{label}: {p.get('error')}")
        else:
            st.progress(frac, text=label)

# ==========================================
# TAB 01: SYSTEM OVERVIEW + JOB MONITOR
# ==========================================
with tab1:
    st.subheader("SYSTEM OVERVIEW // LIVE METRICS")
    try:
        s = api_get("/stats").json()
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("NODES", s.get("nodes", 0))
        c2.metric("EDGES", s.get("edges", 0))
        c3.metric("EPISODES", s.get("episodes", 0))
        c4.metric("ACTIVE JOBS", s.get("active_jobs", 0))
    except Exception as e:
        st.error(f"Backend unreachable: {e}")

    st.markdown("---")
    st.subheader("JOB MONITOR // ALL INGESTION & ENRICHMENT TASKS")
    st.caption("Tracks jobs from UI uploads, URL collection, text paste, Hermes/OpenWebUI MCP writes, and enrichment runs.")

    if st.button("REFRESH JOB LIST", key="refresh_jobs"):
        st.rerun()

    try:
        jobs_data = api_get("/jobs", params={"limit": 50}).json()
        jobs = jobs_data.get("jobs", [])

        if not jobs:
            st.info("No jobs tracked yet.")
        else:
            rows = []
            for j in jobs:
                total = j.get("total", 0) or 1
                pct = min((j.get("current", 0) / total) * 100, 100)

                src = j.get("source", "ui")
                src_label = {"ui": "🖥️ UI", "mcp": "🤖 MCP (Hermes/OpenWebUI)", "auto": "⚡ Auto"}.get(src, src)

                status = j.get("status", "unknown")
                status_icon = {"processing": "🔄", "complete": "✅", "error": "❌"}.get(status, "❓")

                rows.append({
                    "Status": f"{status_icon} {status}",
                    "Source": src_label,
                    "Name": j.get("filename", "unknown"),
                    "Progress": f"{j.get('current', 0)}/{j.get('total', 0)} ({pct:.0f}%)",
                    "Started": j.get("created_at", "N/A")[:19].replace("T", " "),
                })

            df = pd.DataFrame(rows)
            st.dataframe(df, width='stretch', hide_index=True)

            errors = [j for j in jobs if j.get("status") == "error" and j.get("error")]
            if errors:
                st.markdown("#### ⚠️ Recent Errors")
                for e in errors[:5]:
                    st.error(f"**{e.get('filename')}**: {e.get('error')}")

    except Exception as e:
        st.warning(f"Could not load job list: {e}")

    st.markdown("---")
    colA, colB = st.columns(2)
    with colA:
        st.markdown("#### RECENT EPISODES")
        try:
            rec = api_get("/recent", params={"limit": 10}).json().get("recent_episodes", [])
            if rec:
                st.dataframe(pd.DataFrame(rec), width='stretch')
            else:
                st.info("Empty.")
        except Exception:
            st.info("Empty.")
    with colB:
        st.markdown("#### RELATIONSHIP SAMPLE")
        try:
            rel = api_get("/relationships", params={"limit": 15}).json().get("relationships", [])
            if rel:
                st.dataframe(pd.DataFrame(rel), width='stretch')
            else:
                st.info("Empty.")
        except Exception:
            st.info("Empty.")

# ==========================================
# TAB 02: DOCUMENT INGESTION
# ==========================================
with tab2:
    st.subheader("DOCUMENT INGESTION // BATCH UPLOAD")
    source_type = st.text_input("SOURCE CLASSIFICATION", value="Manual Upload")
    custom_prompt = st.text_area("CUSTOM EXTRACTION DIRECTIVES (optional)", value="")
    uploaded = st.file_uploader("SELECT TARGET DOCUMENTS (PDF / TXT / MD / HTML / JSON)",
                                accept_multiple_files=True, type=["pdf", "txt", "md", "html", "json"])
    force = st.checkbox("AUTHORIZE FORCE RE-INGEST (bypass duplicate check)", value=False)
    auto_enrich = st.checkbox("AUTO-ENRICH AFTER INGEST (LLM link discovery)", value=False)

    if st.button("INITIATE PROCESSING", type="primary"):
        if not uploaded:
            st.warning("No documents selected.")
        else:
            files_payload = [("files", (f.name, f.getvalue(), "application/octet-stream")) for f in uploaded]
            r = requests.post(
                f"{API_URL}/upload", files=files_payload,
                data={"source_type": source_type, "custom_prompt": custom_prompt,
                      "force": str(force).lower(), "auto_enrich": str(auto_enrich).lower()},
                timeout=30
            )
            if r.status_code == 409:
                st.error(r.json().get("detail", "Duplicate detected."))
            elif r.status_code == 200:
                st.session_state["last_jobs"] = r.json().get("jobs", [])
                st.success(r.json().get("message", "Queued."))
            else:
                st.error(f"Upload failed: {r.text}")

    if st.session_state.get("last_jobs"):
        st.markdown("#### LIVE JOB QUEUE")
        show_job_progress(st.session_state["last_jobs"])
        if st.button("REFRESH STATUS"):
            st.rerun()

# ==========================================
# TAB 03: OSINT COLLECTION
# ==========================================
with tab3:
    st.subheader("OSINT COLLECTION // URL HARVEST")
    url = st.text_input("TARGET URL")
    url_type = st.text_input("CLASSIFICATION", value="Web Article")
    force_url = st.checkbox("FORCE RE-INGEST", value=False)

    if st.button("COLLECT & INGEST", type="primary"):
        if not url:
            st.warning("Enter a URL.")
        else:
            r = requests.post(
                f"{API_URL}/ingest-url",
                data={"url": url, "source_type": url_type, "force": str(force_url).lower()},
                timeout=60
            )
            if r.status_code == 409:
                st.error(r.json().get("detail", "Duplicate URL."))
            elif r.status_code == 200:
                job = r.json()
                st.session_state["last_url_job"] = [{"filename": url, "job_id": job["job_id"]}]
                st.success(job.get("message", "Queued."))
            else:
                st.error(f"Collection failed: {r.text}")

    if st.session_state.get("last_url_job"):
        show_job_progress(st.session_state["last_url_job"])

# ==========================================
# TAB 04: AUTOMATED FEEDS
# ==========================================
with tab4:
    st.subheader("AUTOMATED FEEDS // RSS POLLING (30 MIN)")
    with st.form("add_feed"):
        name = st.text_input("FEED NAME")
        feed_url = st.text_input("FEED URL")
        if st.form_submit_button("REGISTER FEED"):
            r = requests.post(f"{API_URL}/sources", data={"name": name, "url": feed_url}, timeout=15)
            if r.ok:
                st.success("Feed registered.")
                st.rerun()
            else:
                st.error(r.text)

    try:
        feeds = api_get("/sources").json().get("rss_feeds", [])
    except Exception:
        feeds = []
    if feeds:
        for f in feeds:
            c1, c2 = st.columns([6, 1])
            c1.markdown(f"**{f['name']}** — `{f['url']}`")
            if c2.button("TERMINATE", key=f"kill_{f['url']}"):
                requests.delete(f"{API_URL}/sources", params={"url": f["url"]}, timeout=15)
                st.rerun()
    else:
        st.info("No feeds registered.")

# ==========================================
# TAB 05: AUDIT LOG
# ==========================================
with tab5:
    st.subheader("AUDIT LOG // CHAIN OF CUSTODY")
    try:
        h = api_get("/history").json()
    except Exception:
        h = {"files": [], "urls": []}
    st.markdown("#### DOCUMENTS")
    df = pd.DataFrame(h.get("files", []))
    if not df.empty:
        st.dataframe(df, width='stretch')
    else:
        st.info("No documents ingested.")
    st.markdown("#### URLS")
    df2 = pd.DataFrame(h.get("urls", []))
    if not df2.empty:
        st.dataframe(df2, width='stretch')
    else:
        st.info("No URLs ingested.")

# ==========================================
# TAB 06: GRAPH ENRICHMENT
# ==========================================
with tab6:
    st.subheader("GRAPH ENRICHMENT // LINK DISCOVERY")
    st.caption("Run LLM passes over ingested record nodes to surface hidden links: "
               "attribute hubs (ideology / TTP / weapons / claimed-by), narrative episodes "
               "(Graphiti entity resolution), and cross-layer SAME_AS stitching.")

    try:
        labels = api_get("/record-labels").json().get("labels", [])
    except Exception:
        labels = []

    if not labels:
        st.info("No ingested record datasets found. Ingest a JSON file first (Tab 02).")
    else:
        options = ["— ALL DATASETS —"] + labels
        sel = st.selectbox("TARGET DATASET (record label)", options)
        c1, c2, c3 = st.columns(3)
        with c1:
            run_hubs = st.checkbox("Attribute hubs (ideology / TTP / weapons / claimed-by)", value=True)
        with c2:
            run_narrative = st.checkbox("Narrative layer (Graphiti episodes, slow)", value=False)
        with c3:
            run_stitch = st.checkbox("Stitch layers (SAME_AS edges)", value=True)

        if st.button("EXECUTE ENRICHMENT", type="primary"):
            targets = labels if sel == "— ALL DATASETS —" else [sel]
            jobs = []
            for t in targets:
                r = requests.post(
                    f"{API_URL}/enrich",
                    data={"label": t,
                          "run_hubs": str(run_hubs).lower(),
                          "run_narrative": str(run_narrative).lower(),
                          "run_stitch": str(run_stitch).lower()},
                    timeout=30,
                )
                if r.status_code == 200:
                    jobs.append({"label": t, "job_id": r.json()["job_id"]})
            st.session_state["enrich_jobs"] = jobs
            st.success(f"Queued {len(jobs)} enrichment job(s).")

        for j in st.session_state.get("enrich_jobs", []):
            p = api_get(f"/progress/{j['job_id']}").json()
            total = p.get("total") or 1
            st.progress(min(p.get("current", 0) / total, 1.0),
                        text=f"{j['label']} — {p.get('current', 0)}/{p.get('total', 0)} [{p.get('status')}]")

# ==========================================
# TAB 07: RAW INTEL PASTE
# ==========================================
with tab7:
    st.subheader("RAW INTELLIGENCE // DIRECT TEXT INGESTION")
    st.caption("Paste large blocks of raw text, intercepts, transcripts, or field reports directly into the narrative layer. "
               "The system will chunk and extract entities in the background.")

    c1, c2 = st.columns(2)
    with c1:
        source_name = st.text_input("SOURCE IDENTIFIER (e.g., 'SIGINT Intercept 44-A', 'Field Report 09')", value="Raw Paste")
    with c2:
        source_type_txt = st.text_input("CLASSIFICATION", value="Raw Intelligence")

    raw_text = st.text_area("PASTE INTELLIGENCE HERE", height=450, placeholder="Paste unstructured text, transcripts, or large reports here...")

    if raw_text:
        st.caption(f"Loaded: **{len(raw_text):,}** characters | approx **{len(raw_text.split()):,}** words")

    if st.button("SUBMIT TO GRAPH", type="primary"):
        if not raw_text.strip():
            st.warning("No text provided.")
        else:
            try:
                r = requests.post(
                    f"{API_URL}/ingest-text",
                    json={"text": raw_text, "source_type": source_type_txt, "source_name": source_name},
                    timeout=30
                )
                if r.ok:
                    data = r.json()
                    job_id = data.get("job_id")
                    if job_id:
                        st.session_state["raw_text_job"] = [{"filename": source_name, "job_id": job_id}]
                        st.success(f"Queued for background extraction: {data.get('message')}")
                    else:
                        st.success(data.get("message", "Submitted successfully."))
                else:
                    st.error(f"Submission failed: {r.text}")
            except Exception as e:
                st.error(f"Network error: {e}")

    if st.session_state.get("raw_text_job"):
        st.markdown("#### EXTRACTION PROGRESS")
        show_job_progress(st.session_state["raw_text_job"])
        if st.button("REFRESH STATUS", key="refresh_raw"):
            st.rerun()
