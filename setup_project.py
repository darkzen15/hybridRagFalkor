import os
import shutil

# Clean up old code folders to prevent stale files
for folder in ["graphiti_app", "ingest_ui"]:
    if os.path.exists(folder):
        shutil.rmtree(folder)
        print(f"Cleaned up old {folder} folder.")

files = {
    "docker-compose.yml": """services:
  open-webui:
    image: ghcr.io/open-webui/open-webui:main
    container_name: openwebui
    ports:
      - "8080:8080"
    environment:
      - OLLAMA_BASE_URL=http://host.docker.internal:11434
      - WEBUI_AUTH=false
      - ENABLE_RAG=true
    volumes:
      - ./openwebui_data:/app/backend/data
    extra_hosts:
      - "host.docker.internal:host-gateway"
    restart: unless-stopped

  falkordb:
    image: falkordb/falkordb:latest
    container_name: falkordb
    ports:
      - "6379:6379"
      - "3000:3000"
    volumes:
      - ./falkordb_data:/var/lib/falkordb/data
    environment:
      - REDIS_ARGS=--appendonly yes --appendfsync everysec --save 60 1000
    healthcheck:
      test: ["CMD", "redis-cli", "-p", "6379", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5
    restart: unless-stopped

  graphiti-worker:
    build:
      context: ./graphiti_app
      dockerfile: Dockerfile
    container_name: graphiti-worker
    ports:
      - "8000:8000"
    environment:
      - OPENAI_API_KEY=sk-ollama-local-dummy-key
      - OLLAMA_BASE_URL=http://host.docker.internal:11434/v1
      - FALKORDB_HOST=falkordb
      - FALKORDB_PORT=6379
      - FALKORDB_DATABASE=threat_intel
      - LLM_MODEL=qwen2.5:14b
      - EMBEDDING_MODEL=nomic-embed-text:latest
    volumes:
      - ./graphiti_app:/app
      - ./ingest_config:/app/config
    extra_hosts:
      - "host.docker.internal:host-gateway"
    depends_on:
      falkordb:
        condition: service_healthy
    restart: unless-stopped

  ingest-ui:
    build:
      context: ./ingest_ui
      dockerfile: Dockerfile
    container_name: ingest-ui
    ports:
      - "8501:8501"
    environment:
      - API_URL=http://graphiti-worker:8000
    volumes:
      - ./ingest_ui:/app
    depends_on:
      - graphiti-worker
    restart: unless-stopped
""",

    "graphiti_app/Dockerfile": """FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
""",

    "graphiti_app/requirements.txt": """fastapi
uvicorn
graphiti-core[falkordb]
pydantic
httpx
pypdf
apscheduler
python-multipart
trafilatura
""",

    "graphiti_app/main.py": '''import os
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks
from httpx import AsyncClient
from pypdf import PdfReader
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from pydantic import BaseModel
import trafilatura

from graphiti_core import Graphiti
from graphiti_core.driver.falkordb_driver import FalkorDriver
from graphiti_core.llm_client.config import LLMConfig
from graphiti_core.llm_client.openai_generic_client import OpenAIGenericClient
from graphiti_core.embedder.openai import OpenAIEmbedder, OpenAIEmbedderConfig
from graphiti_core.nodes import EpisodeType

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- HIGH FIDELITY PROMPT ---
DEFAULT_THREAT_INTEL_PROMPT = """
[SYSTEM INSTRUCTION]: You are a Threat Intelligence extraction engine.
When extracting relationships (edges), you MUST use specific, high-fidelity predicates.
Allowed edge types: USES, TARGETS, DEPLOYED_BY, ORIGINATES_FROM, MITIGATES, EXPLOITS, ATTRIBUTED_TO, PRECEDES_IN_TIME, SAME_YEAR_ATTACK, REQUIRES, REFERENCES_WORK_BY, IS_DISTRIBUTED_FORM_OF, HAS_BACKUP_CONFIGURATION, PERFORMS_ROLE_WITH, HAS_GUIDELINE, PUBLISHES_GUIDE, CONTAINS.
NEVER use generic edges like MENTIONS, RELATES_TO, or IS_ASSOCIATED_WITH.
"""

# --- 1. FalkorDB Driver Setup ---
driver = FalkorDriver(
    host=os.getenv("FALKORDB_HOST", "falkordb"),
    port=int(os.getenv("FALKORDB_PORT", 6379)),
    database=os.getenv("FALKORDB_DATABASE", "threat_intel")
)

# --- 2. Ollama LLM & Embedder Setup ---
ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434/v1")
llm_model = os.getenv("LLM_MODEL", "qwen2.5:14b")
embed_model = os.getenv("EMBEDDING_MODEL", "nomic-embed-text:latest")
dummy_api_key = os.getenv("OPENAI_API_KEY", "sk-ollama-local-dummy-key")

llm_config = LLMConfig(api_key=dummy_api_key, base_url=ollama_base_url, model=llm_model)
llm_client = OpenAIGenericClient(config=llm_config)

embedder_config = OpenAIEmbedderConfig(
    api_key=dummy_api_key, base_url=ollama_base_url,
    embedding_model=embed_model, embedding_dim=768
)
embedder = OpenAIEmbedder(config=embedder_config)

graphiti = Graphiti(graph_driver=driver, llm_client=llm_client, embedder=embedder)

# --- 3. Progress Tracking ---
progress_store = {}

def chunk_text(text: str, chunk_size: int = 3000) -> list[str]:
    if not text.strip(): return []
    text = ' '.join(text.split())
    if len(text) <= chunk_size: return [text]
    return [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]

async def process_chunks_background(job_id: str, chunks: list[str], source_type: str, source_name: str, custom_prompt: str = ""):
    try:
        # Combine default prompt with user prompt
        if custom_prompt:
            final_prompt = f"{DEFAULT_THREAT_INTEL_PROMPT}\\n\\n[USER INSTRUCTION]: {custom_prompt}"
        else:
            final_prompt = DEFAULT_THREAT_INTEL_PROMPT

        for i, chunk in enumerate(chunks):
            # PREPEND the prompt directly to the chunk text!
            modified_chunk = f"{final_prompt}\\n\\n--- ACTUAL CONTENT ---\\n{chunk}"

            await graphiti.add_episode(
                name=f"[{source_type}] {source_name} (Part {i+1}/{len(chunks)})",
                episode_body=modified_chunk,
                source=EpisodeType.text,
                source_description=f"Part {i+1} of {len(chunks)}",
                reference_time=datetime.now(timezone.utc)
            )
            progress_store[job_id]["current"] = i + 1
            logger.info(f"Job {job_id}: Processed chunk {i+1}/{len(chunks)}")
        progress_store[job_id]["status"] = "complete"
    except Exception as e:
        logger.error(f"Job {job_id}: Error - {str(e)}")
        progress_store[job_id]["status"] = "error"
        progress_store[job_id]["error"] = str(e)

# --- 4. FastAPI App ---
app = FastAPI(title="Graphiti Threat Intel Worker")
scheduler = AsyncIOScheduler()
CONFIG_FILE = "/app/config/sources.json"

def load_sources():
    if not os.path.exists(CONFIG_FILE): return {"rss_feeds": []}
    with open(CONFIG_FILE, "r") as f: return json.load(f)

def save_sources(sources):
    with open(CONFIG_FILE, "w") as f: json.dump(sources, f, indent=2)

async def poll_rss_feeds():
    sources = load_sources()
    for feed in sources.get("rss_feeds", []):
        try:
            async with AsyncClient() as client:
                resp = await client.get(feed['url'])
                if resp.status_code == 200:
                    modified_text = f"{DEFAULT_THREAT_INTEL_PROMPT}\\n\\n--- ACTUAL CONTENT ---\\n{resp.text[:2000]}"
                    await graphiti.add_episode(
                        name=f"[RSS] {feed['name']}", episode_body=modified_text,
                        source=EpisodeType.text, source_description=f"RSS: {feed['name']}",
                        reference_time=datetime.now(timezone.utc)
                    )
        except Exception as e: logger.error(f"RSS poll failed: {e}")

@app.on_event("startup")
async def startup():
    logger.info("Building Graphiti indices...")
    await graphiti.build_indices_and_constraints()
    scheduler.add_job(poll_rss_feeds, 'interval', minutes=30)
    scheduler.start()

# --- 5. Endpoints ---
@app.post("/upload")
async def upload_file(file: UploadFile = File(...), source_type: str = Form("Manual Upload"), custom_prompt: str = Form(""), background_tasks: BackgroundTasks = BackgroundTasks()):
    content = ""
    filename = file.filename.lower()
    if filename.endswith(".pdf"):
        reader = PdfReader(io.BytesIO(await file.read()))
        content = "\\n".join([page.extract_text() for page in reader.pages if page.extract_text()])
    elif filename.endswith((".txt", ".json", ".md")):
        content = (await file.read()).decode("utf-8")
    else: raise HTTPException(status_code=400, detail="Unsupported file type")

    chunks = chunk_text(content)
    if not chunks: raise HTTPException(status_code=400, detail="No text extracted")

    job_id = str(uuid.uuid4())
    progress_store[job_id] = {"total": len(chunks), "current": 0, "status": "processing", "filename": file.filename}
    background_tasks.add_task(process_chunks_background, job_id, chunks, source_type, file.filename, custom_prompt)
    return {"job_id": job_id, "total_chunks": len(chunks), "message": f"Started processing {file.filename}"}

@app.post("/ingest-url")
async def ingest_url(url: str = Form(...), source_type: str = Form("Web Article"), custom_prompt: str = Form(""), background_tasks: BackgroundTasks = BackgroundTasks()):
    try:
        downloaded = trafilatura.fetch_url(url)
        if not downloaded: raise HTTPException(status_code=400, detail="Failed to fetch URL")
        content = trafilatura.extract(downloaded, include_comments=False, include_tables=True)
        if not content: raise HTTPException(status_code=400, detail="Could not extract article")

        chunks = chunk_text(content)
        if not chunks: raise HTTPException(status_code=400, detail="No content extracted")

        job_id = str(uuid.uuid4())
        progress_store[job_id] = {"total": len(chunks), "current": 0, "status": "processing", "filename": url}
        background_tasks.add_task(process_chunks_background, job_id, chunks, source_type, url, custom_prompt)
        return {"job_id": job_id, "total_chunks": len(chunks), "message": f"Started processing {url}"}
    except HTTPException: raise
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

@app.get("/progress/{job_id}")
async def get_progress(job_id: str):
    if job_id not in progress_store: raise HTTPException(status_code=404, detail="Job not found")
    return progress_store[job_id]

@app.get("/sources")
def get_sources(): return load_sources()

@app.post("/sources")
def add_source(url: str = Form(...), name: str = Form(...)):
    sources = load_sources()
    sources["rss_feeds"].append({"url": url, "name": name})
    save_sources(sources)
    return {"status": "success"}

@app.delete("/sources")
def remove_source(url: str):
    sources = load_sources()
    sources["rss_feeds"] = [f for f in sources["rss_feeds"] if f["url"] != url]
    save_sources(sources)
    return {"status": "success"}

class QueryRequest(BaseModel):
    query: str
    limit: int = 5

@app.post("/query")
async def query_intel(request: QueryRequest):
    results = await graphiti.search(request.query, num_results=request.limit)
    return {"query": request.query, "episodes": results}

class IngestTextRequest(BaseModel):
    text: str
    source_type: str = "Analyst Note"
    source_name: str = "OpenWebUI Chat"

@app.post("/ingest-text")
async def ingest_text(request: IngestTextRequest):
    try:
        chunks = chunk_text(request.text)
        for i, chunk in enumerate(chunks):
            modified_chunk = f"{DEFAULT_THREAT_INTEL_PROMPT}\\n\\n--- ACTUAL CONTENT ---\\n{chunk}"
            await graphiti.add_episode(
                name=f"[{request.source_type}] {request.source_name} (Part {i+1}/{len(chunks)})",
                episode_body=modified_chunk, source=EpisodeType.text,
                source_description="Saved from OpenWebUI",
                reference_time=datetime.now(timezone.utc)
            )
        return {"status": "success", "message": f"Saved {len(chunks)} chunk(s) to knowledge graph"}
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

@app.get("/stats")
async def get_stats():
    try:
        node_result = await driver.execute_query("MATCH (n) RETURN count(n) as count")
        edge_result = await driver.execute_query("MATCH ()-[r]->() RETURN count(r) as count")
        episode_result = await driver.execute_query("MATCH (e:Episode) RETURN count(e) as count")

        def safe_count(res):
            if not res: return 0
            row = res[0]
            if isinstance(row, dict): return int(row.get("count", 0))
            if isinstance(row, list) and row:
                if isinstance(row[0], dict): return int(row[0].get("count", 0))
                return int(row[0]) if isinstance(row[0], int) else 0
            return 0

        return {
            "nodes": safe_count(node_result), "edges": safe_count(edge_result),
            "episodes": safe_count(episode_result),
            "active_jobs": len([j for j in progress_store.values() if j["status"] == "processing"])
        }
    except Exception as e: return {"nodes": 0, "edges": 0, "episodes": 0, "active_jobs": 0, "error": str(e)}

@app.get("/entities")
async def list_entities(limit: int = 50):
    try:
        result = await driver.execute_query(f"MATCH (n) RETURN n.name as name, labels(n) as labels LIMIT {limit}")
        return {"entities": [{"name": row[0], "labels": row[1]} for row in result]}
    except Exception as e: return {"error": str(e)}

@app.get("/relationships")
async def list_relationships(limit: int = 50):
    try:
        result = await driver.execute_query(f"MATCH (a)-[r]->(b) RETURN a.name as source, type(r) as relationship, b.name as target LIMIT {limit}")
        return {"relationships": [{"source": row[0], "relationship": row[1], "target": row[2]} for row in result]}
    except Exception as e: return {"error": str(e)}

@app.get("/recent")
async def get_recent_episodes(limit: int = 10):
    try:
        result = await driver.execute_query(f"MATCH (e:Episode) RETURN e.name as name, e.source_description as description, e.reference_time as time ORDER BY e.reference_time DESC LIMIT {limit}")
        return {"recent_episodes": [{"name": row[0], "description": row[1], "time": str(row[2])} for row in result]}
    except Exception as e: return {"error": str(e)}
''',

    "ingest_ui/Dockerfile": """FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
""",

    "ingest_ui/requirements.txt": """streamlit
requests
""",

    "ingest_ui/app.py": '''import os
import time
import streamlit as st
import requests

API_URL = os.getenv("API_URL", "http://graphiti-worker:8000")

st.set_page_config(page_title="Threat Intel Ingestion", layout="wide")
st.title("️ Local Threat Intelligence Ingestion Hub")

tab1, tab2, tab3, tab4 = st.tabs([" Summary", "📁 File Drop", " Web Article", "📡 Automated Sources"])

with tab1:
    st.header("Knowledge Graph Overview")
    try:
        stats = requests.get(f"{API_URL}/stats", timeout=5).json()
        col1, col2, col3, col4 = st.columns(4)
        with col1: st.metric("Entities (Nodes)", stats.get("nodes", 0))
        with col2: st.metric("Relationships (Edges)", stats.get("edges", 0))
        with col3: st.metric("Episodes Ingested", stats.get("episodes", 0))
        with col4: st.metric("Active Jobs", stats.get("active_jobs", 0))
    except Exception as e: st.error(f"Stats error: {e}")

    st.divider()
    st.subheader("📥 Recent Ingestions")
    try:
        recent = requests.get(f"{API_URL}/recent?limit=10", timeout=5).json().get("recent_episodes", [])
        for ep in recent:
            with st.expander(f"📄 {ep.get('name', 'Unknown')}"):
                st.write(f"**Desc:** {ep.get('description', 'N/A')}")
                st.write(f"**Time:** {ep.get('time', 'Unknown')}")
    except Exception as e: st.error(f"Recent error: {e}")

    st.divider()
    st.subheader("🏷️ Sample Entities & Relationships")
    try:
        entities = requests.get(f"{API_URL}/entities?limit=15", timeout=5).json().get("entities", [])
        if entities: st.write(", ".join([e.get("name", "?") for e in entities]))
    except: pass
    try:
        rels = requests.get(f"{API_URL}/relationships?limit=10", timeout=5).json().get("relationships", [])
        for r in rels: st.write(f"**{r.get('source')}** → {r.get('relationship')} → **{r.get('target')}**")
    except: pass

with tab2:
    st.header("Upload Intelligence Reports")
    uploaded_file = st.file_uploader("Choose a file", type=["pdf", "txt", "json", "md"])
    source_type = st.selectbox("Source Classification", ["OSINT", "CTI/MISP", "HUMINT", "Internal Report"], key="file_source")

    st.markdown("###  Custom LLM Instructions (Optional)")
    custom_prompt = st.text_area("Custom Prompt", placeholder="e.g., Focus on extracting IP addresses, CVEs, and MITRE ATT&CK TTPs.", height=100, key="file_prompt")

    if st.button("Process File"):
        if uploaded_file:
            with st.spinner("Analyzing..."):
                files = {"file": (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type)}
                data = {"source_type": source_type, "custom_prompt": custom_prompt}
                resp = requests.post(f"{API_URL}/upload", files=files, data=data)
                if resp.status_code == 200:
                    res = resp.json()
                    job_id, total = res["job_id"], res["total_chunks"]
                    st.info(f"Split into {total} chunks. Processing...")
                    bar, txt = st.progress(0), st.empty()
                    while True:
                        p = requests.get(f"{API_URL}/progress/{job_id}", timeout=5).json()
                        pct = int((p["current"] / total) * 100) if total > 0 else 0
                        bar.progress(pct)
                        if p["status"] == "complete": txt.success("✅ Complete!"); break
                        elif p["status"] == "error": txt.error(f" {p.get('error')}"); break
                        else: txt.info(f"⏳ Chunk {p['current']}/{total}...")
                        time.sleep(0.5)
                else: st.error(resp.text)
        else: st.warning("Select a file first.")

with tab3:
    st.header("Ingest from Webpage URL")
    url_input = st.text_input("Article URL", placeholder="https://example.com/threat-report")
    url_source_type = st.selectbox("Source Classification", ["OSINT", "News Article", "Research Paper", "Blog Post"], key="url_source")

    st.markdown("###  Custom LLM Instructions (Optional)")
    url_custom_prompt = st.text_area("Custom Prompt", placeholder="e.g., Only extract entities related to Russian threat actors.", height=100, key="url_prompt")

    if st.button("Ingest Article"):
        if url_input:
            with st.spinner("Fetching..."):
                data = {"url": url_input, "source_type": url_source_type, "custom_prompt": url_custom_prompt}
                resp = requests.post(f"{API_URL}/ingest-url", data=data)
                if resp.status_code == 200:
                    res = resp.json()
                    job_id, total = res["job_id"], res["total_chunks"]
                    st.info(f"Split into {total} chunks. Processing...")
                    bar, txt = st.progress(0), st.empty()
                    while True:
                        p = requests.get(f"{API_URL}/progress/{job_id}", timeout=5).json()
                        pct = int((p["current"] / total) * 100) if total > 0 else 0
                        bar.progress(pct)
                        if p["status"] == "complete": txt.success("✅ Complete!"); break
                        elif p["status"] == "error": txt.error(f"❌ {p.get('error')}"); break
                        else: txt.info(f"⏳ Chunk {p['current']}/{total}...")
                        time.sleep(0.5)
                else: st.error(resp.text)
        else: st.warning("Enter a URL first.")

with tab4:
    st.header("Manage Automated Feeds")
    try: sources = requests.get(f"{API_URL}/sources").json().get("rss_feeds", [])
    except: st.error("API connection failed."); sources = []

    col1, col2 = st.columns([2, 1])
    with col1:
        new_name = st.text_input("Feed Name")
        new_url = st.text_input("Feed URL")
    with col2:
        st.write(""); st.write("")
        if st.button("Add Feed"):
            if new_name and new_url:
                requests.post(f"{API_URL}/sources", data={"name": new_name, "url": new_url})
                st.rerun()

    st.divider()
    for feed in sources:
        col_a, col_b = st.columns([4, 1])
        with col_a: st.write(f"**{feed['name']}**\\n`{feed['url']}`")
        with col_b:
            if st.button("Remove", key=feed['url']):
                requests.delete(f"{API_URL}/sources", params={"url": feed['url']})
                st.rerun()
'''
}

# Create directories and write files
for filepath, content in files.items():
    dir_name = os.path.dirname(filepath)
    if dir_name: os.makedirs(dir_name, exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Created: {filepath}")

print("\n✅ All files generated successfully!")
print("\nNext steps:")
print("1. docker compose restart graphiti-worker ingest-ui")
print("2. Clear your old graph: docker exec -it falkordb redis-cli GRAPH.DELETE threat_intel")
print("3. Re-ingest your data to see the new high-fidelity relationships!")
