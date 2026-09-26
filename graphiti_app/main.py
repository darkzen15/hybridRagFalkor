import os
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from collections import defaultdict
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

from falkordb import FalkorDB

# --- INITIALIZE RAW FALKORDB CLIENT (FOR CLEAN JSON SEARCH) ---
raw_db = FalkorDB(
    host=os.getenv("FALKORDB_HOST", "falkordb"),
    port=int(os.getenv("FALKORDB_PORT", 6379))
)
raw_graph = raw_db.select_graph(os.getenv("FALKORDB_DATABASE", "threat_intel"))

# ==========================================
# 1. LOGGING CONFIGURATION (SILENCE NOISE)
# ==========================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

logging.getLogger("graphiti_core.driver.falkordb_driver").setLevel(logging.WARNING)
logging.getLogger("falkordb").setLevel(logging.WARNING)

class EndpointFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not any(endpoint in record.getMessage() for endpoint in ["/stats", "/recent", "/entities", "/relationships", "/progress"])

logging.getLogger("uvicorn.access").addFilter(EndpointFilter())

# ==========================================
# 2. FALKORDB & LLM SETUP
# ==========================================
driver = FalkorDriver(
    host=os.getenv("FALKORDB_HOST", "falkordb"),
    port=int(os.getenv("FALKORDB_PORT", 6379)),
    database=os.getenv("FALKORDB_DATABASE", "threat_intel")
)

ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434/v1")
llm_model = os.getenv("LLM_MODEL", "qwen2.5-coder:14b")
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

# ==========================================
# 3. HISTORY & PROGRESS TRACKING
# ==========================================
HISTORY_FILE = "/app/config/ingestion_history.json"

def load_history():
    if not os.path.exists(HISTORY_FILE):
        return {"files": [], "urls": []}
    with open(HISTORY_FILE, "r") as f:
        return json.load(f)

def save_history(history):
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

progress_store = {}

def chunk_text(text: str, chunk_size: int = 3000) -> list[str]:
    if not text.strip(): return []
    text = ' '.join(text.split())
    if len(text) <= chunk_size: return [text]
    return [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]

# ==========================================
# 4. SEMANTIC JSON MAPPING HELPERS
# ==========================================
def sanitize_key(s) -> str:
    clean = "".join(c if c.isalnum() else "_" for c in str(s))
    return clean or "field"

DIMENSION_EDGE_NAMES = {
    "year": "OCCURRED_IN",
    "industry": "TARGETS_INDUSTRY",
    "attacktype": "CLASSIFIED_AS",
    "country": "LOCATED_IN",
    "type": "IS_TYPE",
}

def detect_dimension_fields(items, max_distinct=60):
    distinct = defaultdict(set)
    for it in items:
        if not isinstance(it, dict): continue
        for k, v in it.items():
            if isinstance(v, (str, int, float, bool)) and v is not None:
                distinct[k].add(v)
    dims = []
    for k, vals in distinct.items():
        if 1 < len(vals) <= max_distinct:
            dims.append(k)
    return dims

# ==========================================
# 5. BACKGROUND TASKS
# ==========================================

async def process_chunks_background(job_id: str, chunks: list[str], source_type: str, source_name: str):
    try:
        for i, chunk in enumerate(chunks):
            await graphiti.add_episode(
                name=f"[{source_type}] {source_name} (Part {i+1}/{len(chunks)})",
                episode_body=chunk,
                source=EpisodeType.text,
                source_description=f"Part {i+1} of {len(chunks)}",
                reference_time=datetime.now(timezone.utc)
            )
            progress_store[job_id]["current"] = i + 1
        progress_store[job_id]["status"] = "complete"
    except Exception as e:
        logger.error(f"Job {job_id} Error: {str(e)}")
        progress_store[job_id]["status"] = "error"
        progress_store[job_id]["error"] = str(e)

async def process_deterministic_json_background(job_id: str, json_content: str, source_type: str, source_name: str):
    try:
        data = json.loads(json_content)
        if isinstance(data, dict) and "objects" in data:
            items = data["objects"]
        elif isinstance(data, list):
            items = data
        else:
            items = [data]
        items = [it for it in items if isinstance(it, dict)]
        total = len(items)
        progress_store[job_id]["total"] = max(total, 1)
        now_iso = datetime.now(timezone.utc).isoformat()

        record_label = sanitize_key(source_name.rsplit(".", 1)[0]) or "Record"
        dim_fields = [sanitize_key(f) for f in detect_dimension_fields(items)]

        norm = []
        for it in items:
            safe = {}
            for k, v in it.items():
                key = sanitize_key(k)
                if v is None or isinstance(v, (str, int, float, bool)):
                    safe[key] = v
                elif isinstance(v, list) and all(isinstance(x, (str, int, float, bool)) or x is None for x in v):
                    safe[key] = v
                else:
                    safe[key] = json.dumps(v)
            safe["entity_id"] = str(it.get("id") or it.get("guid") or it.get("uuid") or it.get("name") or uuid.uuid4())
            norm.append(safe)

        batch_size = 500
        done = 0
        for i in range(0, total, batch_size):
            batch = norm[i:i + batch_size]

            # 1) Record nodes + source provenance edge
            await driver.execute_query(
                f"""
                UNWIND $batch AS item
                MERGE (r:{record_label} {{entity_id: item.entity_id}})
                ON CREATE SET r += item, r.ingested_from = $source_name, r.ingested_at = $now_iso
                ON MATCH SET r.last_updated = $now_iso
                WITH r, item
                MERGE (s:Source {{name: $source_name}})
                MERGE (r)-[:FROM_SOURCE]->(s)
                """,
                batch=batch, source_name=source_name, now_iso=now_iso
            )

            # 2) Dimension hub nodes + meaningful edges (WITH NAME FIX)
            for field in dim_fields:
                sub = [b for b in batch if b.get(field) is not None]
                if not sub: continue

                rel = DIMENSION_EDGE_NAMES.get(field.lower(), "HAS_" + field.upper())
                dlabel = "Dim_" + field

                await driver.execute_query(
                    f"""
                    UNWIND $batch AS item
                    MERGE (r:{record_label} {{entity_id: item.entity_id}})
                    MERGE (d:{dlabel} {{value: item.`{field}`}})
                    SET d.name = d.value, d.field = $field_label
                    MERGE (r)-[:{rel}]->(d)
                    """,
                    batch=sub, field_label=field
                )

            done += len(batch)
            progress_store[job_id]["current"] = done
            logger.info(f"Job {job_id}: Ingested {done}/{total} records with semantic edges")

        progress_store[job_id]["status"] = "complete"
        logger.info(f"Job {job_id}: Completed semantic JSON ingestion ({total} records)")

    except json.JSONDecodeError as e:
        logger.error(f"Job {job_id} JSON Decode Error: {str(e)}")
        progress_store[job_id]["status"] = "error"
        progress_store[job_id]["error"] = "Invalid JSON format"
    except Exception as e:
        logger.error(f"Job {job_id} JSON Ingestion Error: {str(e)}")
        progress_store[job_id]["status"] = "error"
        progress_store[job_id]["error"] = str(e)

# ==========================================
# 6. FASTAPI APP & SCHEDULER
# ==========================================
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
                    await graphiti.add_episode(
                        name=f"[RSS] {feed['name']}", episode_body=resp.text[:2000],
                        source=EpisodeType.text, source_description=f"RSS: {feed['name']}",
                        reference_time=datetime.now(timezone.utc)
                    )
        except Exception as e:
            logger.error(f"RSS poll failed: {e}")

@app.on_event("startup")
async def startup():
    await graphiti.build_indices_and_constraints()
    scheduler.add_job(poll_rss_feeds, 'interval', minutes=30)
    scheduler.start()

# ==========================================
# 7. ENDPOINTS
# ==========================================
@app.post("/upload")
async def upload_file(
    files: list[UploadFile] = File(...),
    source_type: str = Form("Manual Upload"),
    custom_prompt: str = Form(""),
    force: bool = Form(False),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    history = load_history()
    duplicates = [f.filename for f in files if any(h["name"] == f.filename for h in history["files"])]
    if duplicates and not force:
        raise HTTPException(status_code=409, detail=f"Duplicate files found: {', '.join(duplicates)}")

    jobs = []
    for file in files:
        filename = file.filename.lower() if file.filename else ""

        if filename.endswith(".json"):
            content = (await file.read()).decode("utf-8")
            try:
                temp_data = json.loads(content)
                if isinstance(temp_data, dict) and "objects" in temp_data:
                    total_items = len(temp_data["objects"])
                elif isinstance(temp_data, list):
                    total_items = len(temp_data)
                else:
                    total_items = 1
            except json.JSONDecodeError:
                continue

            job_id = str(uuid.uuid4())
            progress_store[job_id] = {"total": total_items, "current": 0, "status": "processing", "filename": file.filename}
            background_tasks.add_task(process_deterministic_json_background, job_id, content, source_type, file.filename)
            jobs.append({"filename": file.filename, "job_id": job_id, "total_chunks": total_items})

            history["files"] = [f for f in history["files"] if f["name"] != file.filename]
            history["files"].append({"name": file.filename, "type": source_type, "timestamp": datetime.now(timezone.utc).isoformat(), "chunks": total_items})
            continue

        content = ""
        if filename.endswith(".pdf"):
            reader = PdfReader(io.BytesIO(await file.read()))
            content = "\n".join([page.extract_text() for page in reader.pages if page.extract_text()])
        elif filename.endswith((".txt", ".md")):
            content = (await file.read()).decode("utf-8")
        else:
            continue

        chunks = chunk_text(content)
        if not chunks: continue

        job_id = str(uuid.uuid4())
        progress_store[job_id] = {"total": len(chunks), "current": 0, "status": "processing", "filename": file.filename}
        background_tasks.add_task(process_chunks_background, job_id, chunks, source_type, file.filename)
        jobs.append({"filename": file.filename, "job_id": job_id, "total_chunks": len(chunks)})

        history["files"] = [f for f in history["files"] if f["name"] != file.filename]
        history["files"].append({"name": file.filename, "type": source_type, "timestamp": datetime.now(timezone.utc).isoformat(), "chunks": len(chunks)})

    save_history(history)

    if not jobs:
        raise HTTPException(status_code=400, detail="No valid text extracted")
    return {"jobs": jobs, "message": f"Started processing {len(jobs)} files"}

@app.post("/ingest-url")
async def ingest_url(
    url: str = Form(...),
    source_type: str = Form("Web Article"),
    custom_prompt: str = Form(""),
    force: bool = Form(False),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    history = load_history()
    if any(h["url"] == url for h in history["urls"]):
        if not force:
            raise HTTPException(status_code=409, detail=f"Duplicate URL found: {url}")
        history["urls"] = [u for u in history["urls"] if u["url"] != url]

    try:
        downloaded = trafilatura.fetch_url(url)
        if not downloaded: raise HTTPException(status_code=400, detail="Failed to fetch URL")
        content = trafilatura.extract(downloaded, include_comments=False, include_tables=True)
        if not content: raise HTTPException(status_code=400, detail="Could not extract article")

        chunks = chunk_text(content)
        if not chunks: raise HTTPException(status_code=400, detail="No content extracted")

        job_id = str(uuid.uuid4())
        progress_store[job_id] = {"total": len(chunks), "current": 0, "status": "processing", "filename": url}
        background_tasks.add_task(process_chunks_background, job_id, chunks, source_type, url)

        history["urls"].append({"url": url, "type": source_type, "timestamp": datetime.now(timezone.utc).isoformat(), "chunks": len(chunks)})
        save_history(history)

        return {"job_id": job_id, "total_chunks": len(chunks), "message": f"Started processing {url}"}
    except HTTPException: raise
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

@app.get("/history")
def get_history(): return load_history()

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

class StructuredSearchRequest(BaseModel):
    query: str
    limit: int = 10

@app.post("/search-structured")
async def search_structured(request: StructuredSearchRequest):
    """Uses the official FalkorDB client to cleanly parse node properties."""
    try:
        # Use the standard falkordb client which returns a clean ResultSet
        res = raw_graph.query("MATCH (n) RETURN properties(n) AS props, labels(n) AS lbls")

        full_q = request.query.lower().strip()
        keywords = [w.strip(".,;:!?()\"'") for w in full_q.split() if len(w) >= 3] or [full_q]

        scored = []
        # res.result_set is a clean list of lists: [[props_dict, labels_list], ...]
        for row in res.result_set:
            props, lbls = row[0], row[1]

            label = lbls[0] if isinstance(lbls, list) and lbls else "Node"
            score = 0

            if not isinstance(props, dict):
                continue

            for k, v in props.items():
                strings = [v] if isinstance(v, str) else ([x for x in v if isinstance(x, str)] if isinstance(v, list) else [])
                for s in strings:
                    sl = s.lower()
                    if full_q and full_q in sl:
                        score += 5
                    elif any(kw in sl for kw in keywords):
                        score += 1

            if score > 0:
                name = str(props.get("name") or props.get("value") or props.get("entity_id") or "Unknown")
                clean = {k: v for k, v in props.items()
                         if isinstance(v, (str, int, float, bool))
                         and k not in ("entity_id", "ingested_at", "last_updated", "ingested_from")}
                scored.append((score, {"type": label, "identifier": name, "properties": clean}))

        scored.sort(key=lambda x: x[0], reverse=True)
        return {"version": 3, "results": [item for _, item in scored[:request.limit]]}

    except Exception as e:
        return {"version": 3, "results": [], "error": str(e)}

class IngestTextRequest(BaseModel):
    text: str
    source_type: str = "Analyst Note"
    source_name: str = "OpenWebUI Chat"

@app.post("/ingest-text")
async def ingest_text(request: IngestTextRequest):
    try:
        chunks = chunk_text(request.text)
        for i, chunk in enumerate(chunks):
            await graphiti.add_episode(
                name=f"[{request.source_type}] {request.source_name} (Part {i+1}/{len(chunks)})",
                episode_body=chunk, source=EpisodeType.text,
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

@app.get("/debug-nodes")
async def debug_nodes():
    """Dumps the raw structure of a node to help debug the search tool."""
    try:
        result = await driver.execute_query("MATCH (n) RETURN n LIMIT 2")
        if not result: return {"error": "Database is empty!"}

        debug_info = []
        for row in result:
            # Extract the node from the row
            node = row[0] if isinstance(row, list) else row

            # Extract properties and labels however they are stored
            props = getattr(node, "properties", None)
            if props is None and isinstance(node, dict):
                props = node

            labels = getattr(node, "labels", None)
            if labels is None and isinstance(node, dict):
                labels = node.get("labels", [])

            debug_info.append({
                "node_type": str(type(node)),
                "has_properties": props is not None,
                "properties_keys": list(props.keys()) if isinstance(props, dict) else "Not a dict",
                "sample_values": {k: str(v)[:50] for k, v in props.items()} if isinstance(props, dict) else None,
                "labels": labels
            })
        return {"nodes": debug_info}
    except Exception as e:
        return {"error": str(e)}
