import os
import io
import json
import logging
import uuid
import asyncio
import httpx
from datetime import datetime, timezone
from collections import defaultdict
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks
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

# ==========================================
# 1. LOGGING CONFIGURATION (SILENCE NOISE)
# ==========================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

logging.getLogger("graphiti_core.driver.falkordb_driver").setLevel(logging.WARNING)
logging.getLogger("graphiti_core.utils.maintenance.edge_operations").setLevel(logging.ERROR)
logging.getLogger("falkordb").setLevel(logging.WARNING)

class EndpointFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not any(endpoint in record.getMessage() for endpoint in ["/stats", "/recent", "/entities", "/relationships", "/progress"])

logging.getLogger("uvicorn.access").addFilter(EndpointFilter())

# ==========================================
# 1b. FIELD-TUNABLE CONFIG (HOT-RELOADED)
# ==========================================
TUNING_FILE = "/app/config/tuning.json"

DEFAULT_TUNING = {
    "chunk_size": 3000,
    "batch_size": 500,
    "max_distinct": 150,
    "enrich_temperature": 0.1,
    "dimension_edge_names": {
        "year": "OCCURRED_IN",
        "industry": "TARGETS_INDUSTRY",
        "attacktype": "CLASSIFIED_AS",
        "country": "LOCATED_IN",
        "type": "IS_TYPE",
    },
    "terror_enrich_prompt": """You are a threat intelligence analyst. Analyze this terror event record and extract structured attributes.
Respond ONLY with raw JSON (no markdown fences) with exactly these keys:
{{"ideology": "<Jihadist|White supremacist|Racist|Antisemitic|Incel|Religious extremist|Separatist|Domestic extremist|Unknown>",
"ttp": "<Vehicle ramming|Suicide bombing|Armed assault|Knife attack|Bombing|Hostage-taking|Arson|Mixed assault|Unknown>",
"weapons": ["<short items>"],
"claimed_by": "<organization name or None>"}}
Record:
{record}""",
    "cyber_enrich_prompt": """You are a threat intelligence analyst. Analyze this cyber incident record and extract structured attributes.
Respond ONLY with raw JSON (no markdown fences) with exactly these keys:
{{"motive": "<Espionage|Financial|Sabotage|Hacktivism|Political|Unknown>",
"ttp": "<Ransomware|ICS/SCADA disruption|Data breach|Wiper malware|Supply-chain compromise|Unknown>",
"tools": ["<short items>"],
"claimed_by": "<organization name or None>"}}
Record:
{record}""",
}

def load_tuning():
    try:
        with open(TUNING_FILE) as f:
            return {**DEFAULT_TUNING, **json.load(f)}
    except FileNotFoundError:
        return dict(DEFAULT_TUNING)
    except Exception as e:
        logger.error(f"Bad tuning.json ({e}); using built-in defaults.")
        return dict(DEFAULT_TUNING)

TUNING = load_tuning()
logger.info(f"Tuning active: chunk_size={TUNING['chunk_size']} batch_size={TUNING['batch_size']} "
            f"max_distinct={TUNING['max_distinct']} enrich_temperature={TUNING['enrich_temperature']}")

# ==========================================
# 2. FALKORDB & LLM SETUP
# ==========================================
driver = FalkorDriver(
    host=os.getenv("FALKORDB_HOST", "falkordb"),
    port=int(os.getenv("FALKORDB_PORT", 6379)),
    database=os.getenv("FALKORDB_DATABASE", "threat_intel")
)

ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434/v1")
llm_model = os.getenv("LLM_MODEL", "qwen2.5:latest")
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

raw_db = FalkorDB(
    host=os.getenv("FALKORDB_HOST", "falkordb"),
    port=int(os.getenv("FALKORDB_PORT", 6379))
)
raw_graph = raw_db.select_graph(os.getenv("FALKORDB_DATABASE", "threat_intel"))

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

def create_job(job_id, total, filename, source="ui"):
    """Helper to create a tracked job with metadata."""
    progress_store[job_id] = {
        "total": total,
        "current": 0,
        "status": "processing",
        "filename": filename,
        "source": source,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    return job_id

def chunk_text(text: str, chunk_size: int = None) -> list[str]:
    chunk_size = int(chunk_size or TUNING["chunk_size"])
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

def detect_dimension_fields(items, max_distinct=150):
    n = len(items)
    stats = defaultdict(lambda: {"distinct": set(), "occ": 0})
    for it in items:
        if not isinstance(it, dict): continue
        for k, v in it.items():
            if v is None: continue
            if isinstance(v, (str, int, float, bool)):
                vals = [v]
            elif isinstance(v, list) and all(isinstance(x, (str, int, float, bool)) or x is None for x in v):
                vals = [x for x in v if x is not None]
            else: continue
            stats[k]["occ"] += len(vals)
            for x in vals:
                stats[k]["distinct"].add(x)

    dims = []
    for k, s in stats.items():
        d = len(s["distinct"])
        occ = s["occ"]
        if d < 2 or d > max_distinct: continue
        if occ <= d: continue
        if occ <= n and d >= 0.9 * n: continue
        if occ > n and d >= 0.95 * occ: continue
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
            logger.info(f"Job {job_id}: Processed chunk {i+1}/{len(chunks)}")
        progress_store[job_id]["status"] = "complete"
    except Exception as e:
        logger.error(f"Job {job_id} Error: {str(e)}")
        progress_store[job_id]["status"] = "error"
        progress_store[job_id]["error"] = str(e)

async def process_deterministic_json_background(job_id: str, json_content: str, source_type: str, source_name: str, auto_enrich: bool = False):
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

        norm = []
        for it in items:
            safe = {}
            for k, v in it.items():
                key = sanitize_key(k)
                if v is None or isinstance(v, (str, int, float, bool)):
                    safe[key] = v.strip() if isinstance(v, str) else v
                elif isinstance(v, list) and all(isinstance(x, (str, int, float, bool)) or x is None for x in v):
                    safe[key] = [x.strip() if isinstance(x, str) else x for x in v]
                else:
                    safe[key] = json.dumps(v)
            safe["entity_id"] = str(it.get("id") or it.get("guid") or it.get("uuid") or it.get("name") or uuid.uuid4())
            if not safe.get("name"):
                caption = safe.get("blurb") or safe.get("description") or safe.get("summary") or safe.get("title")
                if isinstance(caption, str) and caption.strip():
                    safe["name"] = caption.strip()[:70]
                else:
                    loc = str(safe.get("location") or safe.get("country") or "").strip()
                    dt = str(safe.get("date") or safe.get("year") or "").strip()
                    safe["name"] = (f"{loc} {dt}".strip() or safe["entity_id"])
            norm.append(safe)

        dim_fields = detect_dimension_fields(norm, max_distinct=int(TUNING["max_distinct"]))
        edge_names = TUNING["dimension_edge_names"]

        batch_size = int(TUNING["batch_size"])
        done = 0
        for i in range(0, total, batch_size):
            batch = norm[i:i + batch_size]

            await driver.execute_query(
                f"""
                UNWIND $batch AS item
                MERGE (r:{record_label} {{entity_id: item.entity_id}})
                ON CREATE SET r += item, r.ingested_from = $source_name, r.ingested_at = $now_iso
                ON MATCH SET r += item, r.last_updated = $now_iso
                WITH r, item
                MERGE (s:Source {{name: $source_name}})
                MERGE (r)-[:FROM_SOURCE]->(s)
                """,
                batch=batch, source_name=source_name, now_iso=now_iso
            )

            for field in dim_fields:
                sub = [b for b in batch if b.get(field) is not None]
                if not sub: continue
                for b in sub:
                    val = b[field]
                    if isinstance(val, list):
                        b["dim_values"] = [str(v) for v in val if v is not None]
                    else:
                        b["dim_values"] = [str(val)]
                rel = edge_names.get(field.lower(), "HAS_" + field.upper())
                dlabel = "Dim_" + field
                await driver.execute_query(
                    f"""
                    UNWIND $batch AS item
                    MERGE (r:{record_label} {{entity_id: item.entity_id}})
                    WITH r, item
                    UNWIND item.dim_values AS val
                    MERGE (d:{dlabel} {{value: val}})
                    SET d.name = val, d.field = $field_label
                    MERGE (r)-[:{rel}]->(d)
                    """,
                    batch=sub, field_label=field
                )

            done += len(batch)
            progress_store[job_id]["current"] = done
            logger.info(f"Job {job_id}: Ingested {done}/{total} records")

        progress_store[job_id]["status"] = "complete"
        logger.info(f"Job {job_id}: Completed semantic JSON ingestion ({total} records)")

        if auto_enrich:
            enrich_job = str(uuid.uuid4())
            create_job(enrich_job, 0, f"auto-enrich:{record_label}", source="auto")
            asyncio.create_task(run_enrichment(enrich_job, record_label, True, False, True))

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

@app.middleware("http")
async def reload_tuning_middleware(request, call_next):
    global TUNING
    TUNING = load_tuning()
    return await call_next(request)

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
            async with httpx.AsyncClient() as client:
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
    logger.info("Building Graphiti indices...")
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
    auto_enrich: bool = Form(False),
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
            create_job(job_id, total_items, file.filename, source="ui")
            background_tasks.add_task(process_deterministic_json_background, job_id, content, source_type, file.filename, auto_enrich)
            jobs.append({"filename": file.filename, "job_id": job_id, "total_chunks": total_items})

            history["files"] = [f for f in history["files"] if f["name"] != file.filename]
            history["files"].append({"name": file.filename, "type": source_type, "timestamp": datetime.now(timezone.utc).isoformat(), "chunks": total_items})
            continue

        content = ""
        if filename.endswith(".pdf"):
            reader = PdfReader(io.BytesIO(await file.read()))
            content = "\n".join([page.extract_text() for page in reader.pages if page.extract_text()])
        elif filename.endswith((".txt", ".md", ".html")):
            content = (await file.read()).decode("utf-8")
        else:
            continue

        chunks = chunk_text(content)
        if not chunks: continue

        job_id = str(uuid.uuid4())
        create_job(job_id, len(chunks), file.filename, source="ui")
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
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Referer": "https://www.google.com/",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "cross-site"
        }

        async with httpx.AsyncClient(headers=headers, follow_redirects=True, timeout=30.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            downloaded_html = resp.text

        content = trafilatura.extract(downloaded_html, include_comments=False, include_tables=True)
        if not content:
            raise HTTPException(status_code=400, detail="Fetched the page, but could not extract article text. Try saving as PDF and uploading via Tab 02.")

        chunks = chunk_text(content)
        if not chunks: raise HTTPException(status_code=400, detail="No content extracted")

        job_id = str(uuid.uuid4())
        create_job(job_id, len(chunks), url, source="ui")
        background_tasks.add_task(process_chunks_background, job_id, chunks, source_type, url)

        history["urls"].append({"url": url, "type": source_type, "timestamp": datetime.now(timezone.utc).isoformat(), "chunks": len(chunks)})
        save_history(history)

        return {"job_id": job_id, "total_chunks": len(chunks), "message": f"Started processing {url}"}

    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=400, detail=f"Site blocked the request (HTTP {e.response.status_code}). Try saving as PDF and uploading via Tab 02.")
    except httpx.RequestError as e:
        raise HTTPException(status_code=400, detail=f"Network error fetching URL: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/history")
def get_history(): return load_history()

@app.get("/progress/{job_id}")
async def get_progress(job_id: str):
    if job_id not in progress_store: raise HTTPException(status_code=404, detail="Job not found")
    return progress_store[job_id]

@app.get("/jobs")
def list_jobs(limit: int = 50):
    """Returns all tracked jobs sorted by most recent first."""
    jobs = []
    for job_id, data in progress_store.items():
        jobs.append({"job_id": job_id, **data})
    jobs.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return {"jobs": jobs[:limit], "total_tracked": len(jobs)}

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
async def ingest_text(request: IngestTextRequest, background_tasks: BackgroundTasks):
    try:
        chunks = chunk_text(request.text)
        if not chunks:
            return {"status": "error", "message": "Empty text provided"}

        job_id = str(uuid.uuid4())
        source = "mcp" if "MCP" in request.source_name else "ui"
        create_job(job_id, len(chunks), request.source_name, source=source)

        background_tasks.add_task(process_chunks_background, job_id, chunks, request.source_type, request.source_name)

        history = load_history()
        history["files"].append({
            "name": f"[TEXT] {request.source_name}",
            "type": request.source_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "chunks": len(chunks)
        })
        save_history(history)

        return {"status": "queued", "job_id": job_id, "message": f"Queued {len(chunks)} chunk(s) for background extraction."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class StructuredSearchRequest(BaseModel):
    query: str
    limit: int = 10

@app.post("/search-structured")
async def search_structured(request: StructuredSearchRequest):
    try:
        res = raw_graph.query("MATCH (n) RETURN properties(n) AS props, labels(n) AS lbls")
        full_q = request.query.lower().strip()
        keywords = [w.strip(".,;:!?()\"'") for w in full_q.split() if len(w) >= 3] or [full_q]

        scored = []
        for row in res.result_set:
            props, lbls = row[0], row[1]
            if not isinstance(props, dict): continue
            label = lbls[0] if isinstance(lbls, list) and lbls else "Node"
            score = 0
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

@app.get("/record-labels")
async def record_labels():
    try:
        res = raw_graph.query(
            "MATCH (n) WHERE n.entity_id IS NOT NULL AND n.ingested_from IS NOT NULL "
            "RETURN DISTINCT head(labels(n)) AS label"
        )
        labels = sorted({row[0] for row in (res.result_set or []) if row and row[0]})
        return {"labels": labels}
    except Exception as e:
        return {"labels": [], "error": str(e)}

# ==========================================
# 8. LLM ENRICHMENT ENGINE (LINK DISCOVERY)
# ==========================================
async def run_enrichment(job_id: str, label: str, run_hubs: bool, run_narrative: bool, run_stitch: bool):
    try:
        conds = []
        if run_hubs: conds.append("r.enriched_hubs IS NULL")
        if run_narrative: conds.append("r.enriched_narrative IS NULL")
        where = " OR ".join(conds) if conds else "true"

        res = raw_graph.query(
            f"MATCH (r:{label}) WHERE {where} RETURN r.entity_id AS eid, properties(r) AS props"
        )
        rows = res.result_set or []
        progress_store[job_id]["total"] = len(rows)

        async with httpx.AsyncClient() as client:
            for i, row in enumerate(rows):
                eid, props = row[0], row[1] or {}
                if not isinstance(props, dict): continue
                slim = {k: v for k, v in props.items()
                        if not k.startswith(("ingested", "last_", "entity_id", "enriched"))}
                record_json = json.dumps(slim, default=str)[:2000]
                is_cyber = any(k in props for k in ("industry", "attackType", "attacktype"))
                extracted = {}

                if run_hubs:
                    try:
                        prompt = (TUNING["cyber_enrich_prompt"] if is_cyber else TUNING["terror_enrich_prompt"]).format(record=record_json)
                        resp = await client.post(
                            f"{ollama_base_url}/chat/completions",
                            json={"model": llm_model, "temperature": float(TUNING["enrich_temperature"]),
                                  "messages": [{"role": "user", "content": prompt}]},
                            timeout=180
                        )
                        text = resp.json()["choices"][0]["message"]["content"]
                        extracted = json.loads(text[text.find("{"):text.rfind("}") + 1])
                    except Exception as ex:
                        logger.warning(f"Enrichment parse failed for {eid}: {ex}")

                    for field, rel, dlabel in [
                        ("ideology", "DRIVEN_BY", "Dim_ideology"),
                        ("motive", "DRIVEN_BY", "Dim_motive"),
                        ("ttp", "USES_TTP", "Dim_ttp"),
                        ("claimed_by", "CLAIMED_BY", "Dim_claimed_by"),
                    ]:
                        val = str(extracted.get(field) or "").strip()
                        if not val or val.lower() in ("unknown", "none"): continue
                        await driver.execute_query(
                            f"""
                            MERGE (r:{label} {{entity_id: $eid}})
                            MERGE (d:{dlabel} {{value: $val}})
                            SET d.name = $val, d.field = $field, d.provenance = 'llm_enrichment'
                            MERGE (r)-[:{rel}]->(d)
                            """, eid=eid, val=val, field=field
                        )
                    inst_key = "weapons" if extracted.get("weapons") else "tools"
                    instruments = extracted.get(inst_key) or []
                    if isinstance(instruments, list):
                        dlabel = "Dim_weapon" if inst_key == "weapons" else "Dim_tool"
                        rel = "USED_WEAPON" if inst_key == "weapons" else "USED_TOOL"
                        wbatch = [{"eid": eid, "w": str(w).strip()} for w in instruments if str(w).strip()]
                        if wbatch:
                            await driver.execute_query(
                                f"""
                                UNWIND $batch AS item
                                MERGE (r:{label} {{entity_id: item.eid}})
                                MERGE (d:{dlabel} {{value: item.w}})
                                SET d.name = item.w, d.field = $field, d.provenance = 'llm_enrichment'
                                MERGE (r)-[:{rel}]->(d)
                                """, batch=wbatch, field=inst_key
                            )
                    raw_graph.query(f"MATCH (r:{label} {{entity_id: $eid}}) SET r.enriched_hubs = true", {"eid": eid})

                if run_narrative:
                    extra = f" Analyst extraction: {json.dumps(extracted, default=str)}" if extracted else ""
                    body = (f"{props.get('date', '')} — {props.get('location', '')}. "
                            f"{props.get('blurb') or props.get('name') or ''}{extra}")
                    await graphiti.add_episode(
                        name=f"[ENRICH] {label} {str(eid)[:8]}",
                        episode_body=body, source=EpisodeType.text,
                        source_description="LLM enrichment episode",
                        reference_time=datetime.now(timezone.utc)
                    )
                    raw_graph.query(f"MATCH (r:{label} {{entity_id: $eid}}) SET r.enriched_narrative = true", {"eid": eid})

                progress_store[job_id]["current"] = i + 1
                logger.info(f"Enrichment {i+1}/{len(rows)}: {str(eid)[:8]}")

        if run_stitch:
            raw_graph.query(
                "MATCH (e:Entity), (p:Dim_perpetrator) "
                "WHERE toLower(e.name) = toLower(p.value) "
                "MERGE (e)-[:SAME_AS]->(p)"
            )
        progress_store[job_id]["status"] = "complete"
        logger.info("Enrichment complete")
    except Exception as e:
        logger.error(f"Enrichment job {job_id} failed: {e}")
        progress_store[job_id]["status"] = "error"
        progress_store[job_id]["error"] = str(e)

@app.post("/enrich")
async def enrich(
    label: str = Form(...),
    run_hubs: bool = Form(True),
    run_narrative: bool = Form(False),
    run_stitch: bool = Form(True),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    job_id = str(uuid.uuid4())
    create_job(job_id, 0, f"enrich:{label}", source="ui")
    background_tasks.add_task(run_enrichment, job_id, label, run_hubs, run_narrative, run_stitch)
    return {"job_id": job_id, "message": f"Enrichment started for {label}"}

# ==========================================
# 9. SYSTEM ENDPOINTS (Episodic label fix)
# ==========================================
@app.get("/stats")
async def get_stats():
    try:
        node_result = await driver.execute_query("MATCH (n) RETURN count(n) as count")
        edge_result = await driver.execute_query("MATCH ()-[r]->() RETURN count(r) as count")
        episode_result = await driver.execute_query("MATCH (e:Episodic) RETURN count(e) as count")

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
        result = await driver.execute_query(f"MATCH (e:Episodic) RETURN e.name as name, e.source_description as description, e.reference_time as time ORDER BY e.reference_time DESC LIMIT {limit}")
        return {"recent_episodes": [{"name": row[0], "description": row[1], "time": str(row[2])} for row in result]}
    except Exception as e: return {"error": str(e)}
