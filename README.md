# TIIS — Tactical Intelligence Ingestion System
### Local, Air-Gapped, Hybrid-Engine Threat Intelligence Platform · v2.1

> *Handling caveat: This system processes structured and unstructured intelligence entirely on local hardware. No data leaves the host machine.*

---

## Table of Contents
1. [Executive Overview](#1-executive-overview)
2. [System Architecture](#2-system-architecture)
3. [Repository Layout & Persistence](#3-repository-layout--persistence)
4. [Prerequisites](#4-prerequisites)
5. [Installation](#5-installation)
6. [Starting, Stopping, Updating](#6-starting-stopping-updating)
7. [Configuration Reference](#7-configuration-reference)
8. [Operator Guide: Ingestion](#8-operator-guide-ingestion)
9. [Analyst Guide: Querying & Chat](#9-analyst-guide-querying--chat)
10. [API Reference](#10-api-reference)
11. [Graph Schema Reference](#11-graph-schema-reference)
12. [Backup & Restore](#12-backup--restore)
13. [Maintenance Operations](#13-maintenance-operations)
14. [Troubleshooting](#14-troubleshooting)
15. [Performance & Tuning](#15-performance--tuning)
16. [Security Posture](#16-security-posture)
17. [Roadmap](#17-roadmap)
18. [Quick Reference Cheat Sheet](#18-quick-reference-cheat-sheet)
- [Appendix A: OpenWebUI Tool Source](#appendix-a-openwebui-tool-source)
- [Appendix B: Endpoint Test Snippets](#appendix-b-endpoint-test-snippets)

---

## 1. Executive Overview

TIIS is a self-hosted threat intelligence platform that combines:

- **A temporal knowledge graph** (FalkorDB + Graphiti) that extracts entities and relationships from unstructured text using a local LLM.
- **A deterministic semantic mapper** that converts structured JSON datasets (STIX-like bundles, incident lists, MITRE exports) into a dimensional "star schema" graph in seconds — no LLM involved.
- **A classified-style ingestion console** (Streamlit) with duplicate detection, batch queues, live progress, RSS automation, and a persistent audit log.
- **An analyst chat interface** (Open WebUI + local Ollama models) with a hybrid retrieval tool that answers questions from *both* the narrative graph and the structured graph, with zero cloud dependency.

**Design principles:** air-gapped operation, idempotent ingestion (`MERGE`-based, safe to re-run), hybrid engines (LLM where meaning must be inferred, Cypher where structure already exists), and graceful degradation (every pipeline stage logs and reports status).

---

## 2. System Architecture

### 2.1 Component Map

```
                        ┌────────────────────────────────────────────┐
                        │              HOST MACHINE (Windows)        │
                        │                                            │
                        │   ┌──────────────────────────────────┐     │
                        │   │  Ollama  (:11434)                │     │
                        │   │  • qwen2.5-coder:14b   (LLM)     │     │
                        │   │  • nomic-embed-text    (embed)   │     │
                        │   └──────────────▲───────────────────┘     │
                        │                  │ host.docker.internal    │
   ┌───────────────┐    │  ┌───────────────┴──────────────────────┐   │
   │  ANALYST      │    │  │         DOCKER NETWORK               │   │
   │  browser      │    │  │  (localllm_default)                  │   │
   └───┬───┬───┬───┘    │  │                                      │   │
       │   │   │        │  │  ┌─────────────┐   ┌──────────────┐  │   │
       │   │   └───────────►│ OpenWebUI    │   │ Streamlit    │  │   │
       │   │            │  │ │ :8080      │   │ TIIS UI      │  │   │
       │   │            │  │ │ + Hybrid   │   │ :8501        │  │   │
       │   │            │  │ │ Search Tool│   │ (ingest-ui)  │  │   │
       │   │            │  │ └─────┬──────┘   └──────────────┘  │   │
       │   │            │  │       │  HTTP            │ HTTP    │   │
       │   │            │  │  ┌────▼──────────────────▼──────┐  │   │
       │   │            │  │  │  graphiti-worker (FastAPI)   │  │   │
       │   │            │  │  │  :8000                       │  │   │
       │   │            │  │  │  • /upload  /ingest-url      │  │   │
       │   │            │  │  │  • /query   /search-structured│ │   │
       │   │            │  │  │  • Graphiti engine (LLM)     │  │   │
       │   │            │  │  │  • Semantic Cypher engine    │  │   │
       │   │            │  │  │  • APScheduler (RSS 30 min)  │  │   │
       │   │            │  │  └────┬─────────────────────────┘  │   │
       │   │            │  │       │ Redis protocol             │   │
       │   │            │  │  ┌────▼─────────────┐  ┌─────────┐ │   │
       │   └───────────────►│ FalkorDB :6379    │  │ FalkorDB│ │   │
       │                │  │  │ graph:threat_intel│  │ UI :3000│ │   │
       └───────────────────►│                  │  └─────────┘ │   │
                        │  │  └─────────────────┘              │   │
                        │  └──────────────────────────────────────┘   │
                        └────────────────────────────────────────────┘
```

### 2.2 Service Table

| Service | Image / Origin | Port | Role |
|---|---|---|---|
| `falkordb` | `falkordb/falkordb:latest` (compose) | 6379 (db), 3000 (UI) | Graph database + visual explorer |
| `graphiti-worker` | built from `graphiti_app/` (compose) | 8000 | FastAPI backend: ingestion engines, search API, scheduler |
| `ingest-ui` | built from `ingest_ui/` (compose) | 8501 | Streamlit classified-style console |
| `openwebui` | `ghcr.io/open-webui/open-webui:main` (**standalone `docker run`**) | 8080 | Analyst chat + tool execution |
| Ollama | host install | 11434 | Local LLM + embedding inference |

> **Note:** `openwebui` is *not* part of `docker-compose.yml`. It is managed with plain `docker` commands and attached to the compose network `localllm_default`. See §5.4.

### 2.3 The Two Ingestion Engines

**Engine A — Unstructured (LLM, Graphiti).** For PDF, TXT, MD, and scraped URLs.
1. Text extracted (`pypdf` / `trafilatura`).
2. Whitespace-normalized and split into 3,000-character chunks.
3. Each chunk → `graphiti.add_episode(..., source=EpisodeType.text)`.
4. Graphiti runs the local LLM to extract entities, relationships (`fact` sentences), and temporal metadata; embeddings are computed with `nomic-embed-text`.
5. Result: `Episode`, `Entity` nodes and `EntityEdge` relationships, searchable by vector + graph traversal.
*Cost: slow (LLM-bound, ~30–90 s/chunk). Value: infers meaning that isn't explicitly written.*

**Engine B — Structured (deterministic Cypher).** For JSON.
1. JSON parsed; top-level list or `objects` array selected.
2. **Dimension auto-detection:** fields whose distinct-value count is `> 1 and <= 60` become hub dimensions (e.g., `year`, `industry`, `attackType`); high-cardinality fields (`name`, `guid`) stay as node properties; nested objects/lists-of-objects are JSON-stringified (FalkorDB only stores primitives).
3. Bulk `UNWIND ... MERGE` batches of 500 records create:
   - record nodes labeled after the file (e.g., `:cyberattacks`), keyed by `entity_id` (priority: `id` → `guid` → `uuid` → `name` → random UUID);
   - a `:Source` provenance node per file (`FROM_SOURCE` edge);
   - `:Dim_<field>` hub nodes with semantic edges (`OCCURRED_IN`, `TARGETS_INDUSTRY`, `CLASSIFIED_AS`, …).
4. Result: an instantly queryable star schema.
*Cost: seconds for thousands of records. Value: exact, hallucination-free structural data.*

### 2.4 Hybrid Retrieval (OpenWebUI tool)

Every chat query runs two searches in parallel:
- **Narrative:** `POST /query` → `graphiti.search()` → relationship facts from Engine A.
- **Structured:** `POST /search-structured` → keyword-scored scan of every node property (phrase match +5, keyword match +1) → Engine B records and hubs.
Results are merged into a single report the LLM cites when answering.

---

## 3. Repository Layout & Persistence

```
C:\Users\JJ\Desktop\LocalLLM\
├── docker-compose.yml            # falkordb, graphiti-worker, ingest-ui
├── README.md                     # this document
├── falkordb_data\                # PERSISTENT graph database files
├── ingest_config\                # PERSISTENT worker state
│   ├── ingestion_history.json    #   audit log (files + URLs ingested)
│   └── sources.json              #   registered RSS feeds
├── openwebui_data\               # PERSISTENT chat history, users, tools
├── graphiti_app\
│   ├── Dockerfile                # python:3.11-slim + git + pip deps
│   ├── requirements.txt
│   └── main.py                   # FastAPI worker (both engines + API)
└── ingest_ui\
    ├── Dockerfile
    └── app.py                    # Streamlit TIIS console
```

**Nothing of value lives inside containers.** Wiping containers is always safe; wiping the three data folders is not.

---

## 4. Prerequisites

| Requirement | Notes |
|---|---|
| Windows 10/11 + PowerShell | All commands below are PowerShell-safe |
| Docker Desktop (WSL2) | Compose v2 (`docker compose`, not `docker-compose`) |
| Ollama installed on host | `https://ollama.com` |
| LLM model | `ollama pull qwen2.5-coder:14b` (or set `LLM_MODEL`) |
| Embedding model | `ollama pull nomic-embed-text` (768-dim) |
| ~16 GB RAM free | 14B model + Docker stack |
| Disk | Size of your intel corpus × ~2 |

---

## 5. Installation

### 5.1 Core stack
```powershell
cd C:\Users\JJ\Desktop\LocalLLM
docker compose build
docker compose up -d
docker compose ps        # expect: falkordb / graphiti-worker / ingest-ui  = Up
```

### 5.2 Verify worker health
```powershell
docker compose logs graphiti-worker --tail 20
# expect: "Application startup complete." and "Uvicorn running on http://0.0.0.0:8000"
```

### 5.3 First-run smoke test
Browser checks:
- `http://localhost:8501` → TIIS console with red classification banner
- `http://localhost:3000` → FalkorDB explorer (graph `threat_intel`)
- `http://localhost:8000/docs` → FastAPI Swagger (worker)

### 5.4 Open WebUI (standalone container)
```powershell
docker run -d --name openwebui --network localllm_default -p 8080:8080 `
  -v C:\Users\JJ\Desktop\LocalLLM\openwebui_data:/app/backend/data `
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434 `
  -e WEBUI_AUTH=false `
  -e ENABLE_RAG=true `
  -e ENABLE_TITLE_GENERATION=0 `
  ghcr.io/open-webui/open-webui:main
```
> `ENABLE_TITLE_GENERATION=0` works around an upstream Open WebUI `KeyError: 'model'` crash in the auto-title background task. Chat titles become manual (pencil icon in sidebar).

### 5.5 Install the Hybrid Search tool
1. Open `http://localhost:8080` → **Workspace → Tools → New Tool**.
2. Paste the full source from **Appendix A**. Save.
3. In each chat, toggle the tool **ON** (tool icon above the message box).

---

## 6. Starting, Stopping, Updating

```powershell
docker compose up -d                     # start core stack
docker compose down                      # stop (data preserved)
docker compose restart graphiti-worker   # reload worker
docker compose logs -f graphiti-worker   # live backend logs
docker start openwebui                   # start chat UI
docker stop openwebui                    # stop chat UI
```

**Code changes:** `graphiti_app/` and `ingest_ui/` are baked into images at build time. After editing `main.py` or `app.py`:
```powershell
docker compose build graphiti-worker ingest-ui
docker compose up -d
```
After editing `requirements.txt` or a `Dockerfile`, use `docker compose build --no-cache <service>`.

---

## 7. Configuration Reference

### 7.1 Worker environment variables (compose)

| Variable | Default | Purpose |
|---|---|---|
| `FALKORDB_HOST` | `falkordb` | DB service name |
| `FALKORDB_PORT` | `6379` | Redis protocol port |
| `FALKORDB_DATABASE` | `threat_intel` | Graph name |
| `OLLAMA_BASE_URL` | `http://host.docker.internal:11434/v1` | LLM/embedding endpoint |
| `LLM_MODEL` | `qwen2.5-coder:14b` | Extraction model |
| `EMBEDDING_MODEL` | `nomic-embed-text:latest` | Embedding model (768-dim) |
| `OPENAI_API_KEY` | dummy value | Required by OpenAI-compatible client; ignored by Ollama |

### 7.2 Tunables inside `graphiti_app/main.py`

| Constant / parameter | Default | Effect |
|---|---|---|
| `chunk_text(chunk_size=)` | 3000 | Characters per LLM episode (PDF/TXT/URL) |
| `batch_size` (JSON engine) | 500 | Records per Cypher transaction |
| `detect_dimension_fields(max_distinct=)` | 60 | Max distinct values for a field to become a hub |
| `DIMENSION_EDGE_NAMES` | year→`OCCURRED_IN`, industry→`TARGETS_INDUSTRY`, attacktype→`CLASSIFIED_AS`, country→`LOCATED_IN`, type→`IS_TYPE` | Semantic edge naming; fallback `HAS_<FIELD>` |
| RSS interval | 30 minutes | `scheduler.add_job(..., 'interval', minutes=30)` |
| UI request timeouts (`ingest_ui/app.py`) | 30 s | Raise if backend is busy |

### 7.3 OpenWebUI tool valves
| Valve | Default | Fallback |
|---|---|---|
| `api_url` | `http://host.docker.internal:8000` | `http://graphiti-worker:8000` if host alias fails |

---

## 8. Operator Guide: Ingestion

### Tab 01 // SYSTEM OVERVIEW
Live metrics (nodes / edges / episodes / active jobs), recent episodes, and entity/relationship samples. Use it as a health dashboard after each ingestion.

### Tab 02 // DOCUMENT INGESTION
- **Formats:** PDF, TXT, JSON, MD. Multi-select supported; each file gets its own job + progress bar.
- **Source Classification:** free-form tag stored in the audit log (and episode names).
- **Custom Extraction Directives:** *collected but not yet applied* to LLM extraction (see Roadmap).
- **Duplicates:** re-uploading a known filename returns HTTP 409; the UI offers **AUTHORIZE FORCE RE-INGEST**, which re-runs with `force=true`. All writes are `MERGE`-based, so re-ingestion updates rather than duplicates.
- **PDF/TXT/MD** → Engine A (slow, deep). **JSON** → Engine B (fast, structural).

### Tab 03 // OSINT COLLECTION
- Fetches a URL, extracts the article body with `trafilatura`, chunks, and runs Engine A.
- Government/enterprise sites with WAFs may time out (`ReadTimeoutError` warnings in logs are normal and non-fatal). **Workaround:** save the page as PDF/TXT locally and use Tab 02.

### Tab 04 // AUTOMATED FEEDS
- Register RSS/feed URLs; the worker polls every 30 minutes and ingests the first ~2,000 characters per feed via Engine A.
- `TERMINATE` removes a feed from `ingest_config/sources.json`.

### Tab 05 // AUDIT LOG
- Two tables (documents / URLs) from `ingest_config/ingestion_history.json`: name, classification, chunk/item count, timestamp. This file is your chain-of-custody record — back it up.

---

## 9. Analyst Guide: Querying & Chat

### 9.1 Chat workflows (OpenWebUI)
Enable the Hybrid tool, then ask cross-source questions:
- *"What industries are targeted by untargeted attacks?"*
- *"Summarize the cyberattacks that occurred in 2018."*
- *"Compare water-sector incidents in the graph with this report's findings."* (after ingesting a relevant PDF)
The tool output panel shows which source answered (`NARRATIVE INTELLIGENCE` vs `STRUCTURED INTELLIGENCE`).

### 9.2 FalkorDB explorer (`http://localhost:3000`)
- Select graph `threat_intel`.
- **Node captions:** click a label chip in the legend → set Caption to `name` (or `value`). Hubs display names once `name` is stamped; otherwise the UI falls back to internal node IDs.
- Avoid the default full-graph query on large graphs; expand from a single hub node instead.

### 9.3 Cypher cookbook (run in the explorer query box)

```cypher
// Label census
MATCH (n) RETURN head(labels(n)) AS label, count(n) AS cnt ORDER BY cnt DESC

// Industry heat map
MATCH (i:Dim_industry)<-[:TARGETS_INDUSTRY]-(a:cyberattacks)
RETURN i.name AS Industry, count(a) AS Total ORDER BY Total DESC

// Attacks in a year
MATCH (a:cyberattacks)-[:OCCURRED_IN]->(y:Dim_year)
WHERE y.value = 2020 RETURN a.name, a.industry LIMIT 25

// Everything about one hub
MATCH (a)-[r]->(h:Dim_attackType {name: "Untargeted Attack"}) RETURN a.name, type(r), h.name

// Purge a label (e.g., experimental junk)
MATCH (n:SomeLabel) DETACH DELETE n
```

---

## 10. API Reference (worker, `:8000`)

| Method & path | Body / params | Purpose |
|---|---|---|
| `POST /upload` | multipart `files[]`, `source_type`, `custom_prompt`, `force` | Queue files; returns `jobs[]` with `job_id`, `total_chunks`. 409 on duplicates unless `force=true` |
| `POST /ingest-url` | form `url`, `source_type`, `custom_prompt`, `force` | Scrape + ingest article |
| `GET /progress/{job_id}` | — | `{total, current, status: processing|complete|error, error?}` |
| `POST /query` | JSON `{query, limit}` | Graphiti semantic search → `{episodes:[{fact,...}]}` |
| `POST /search-structured` | JSON `{query, limit}` | Keyword-scored node scan → `{version, results:[{type, identifier, properties}]}` |
| `POST /ingest-text` | JSON `{text, source_type, source_name}` | Save analyst notes into the graph |
| `GET /history` | — | Audit log JSON |
| `GET /sources` / `POST /sources` / `DELETE /sources?url=` | — | RSS feed management |
| `GET /stats` | — | Node/edge/episode counts + active jobs |
| `GET /entities?limit=` / `GET /relationships?limit=` / `GET /recent?limit=` | — | Graph samples for the UI |
| `GET /debug-nodes` | — | Raw driver-shape diagnostic |

---

## 11. Graph Schema Reference

**Engine A (Graphiti):** `Episode`, `Entity` nodes; `EntityEdge` relationships carrying `fact`, temporal validity, and embeddings.

**Engine B (semantic JSON):**
- `:<filelabel>` record nodes — all sanitized primitive properties; `entity_id` (unique key), `ingested_from`, `ingested_at`, `last_updated`.
- `:Source {name}` — one per file; records link via `FROM_SOURCE`.
- `:Dim_<field> {value, name, field}` — shared hubs; records link via `OCCURRED_IN` / `TARGETS_INDUSTRY` / `CLASSIFIED_AS` / `HAS_<FIELD>`.

**Sanitization rules:** keys → alphanumeric+underscore; nested dicts & object-lists → JSON strings; flat primitive lists kept as arrays (FalkorDB property constraint).

---

## 12. Backup & Restore

**Backup:** copy `falkordb_data\`, `ingest_config\`, `openwebui_data\` (stop the stack first for a clean snapshot: `docker compose down`).
**Restore:** place folders back, `docker compose up -d`, `docker start openwebui`.
**Graph-only export alternative:** FalkorDB UI → export, or `docker exec -it falkordb redis-cli SAVE`.

---

## 13. Maintenance Operations

```powershell
# Full graph wipe (keeps containers/config)
docker exec -it falkordb redis-cli GRAPH.DELETE threat_intel
docker compose restart graphiti-worker     # rebuilds Graphiti indices
```
Re-ingestion is always safe (`MERGE` + content-keyed `entity_id`); use Force Re-ingest from the UI rather than wiping.

---

## 14. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'X'` after code change | Image not rebuilt | `docker compose build <svc> && docker compose up -d` |
| `Unknown function 'random'` / `'datetime'` | Neo4j-only Cypher functions | Generate IDs/timestamps in Python (already implemented) |
| `A WITH clause is required to introduce UNWIND after an updating clause` | Cypher clause-ordering rule | Bridge with `WITH source, $batch AS batch` (implemented) |
| `Property values can only be of primitive types...` | Nested JSON objects as properties | `sanitize_for_graph` stringifies nested values (implemented) |
| `Read timed out (read timeout=5)` in ingest-ui | Backend busy during LLM work | Timeouts raised to 30 s (implemented) |
| `UnboundLocalError: filename` / `NameError: process_json_background` | Partial code merges | Always replace whole files/blocks exactly as provided |
| Edges named `ELEMENT_0..N` | Structural json2graph mirror (retired) | Purge labels: `MATCH (n:cyberattacksItem) DETACH DELETE n` etc. |
| Nodes captioned as 3-digit numbers | Missing `name` property; UI falls back to node ID | `MATCH (d:Dim_x) SET d.name = d.value`; set caption per label in explorer |
| `/search-structured` returns `'NoneType' object is not subscriptable` | Graphiti driver returns raw Cypher strings for nodes | Use raw `falkordb` client `raw_graph.query(...)` (v3, implemented) |
| OpenWebUI crash `KeyError: 'model'` | Upstream title-generation bug | `ENABLE_TITLE_GENERATION=0` on the container |
| `no such service: openwebui` | Standalone container, not in compose | Manage with `docker start/stop/inspect openwebui` |
| Tool says "No relevant intelligence" while API has data | Tool can't reach worker | Switch valve `api_url` to `http://graphiti-worker:8000` |
| URL scrape warns `ReadTimeoutError` on gov sites | WAF/rate limiting | Download locally, ingest via Tab 02 |
| Worker restart-looping after an edit | Syntax/indentation error in `main.py` | `docker compose logs graphiti-worker --tail 30`; fix placement (module level, zero indent) |

---

## 15. Performance & Tuning

- **JSON:** thousands of records in seconds (batched `UNWIND`); progress bar tracks records, not chunks.
- **PDF/URL:** LLM-bound; expect ~30–90 s per 3,000-char chunk on a 14B local model. Multiple files queue concurrently — avoid uploading the same file repeatedly (each click creates a job).
- **`/search-structured`** scans all node properties per call (O(N)). Fine to ~100k nodes; beyond that, scope it by label.
- **Chunk size:** smaller chunks = more episodes = finer retrieval but slower ingestion and more LLM calls.
- **Dimension threshold (`max_distinct=60`):** raise for coarser hubs, lower to keep near-unique fields as properties.

---

## 16. Security Posture

- **Air-gapped inference:** LLM + embeddings run on-host via Ollama; no telemetry (`DO_NOT_TRACK`, `ANONYMIZED_TELEMETRY=false`, `SCARF_NO_ANALYTICS=true`).
- **Outbound network:** only explicit OSINT URL fetches and RSS polling from the worker.
- **`WEBUI_AUTH=false`:** acceptable only on a trusted local network. If the host is ever reachable by others, recreate the container with auth enabled and create an admin account.
- **Classification banner** is cosmetic labeling; apply your real handling caveats to the underlying folders (`falkordb_data`, `ingest_config`) with filesystem encryption at rest if required.

---

## 17. Roadmap

- Wire the UI's **Custom Extraction Directives** into `graphiti.add_episode` (custom extraction prompt) for focused PDF pulls (CVEs, TTPs, actors).
- Cross-engine entity resolution: link `:cyberattacks` records to Graphiti `Entity` nodes by name similarity.
- STIX/TAXII connector feeding Engine B.
- Label-scoped `/search-structured` + full-text index for >100k-node graphs.
- In-UI graph visualization (pyvis) on Tab 01.
- Scheduled graph snapshots to `falkordb_data/backups/`.

---

## 18. Quick Reference Cheat Sheet

```powershell
# Stack
docker compose up -d | down | restart graphiti-worker
docker compose build --no-cache graphiti-worker
docker compose logs -f graphiti-worker
docker start openwebui

# URLs
TIIS UI      http://localhost:8501
Chat         http://localhost:8080
Graph UI     http://localhost:3000   (graph: threat_intel)
API docs     http://localhost:8000/docs

# API smoke test (from inside the network)
docker compose exec ingest-ui python -c "import requests; print(requests.post('http://graphiti-worker:8000/search-structured', json={'query':'untargeted','limit':3}).text[:400])"

# Nuclear reset
docker exec -it falkordb redis-cli GRAPH.DELETE threat_intel
docker compose restart graphiti-worker
```

---

## Appendix A: OpenWebUI Tool Source

```python
"""
title: Hybrid Threat Intel Search
author: LocalLLM
version: 4.0
"""
import requests
from pydantic import BaseModel, Field

class Tools:
    class Valves(BaseModel):
        api_url: str = Field(default="http://host.docker.internal:8000")

    def __init__(self):
        self.valves = self.Valves()

    async def query_threat_graph(self, query: str, limit: int = 10) -> str:
        """
        Search the local Threat Intelligence Knowledge Graph for cyber threat intel,
        MITRE ATT&CK techniques, historical attacks, actors, malware, and OSINT data.
        :param query: The topic to search for (e.g. "lateral movement", "APT29", "ransomware 2021")
        :param limit: Maximum number of results per source
        :return: A formatted intelligence report combining narrative and structured data
        """
        lines = []

        try:
            r_test = requests.get(f"{self.valves.api_url}/history", timeout=5)
            if r_test.status_code != 200:
                return f"ERROR: Could not reach API at {self.valves.api_url}. Status: {r_test.status_code}"
        except Exception as e:
            return f"ERROR: Connection failed to {self.valves.api_url}. Details: {str(e)}"

        try:
            r = requests.post(f"{self.valves.api_url}/query",
                              json={"query": query, "limit": limit}, timeout=120)
            if r.status_code == 200:
                facts = [e["fact"] for e in r.json().get("episodes", [])
                         if isinstance(e, dict) and e.get("fact")]
                if facts:
                    lines.append("NARRATIVE INTELLIGENCE (reports, PDFs, articles):")
                    lines.extend(f"- {f}" for f in facts)
        except Exception as e:
            lines.append(f"(narrative search error: {e})")

        try:
            r2 = requests.post(f"{self.valves.api_url}/search-structured",
                               json={"query": query, "limit": limit}, timeout=120)
            if r2.status_code == 200:
                data = r2.json()
                results = data.get("results", [])
                if data.get("error"):
                    lines.append(f"(structured search backend error: {data['error']})")
                elif results:
                    lines.append("")
                    lines.append("STRUCTURED INTELLIGENCE (JSON databases):")
                    for m in results:
                        lines.append(f"- [{m.get('type')}] {m.get('identifier')}")
                        for k, v in (m.get("properties") or {}).items():
                            lines.append(f"    {k}: {v}")
                else:
                    lines.append("(structured search returned 0 results)")
            else:
                lines.append(f"(structured search HTTP error: {r2.status_code})")
        except Exception as e:
            lines.append(f"(structured search connection error: {e})")

        if not lines:
            return "No relevant intelligence found in the local graph."
        return "\n".join(lines)
```

## Appendix B: Endpoint Test Snippets

```powershell
# Structured search
docker compose exec ingest-ui python -c "import requests; r=requests.post('http://graphiti-worker:8000/search-structured', json={'query':'water','limit':3}); print(r.text[:600])"

# Narrative search
docker compose exec ingest-ui python -c "import requests; r=requests.post('http://graphiti-worker:8000/query', json={'query':'water utility','limit':3}); print(r.text[:600])"

# Stats
docker compose exec ingest-ui python -c "import requests; print(requests.get('http://graphiti-worker:8000/stats').text)"
```

---

*End of document. TIIS v2.1 — built, debugged, and operational.*
