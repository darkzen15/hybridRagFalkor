import os
import json
import uuid
import time
from datetime import datetime, timezone
from typing import Optional, List, Union

import requests
from fastmcp import FastMCP
from falkordb import FalkorDB

TIIS_API = os.getenv("TIIS_API", "http://localhost:8000")
FALKORDB_HOST = os.getenv("FALKORDB_HOST", "localhost")
FALKORDB_PORT = int(os.getenv("FALKORDB_PORT", 6379))
FALKORDB_DATABASE = os.getenv("FALKORDB_DATABASE", "threat_intel")

mcp = FastMCP("TIIS Threat Intelligence")

_db = FalkorDB(host=FALKORDB_HOST, port=FALKORDB_PORT)
_graph = _db.select_graph(FALKORDB_DATABASE)


def _sanitize(s) -> str:
    clean = "".join(c if c.isalnum() else "_" for c in str(s))
    return clean or "field"


def _retry_query(query: str, params: dict, attempts: int = 3) -> None:
    """Executes a Cypher query with automatic retry for transient network drops."""
    for i in range(attempts):
        try:
            _graph.query(query, params)
            return
        except Exception as e:
            if i == attempts - 1:
                raise e
            time.sleep(1)


# ==========================================
# READ TOOL
# ==========================================
@mcp.tool()
def query_threat_graph(query: str, limit: int = 10) -> str:
    """Search the local threat intelligence knowledge graph (FalkorDB + Graphiti).
    Returns narrative facts from ingested PDFs/articles and structured records
    from ingested JSON datasets (terror events, MITRE ATT&CK, cyber incidents).
    Use this for any question about attacks, perpetrators, targets, TTPs, or actors."""
    lines = []
    try:
        r = requests.post(f"{TIIS_API}/query", json={"query": query, "limit": limit}, timeout=120)
        if r.ok:
            facts = [e["fact"] for e in r.json().get("episodes", []) if isinstance(e, dict) and e.get("fact")]
            if facts:
                lines.append("NARRATIVE INTELLIGENCE (reports, PDFs, articles):")
                lines += [f"- {f}" for f in facts]
    except Exception as e:
        lines.append(f"(narrative search error: {e})")

    try:
        r2 = requests.post(f"{TIIS_API}/search-structured", json={"query": query, "limit": limit}, timeout=30)
        if r2.ok:
            results = r2.json().get("results", [])
            if results:
                lines.append("\nSTRUCTURED INTELLIGENCE (JSON databases):")
                for m in results:
                    lines.append(f"- [{m.get('type')}] {m.get('identifier')}")
                    for k, v in (m.get("properties") or {}).items():
                        lines.append(f"    {k}: {v}")
    except Exception as e:
        lines.append(f"(structured search error: {e})")

    return "\n".join(lines) if lines else "No relevant intelligence found in the local graph."


# ==========================================
# WRITE TOOL 1 — Analyst notes (Instant, non-blocking)
# ==========================================
@mcp.tool()
def save_analyst_note(text: str, classification: str = "Analyst Note") -> str:
    """Save a free-text intelligence observation, assessment, or summary into the
    knowledge graph's narrative layer. The local LLM extracts entities and
    relationships from the note automatically, making it searchable later.
    Use this for prose: assessments, source summaries, meeting notes, hypotheses."""
    try:
        if not text or not text.strip():
            return "Error: Note text cannot be empty."

        r = requests.post(
            f"{TIIS_API}/ingest-text",
            json={"text": text, "source_type": classification, "source_name": "MCP Client"},
            timeout=60,
        )
        if r.ok:
            data = r.json()
            return f"Success: Note queued for background extraction (Job ID: {data.get('job_id', 'unknown')}). It will be searchable in 30-90 seconds."
        return f"Failed to save note: {r.status_code} {r.text[:200]}"
    except requests.exceptions.Timeout:
        return "Note submitted to worker, but response timed out. It is likely processing in the background."
    except Exception as e:
        return f"Error saving note: {e}"


# ==========================================
# WRITE TOOL 2 — Structured records (JSON-resilient)
# ==========================================
@mcp.tool()
def add_incident_record(
    dataset: str,
    record: Union[dict, str],
    dimension_fields: Optional[List[str]] = None
) -> str:
    """Add a structured intelligence record to the knowledge graph with hub links.
    Use this for factual event data with discrete fields.
    ALWAYS include a short descriptive 'name' field in the record so re-ingestion stays idempotent.

    :param dataset: Target dataset label, e.g. 'analyst_events' (new) or an existing dataset name.
    :param record: The record as key/value fields. Can be passed as a JSON object or a JSON string.
    :param dimension_fields: Optional list of record fields to turn into shared hub nodes.
    :return: Confirmation with the record's entity_id.
    """
    try:
        # 1. Robust JSON Parsing (Fixes LLMs passing strings instead of objects)
        if isinstance(record, str):
            try:
                record = json.loads(record)
            except json.JSONDecodeError:
                return "Error: 'record' was provided as a string but is not valid JSON. Please format it as a proper JSON object."

        if not isinstance(record, dict):
            return "Error: 'record' must be a valid JSON object/dictionary."

        label = _sanitize(dataset)
        safe = {}

        # 2. Type Coercion (Ensures FalkorDB only gets primitives or lists of primitives)
        for k, v in record.items():
            key = _sanitize(k)
            if v is None:
                continue
            if isinstance(v, (str, int, float, bool)):
                safe[key] = v.strip() if isinstance(v, str) else v
            elif isinstance(v, list):
                clean_list = []
                for item in v:
                    if isinstance(item, (str, int, float, bool)):
                        clean_list.append(item.strip() if isinstance(item, str) else item)
                    elif item is not None:
                        clean_list.append(str(item))
                safe[key] = clean_list
            else:
                safe[key] = json.dumps(v)

        entity_id = str(record.get("id") or record.get("guid") or record.get("uuid") or record.get("name") or uuid.uuid4())
        safe["entity_id"] = entity_id
        now_iso = datetime.now(timezone.utc).isoformat()
        source = f"mcp:{dataset}"

        # 3. Write record node + provenance (with retry)
        _retry_query(
            f"""
            UNWIND $batch AS item
            MERGE (r:{label} {{entity_id: item.entity_id}})
            ON CREATE SET r += item, r.ingested_from = $source, r.ingested_at = $now
            ON MATCH SET r += item, r.last_updated = $now
            WITH r, item
            MERGE (s:Source {{name: $source}})
            MERGE (r)-[:FROM_SOURCE]->(s)
            """,
            {"batch": [safe], "source": source, "now": now_iso},
        )

        # 4. Write dimension hubs (with retry)
        hubs_made = []
        for field in (dimension_fields or []):
            sfield = _sanitize(field)
            if sfield not in safe or safe[sfield] is None:
                continue

            val = safe[sfield]
            vals = [str(x) for x in val if x is not None] if isinstance(val, list) else [str(val)]
            if not vals:
                continue

            rel = {"year": "OCCURRED_IN", "industry": "TARGETS_INDUSTRY", "attacktype": "CLASSIFIED_AS"}.get(sfield.lower(), "HAS_" + sfield.upper())
            dlabel = "Dim_" + sfield

            _retry_query(
                f"""
                MERGE (r:{label} {{entity_id: $eid}})
                WITH r
                UNWIND $vals AS val
                MERGE (d:{dlabel} {{value: val}})
                SET d.name = val, d.field = $field
                MERGE (r)-[:{rel}]->(d)
                """,
                {"eid": entity_id, "vals": vals, "field": sfield},
            )
            hubs_made.append(dlabel)

        return f"Success: Record written to dataset '{label}' (entity_id: {entity_id}). Provenance: {source}. Hubs linked: {', '.join(hubs_made) if hubs_made else 'none'}."
    except Exception as e:
        return f"Error writing record: {e}"
