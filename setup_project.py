#!/usr/bin/env python3
"""
TIIS PLATFORM SETUP / UPDATER
One command to build, deploy, verify, and (optionally) reset + reload the entire stack.

Examples:
    python setup.py                          # build + up + ensure OpenWebUI + health check
    python setup.py --no-build               # redeploy without rebuilding images
    python setup.py --wipe                   # also delete the threat_intel graph (fresh start)
    python setup.py --reingest data          # force-upload every .json/.pdf/.txt/.md in ./data
    python setup.py --enrich-all             # queue hub+stitch enrichment for every dataset
    python setup.py --wipe --reingest data --enrich-all   # full reset pipeline
    python setup.py --status                 # just health-check everything
"""
import argparse
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKER = "http://localhost:8000"
NETWORK = "localllm_default"
GRAPH = "threat_intel"

def log(msg): print(f"[TIIS] {msg}", flush=True)

def compose_cmd():
    try:
        subprocess.run(["docker", "compose", "version"], check=True, capture_output=True)
        return ["docker", "compose"]
    except Exception:
        return ["docker-compose"]

def run(cmd, check=True, cwd=ROOT):
    log(f"$ {' '.join(map(str, cmd))}")
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and r.returncode != 0:
        log(f"FAILED ({r.returncode}):\n{r.stdout}\n{r.stderr}")
        sys.exit(1)
    return r

def wait_http(url, timeout=180, expect_json=False):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                if r.status == 200:
                    return json.load(r) if expect_json else True
        except Exception:
            pass
        time.sleep(3)
    return None

def build():
    run(compose_cmd() + ["build", "graphiti-worker", "ingest-ui"])

def up():
    run(compose_cmd() + ["up", "-d"])

def ensure_openwebui(recreate=False):
    exists = run(["docker", "inspect", "openwebui"], check=False).returncode == 0
    if exists and not recreate:
        run(["docker", "start", "openwebui"], check=False)
        log("OpenWebUI container present.")
        return
    if exists:
        run(["docker", "stop", "openwebui"], check=False)
        run(["docker", "rm", "openwebui"], check=False)
    log("Creating OpenWebUI container...")
    run([
        "docker", "run", "-d", "--name", "openwebui", "--network", NETWORK,
        "-p", "8080:8080",
        "-v", f"{ROOT / 'openwebui_data'}:/app/backend/data",
        "-e", "OLLAMA_BASE_URL=http://host.docker.internal:11434",
        "-e", "WEBUI_AUTH=false",
        "-e", "ENABLE_RAG=true",
        "-e", "ENABLE_TITLE_GENERATION=0",
        "ghcr.io/open-webui/open-webui:main",
    ])

def wipe_graph():
    log("Wiping graph (containers and configs are preserved)...")
    run(["docker", "exec", "falkordb", "redis-cli", "GRAPH.DELETE", GRAPH], check=False)
    run(compose_cmd() + ["restart", "graphiti-worker"])

def reingest(folder: Path):
    files = [p for p in sorted(folder.iterdir()) if p.suffix.lower() in (".json", ".pdf", ".txt", ".md")]
    if not files:
        log(f"No ingestible files found in {folder}")
        return
    for p in files:
        log(f"Uploading {p.name} (force)...")
        r = run(["curl", "-s", "-X", "POST", f"{WORKER}/upload",
                 "-F", f"files=@{p}", "-F", "source_type=Manual Upload", "-F", "force=true"], check=False)
        try:
            jobs = json.loads(r.stdout).get("jobs", [])
            log(f"  queued {len(jobs)} job(s)")
        except Exception:
            log(f"  response: {r.stdout[:200]}")

def enrich(labels=None, narrative=False):
    info = wait_http(f"{WORKER}/record-labels", timeout=30, expect_json=True)
    all_labels = (info or {}).get("labels", [])
    targets = all_labels if labels in (None, ["all"]) else [l for l in (labels or []) if l in all_labels]
    if not targets:
        log("No record labels to enrich.")
        return
    for lbl in targets:
        data = urllib.parse.urlencode({
            "label": lbl, "run_hubs": "true",
            "run_narrative": "true" if narrative else "false",
            "run_stitch": "true",
        }).encode()
        req = urllib.request.Request(f"{WORKER}/enrich", data=data)
        try:
            urllib.request.urlopen(req, timeout=30)
            log(f"Enrichment queued: {lbl}")
        except Exception as e:
            log(f"Enrichment failed for {lbl}: {e}")

def health():
    checks = [
        ("graphiti-worker :8000", f"{WORKER}/stats", True),
        ("TIIS Streamlit  :8501", "http://localhost:8501", False),
        ("FalkorDB UI     :3000", "http://localhost:3000", False),
        ("OpenWebUI       :8080", "http://localhost:8080", False),
    ]
    log("Health checks:")
    for name, url, as_json in checks:
        res = wait_http(url, timeout=120, expect_json=as_json)
        if as_json and res:
            log(f"  [OK]   {name}  nodes={res.get('nodes')} edges={res.get('edges')} episodes={res.get('episodes')} jobs={res.get('active_jobs')}")
        elif res:
            log(f"  [OK]   {name}")
        else:
            log(f"  [FAIL] {name}")

def ensure_gitignore():
    gi = ROOT / ".gitignore"
    if not gi.exists():
        gi.write_text(
            "openwebui_data/\nfalkordb_data/\ningest_config/\n__pycache__/\n*.pyc\n.env\nThumbs.db\nDesktop.ini\n",
            encoding="utf-8",
        )
        log("Created .gitignore")

def main():
    ap = argparse.ArgumentParser(description="TIIS platform setup/updater")
    ap.add_argument("--no-build", action="store_true", help="skip docker compose build")
    ap.add_argument("--wipe", action="store_true", help="delete the threat_intel graph first")
    ap.add_argument("--reingest", metavar="DIR", help="force-upload all ingestible files in DIR")
    ap.add_argument("--enrich", nargs="*", metavar="LABEL", help="enrich specific labels (or 'all')")
    ap.add_argument("--enrich-all", action="store_true", help="enrich every dataset (hubs+stitch)")
    ap.add_argument("--enrich-narrative", action="store_true", help="include slow Graphiti episode layer")
    ap.add_argument("--recreate-openwebui", action="store_true", help="destroy and recreate the OpenWebUI container")
    ap.add_argument("--skip-openwebui", action="store_true")
    ap.add_argument("--status", action="store_true", help="health check only, change nothing")
    args = ap.parse_args()

    if args.status:
        health()
        return

    ensure_gitignore()
    if not args.no_build:
        build()
    up()
    if not args.skip_openwebui:
        ensure_openwebui(recreate=args.recreate_openwebui)
    log("Waiting for worker...")
    if not wait_http(f"{WORKER}/stats", timeout=180, expect_json=True):
        log("Worker never became healthy. Check: docker compose logs graphiti-worker --tail 40")
        sys.exit(1)
    if args.wipe:
        wipe_graph()
        wait_http(f"{WORKER}/stats", timeout=180, expect_json=True)
    if args.reingest:
        reingest(Path(args.reingest))
    if args.enrich_all or args.enrich:
        enrich(labels="all" if args.enrich_all else args.enrich, narrative=args.enrich_narrative)
    health()
    log("Done. UIs: http://localhost:8501 (TIIS) | http://localhost:8080 (chat) | http://localhost:3000 (graph)")

if __name__ == "__main__":
    main()
