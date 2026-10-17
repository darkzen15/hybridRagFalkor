# TIIS Air-Gapped Transfer Runbook

**System:** Tactical Intelligence Ingestion System (TIIS) v2.1
**Purpose:** Relocate the full platform from a connected machine to an air-gapped / SCIF environment.
**Key fact:** Containers bake in all Python dependencies, and `docker save` includes base-image layers, so **nothing needs internet on the target box** once exported correctly.

---

## Table of Contents
1. [What You're Transferring](#what-youre-transferring)
2. [Phase 1 — Export (Connected Machine)](#phase-1--export-connected-machine)
3. [Phase 2 — Transport](#phase-2--transport)
4. [Phase 3 — Prepare Air-Gapped Machine](#phase-3--prepare-air-gapped-machine)
5. [Phase 4 — Import and Launch](#phase-4--import-and-launch)
6. [Phase 5 — Verify](#phase-5--verify)
7. [Troubleshooting](#troubleshooting)
8. [Key Gotchas](#key-gotchas)

---

## What You're Transferring

| Category | Why | Approx Size |
|---|---|---|
| 5 Docker images | The whole platform (all deps baked in) | ~8–15 GB |
| Ollama models | LLM + embeddings (nothing works without these) | ~5 GB minimum |
| Project folder | `main.py`, `app.py`, `tiis_mcp.py`, compose, Dockerfiles | a few MB |
| Persistent data (optional) | Existing graph, config, OpenWebUI setup | varies |
| Offline installers | Docker Desktop + Ollama for the target | ~1 GB |

---

## Phase 1 — Export (Connected Machine)

### 1A. Get your exact image names
```powershell
docker images
```
Note the names of your five images. Based on the build they look like `localllm/falkordb`, `localllm/graphiti-worker`, `localllm/ingest-ui`, `localllm/tiis-mcp`, and `ghcr.io/open-webui/open-webui`. **Use whatever yours actually says.**

### 1B. Export the Docker images
Create a folder and save each image. `docker save` captures all layers including the base image, so the target needs no registry access.

```powershell
mkdir C:\tiis-transfer\images
cd C:\tiis-transfer\images

docker save -o falkordb.tar        <your-falkordb-image>
docker save -o graphiti-worker.tar <your-worker-image>
docker save -o ingest-ui.tar       <your-ui-image>
docker save -o tiis-mcp.tar        <your-mcp-image>
docker save -o openwebui.tar       <your-openwebui-image>
```

### 1C. Export the Ollama models
The models live in your user profile. Copy the whole `models` directory (this preserves the blob + manifest structure Ollama needs):

```
Source folder:  C:\Users\JJ\.ollama\models
```

Copy that entire `models` folder to `C:\tiis-transfer\ollama-models\`.

**Minimum you MUST transfer:**
- Your `LLM_MODEL` (currently `qwen2.5:latest`, ~4.7 GB)
- `nomic-embed-text:latest` (~274 MB) — **critical**, embeddings break without it

Transfer the bigger models (Gemma4:26b, etc.) only if you want them for the chat interface.

### 1D. Copy the project folder
```
Source folder:  C:\Users\JJ\Desktop\LocalLLM
```
Copy it to `C:\tiis-transfer\LocalLLM\`. This includes `main.py`, `app.py`, `tiis_mcp.py`, the Dockerfiles, `docker-compose.yml`, and `ingest_config` (your tuning + history).

### 1E. Download offline installers (on the connected machine)
- **Docker Desktop for Windows** installer
- **Ollama Windows installer** (`OllamaSetup.exe`)

Put both in `C:\tiis-transfer\`.

### 1F. (Optional) Preserve your existing intelligence
If you want to keep your existing graph instead of re-ingesting:

**FalkorDB data** — force a save, then copy the data volume:
```powershell
docker exec <falkordb-container-name> redis-cli SAVE
```
Then find the FalkorDB volume path in `docker-compose.yml` (look for a `volumes:` entry under the falkordb service, e.g. `./falkordb-data:/data`) and copy that folder to `C:\tiis-transfer\falkordb-data\`.

**OpenWebUI data** — find its volume (usually a named volume or bind mount for `/app/backend/data`) and copy it too if you want your accounts, MCP config, and chat history preserved.

---

## Phase 2 — Transport

Copy the entire `C:\tiis-transfer\` folder to your secure transfer media (USB / external drive). **Verify the total size copied correctly before wiping anything.**

---

## Phase 3 — Prepare Air-Gapped Machine

### 3A. Install prerequisites
1. Install **Docker Desktop** from the offline installer. Enable the WSL2 backend when prompted, then start Docker.
2. Install **Ollama** from the offline installer. Start it (it runs in the system tray).
3. Verify both:
```powershell
docker --version
ollama --version
```

### 3B. Restore the Ollama models
Copy the transferred `models` folder into the target user's Ollama directory:
```
C:\Users\<TARGET_USER>\.ollama\models
```
Then verify the models are visible:
```powershell
ollama list
```
You should see `qwen2.5:latest` and `nomic-embed-text:latest`. If they don't appear, Ollama isn't reading the directory — restart Ollama and check `OLLAMA_MODELS`.

---

## Phase 4 — Import and Launch

### 4A. Restore the project folder
Copy `LocalLLM` to the **same folder name** on the target (e.g. `C:\Users\<TARGET_USER>\Desktop\LocalLLM`). Keeping the folder name identical matters — Docker Compose derives the project name from it, and your exported image names must match.

### 4B. Load the Docker images
```powershell
cd C:\Users\<TARGET_USER>\Desktop\LocalLLM

docker load -i <path>\images\falkordb.tar
docker load -i <path>\images\graphiti-worker.tar
docker load -i <path>\images\ingest-ui.tar
docker load -i <path>\images\tiis-mcp.tar
docker load -i <path>\images\openwebui.tar
```
Confirm with `docker images` — all five should be present.

### 4C. Restore persistent data (if you transferred it)
- Copy `falkordb-data` back to the path referenced in `docker-compose.yml`.
- Copy `ingest_config` into the project folder if it wasn't already included.
- Restore the OpenWebUI volume if transferred.

### 4D. Verify environment variables
Open `docker-compose.yml` and confirm:
```yaml
- OLLAMA_BASE_URL=http://host.docker.internal:11434/v1
- LLM_MODEL=qwen2.5:latest
- EMBEDDING_MODEL=nomic-embed-text:latest
```
These must match models you actually restored in 3B. `host.docker.internal` resolves to the host on Docker Desktop, so the worker will reach Ollama running on the target.

### 4E. Launch WITHOUT pulling or building
```powershell
docker compose up -d --pull never
```
`--pull never` is essential — it stops Compose from trying to reach a registry. Since the images are already loaded, Compose uses them directly. **Do not run `docker compose build` on the air-gapped box** (it would try to `pip install` and fail).

### 4F. Start OpenWebUI (if you run it separately)
Use the same `docker run` command you used before, referencing the loaded OpenWebUI image, or start it via compose if it's defined there.

---

## Phase 5 — Verify

### 5A. Check all containers are up
```powershell
docker compose ps
```
All services should show `Up`, not `Restarting`.

### 5B. Confirm the worker reaches the LLM
```powershell
docker compose exec graphiti-worker python -c "import requests; r=requests.post('http://host.docker.internal:11434/v1/chat/completions', json={'model':'qwen2.5:latest','messages':[{'role':'user','content':'say ok'}],'max_tokens':5}, timeout=60); print(r.status_code)"
```
Expect `200`. If it hangs, Ollama isn't running or the model name doesn't match.

### 5C. Test the endpoints
```powershell
docker compose exec ingest-ui python -c "import requests; print(requests.get('http://graphiti-worker:8000/stats').text)"
```
You should see node/edge/episode counts.

### 5D. Test the MCP server
```powershell
curl http://localhost:9000/mcp -X GET
```
A `400` or `405` means it's alive.

### 5E. Open the UIs
| Service | URL |
|---|---|
| TIIS Streamlit | `http://localhost:8501` |
| FalkorDB browser | `http://localhost:3000` |
| OpenWebUI | `http://localhost:8080` |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `docker compose up` tries to pull | Image name mismatch | Confirm folder name matches; re-check `docker images` names |
| `docker compose up` tries to build | Compose thinks image missing | Use `--pull never`; verify loaded image names exactly |
| LLM calls time out | Ollama not running / wrong model | Start Ollama; match `LLM_MODEL` to `ollama list` |
| `episodes: 0` always | Wrong label in stats query | Already fixed — uses `Episodic` label |
| Container `Restarting` | Missing env or model | `docker compose logs <service> --tail 30` |
| No embeddings | `nomic-embed-text` not transferred | Re-copy models; it's required |

---

## Key Gotchas

1. **Never run `docker compose build` on the air-gapped box** — it needs pip/internet. Always use the exported images with `--pull never`.
2. **The embedding model is non-negotiable** — if `nomic-embed-text` is missing, Graphiti can't embed anything and the narrative layer silently fails.
3. **Keep the project folder name identical** so Compose image names line up with what you exported.
4. **`host.docker.internal`** works on Docker Desktop for Windows — that's how the containerized worker reaches Ollama on the host. If you ever move to a Linux target, you'll need `--add-host=host.docker.internal:host-gateway` or the host's LAN IP instead.
5. **Update `LLM_MODEL`** if you decide to use a different model on the target — just make sure that exact model was transferred.

---

## Quick-Reference Command Cheat Sheet

```powershell
# === CONNECTED MACHINE (EXPORT) ===
docker images
docker save -o falkordb.tar        <falkordb-image>
docker save -o graphiti-worker.tar <worker-image>
docker save -o ingest-ui.tar       <ui-image>
docker save -o tiis-mcp.tar        <mcp-image>
docker save -o openwebui.tar       <openwebui-image>
# Copy: C:\Users\JJ\.ollama\models  ->  transfer media
# Copy: C:\Users\JJ\Desktop\LocalLLM  ->  transfer media

# === AIR-GAPPED MACHINE (IMPORT) ===
docker load -i falkordb.tar
docker load -i graphiti-worker.tar
docker load -i ingest-ui.tar
docker load -i tiis-mcp.tar
docker load -i openwebui.tar
ollama list                                  # verify models present
docker compose up -d --pull never
docker compose ps
```