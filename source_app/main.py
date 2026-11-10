"""
Simulated SOC platform: the "web app" that CyberGuardian connects to.

Run from the project root:
    uvicorn source_app.main:app --port 8000

Every /api/v1 endpoint needs the header  X-API-Key: <key>.
The key defaults to "demo-key-123"; set SOURCE_API_KEY to change it.
"""
import os
import secrets
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from .data import IncidentStore

API_KEY = os.environ.get("SOURCE_API_KEY", "demo-key-123")

app = FastAPI(title="Simulated SOC Platform", version="1.0")
store = IncidentStore()


def require_api_key(x_api_key: Optional[str] = Header(default=None)):
    """Reject requests that do not carry the correct API key."""
    if x_api_key is None or not secrets.compare_digest(x_api_key.encode(), API_KEY.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


class ActionRequest(BaseModel):
    incident_id: str
    action: str          # block_ip | isolate_host | disable_account
    target: str
    requested_by: str = "cyberguardian"


@app.get("/health")
def health():
    """Open endpoint, used to check that the server is reachable."""
    return {"status": "ok", "service": "Simulated SOC Platform"}


@app.get("/api/v1/incidents", dependencies=[Depends(require_api_key)])
def list_incidents():
    summaries = store.list_summaries()
    return {"count": len(summaries), "incidents": summaries}


@app.get("/api/v1/incidents/{incident_id}", dependencies=[Depends(require_api_key)])
def get_incident(incident_id: str):
    incident = store.get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.post("/api/v1/simulate", dependencies=[Depends(require_api_key)])
def simulate_incident():
    """Create a new incident, so the dashboard visibly changes during a demo."""
    return store.simulate_new()


@app.post("/api/v1/actions", dependencies=[Depends(require_api_key)])
def request_action(request: ActionRequest):
    try:
        return store.record_action(
            request.incident_id, request.action, request.target, request.requested_by
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Incident not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/v1/actions", dependencies=[Depends(require_api_key)])
def list_actions():
    return store.list_actions()
