import asyncio
import logging
import json
import time
from datetime import datetime
from ipaddress import ip_address, AddressValueError
from pathlib import Path
from typing import Union

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Query, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

from config.settings import (
    DASHBOARD_HOST, DASHBOARD_PORT, SECRET_KEY,
    DASHBOARD_USER, DASHBOARD_PASSWORD,
)
from ips.alert_manager import _sanitize
from ips.incident_logger import IncidentLogger
from capture.geolocation import GeoLocator

logger = logging.getLogger(__name__)


def _validate_ip(ip: str) -> bool:
    """Validate IP address (IPv4 or IPv6)."""
    try:
        ip_address(ip)
        return True
    except AddressValueError:
        return False


app = FastAPI(title="InfraSentinel-CI", version="1.0.0")

BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


class _SafeCache:
    """Cache Jinja2 qui accepte des clefs non-hashables."""
    def __init__(self):
        self._store = {}
    def __getitem__(self, key):
        return self._store[str(key)]
    def __setitem__(self, key, value):
        self._store[str(key)] = value
    def get(self, key):
        return self._store.get(str(key))
    def clear(self):
        self._store.clear()

templates.env.cache = _SafeCache()

security = HTTPBasic()

agent = None
incident_logger = IncidentLogger()
geolocator = GeoLocator()


def _get_agent():
    return agent


def _fallback_hybrid_status() -> dict:
    return {
        "online": False,
        "mode": "hors_connexion",
        "reason": "Agent non initialise.",
        "checks": 0,
        "last_check": None,
        "last_change": None,
        "queue": {"pending_total": 0, "by_service": {}},
        "services": {},
    }


def _get_hybrid_status() -> dict:
    a = _get_agent()
    if a and hasattr(a, "get_hybrid_status"):
        return a.get_hybrid_status()
    return _fallback_hybrid_status()


def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    correct_user = secrets.compare_digest(credentials.username, DASHBOARD_USER)
    correct_pass = secrets.compare_digest(credentials.password, DASHBOARD_PASSWORD)
    if not (correct_user and correct_pass):
        raise HTTPException(
            status_code=401, detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


# ─── Pages ────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, username: str = Depends(authenticate)):
    return templates.TemplateResponse(
        request, "index.html", {"request": request, "username": username}
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"request": request})


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


# ─── API: Agent Stats ─────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats(username: str = Depends(authenticate)):
    a = _get_agent()
    if a:
        return a.get_stats()
    return {"error": "Agent not initialized"}


@app.get("/api/hybrid/status")
async def get_hybrid_status(username: str = Depends(authenticate)):
    return _get_hybrid_status()


@app.get("/api/ai/retrain-status")
async def get_retrain_status(username: str = Depends(authenticate)):
    a = _get_agent()
    if a:
        return a.get_retrain_status()
    return {"error": "Agent not initialized"}


@app.post("/api/ai/retrain")
async def trigger_retrain(
    use_fp_only: bool = True,
    username: str = Depends(authenticate),
):
    a = _get_agent()
    if a:
        return a.trigger_retrain(use_fp_only=use_fp_only)
    return {"error": "Agent not initialized"}


# ─── API: Chatbot ───────────────────────────────────────────────────

@app.get("/api/chatbot/status")
async def chatbot_status(username: str = Depends(authenticate)):
    a = _get_agent()
    hybrid = _get_hybrid_status()
    service = hybrid.get("services", {}).get("chatbot", {})
    if a and a.chatbot:
        chatbot_status = a.chatbot.get_status()
        return {
            "enabled": bool(chatbot_status.get("enabled")),
            "model": chatbot_status.get("model"),
            "provider": chatbot_status.get("provider"),
            "mode": chatbot_status.get("mode"),
            "local_enabled": chatbot_status.get("local_enabled", False),
            "cloud_available": chatbot_status.get("cloud_available", False),
            "cloud_enabled": chatbot_status.get("cloud_enabled", False),
            "cloud_configured": chatbot_status.get("cloud_configured", False),
            "reason": chatbot_status.get("reason") or service.get("reason"),
            "hybrid_mode": hybrid.get("mode"),
        }
    return {
        "enabled": False,
        "model": None,
        "provider": "local",
        "reason": service.get("reason") or "Chatbot not available",
        "mode": "disabled",
        "local_enabled": False,
        "cloud_available": False,
        "cloud_enabled": False,
        "cloud_configured": False,
        "hybrid_mode": hybrid.get("mode"),
    }


@app.post("/api/chatbot/chat")
async def chatbot_chat(
    message: str = Form(...),
    username: str = Depends(authenticate),
):
    a = _get_agent()
    if a and a.chatbot:
        return a.chatbot.chat(message)
    return {"response": "Chatbot non disponible", "type": "error"}


# ─── API: Incidents ───────────────────────────────────────────────

@app.get("/api/incidents")
async def get_incidents(
    limit: int = Query(100, ge=1, le=10000),
    offset: int = Query(0, ge=0),
    risk_level: str = Query(None),
    ip: str = Query(None),
    username: str = Depends(authenticate),
):
    return incident_logger.get_incidents(
        limit=limit, offset=offset, risk_level=risk_level, ip=ip,
    )


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: int, username: str = Depends(authenticate)):
    inc = incident_logger.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@app.get("/api/incidents/export")
async def export_incidents(
        fmt: str = Query("json", pattern="^(json|csv)$"),
    username: str = Depends(authenticate),
):
    data = incident_logger.export_incidents(fmt=fmt)
    if fmt == "csv":
        return JSONResponse(
            content={"data": data},
            headers={"Content-Disposition": "attachment; filename=incidents.csv"},
        )
    return JSONResponse(content=json.loads(data) if data else [])


# ─── API: Blocked IPs ─────────────────────────────────────────────

@app.get("/api/blocked-ips")
async def get_blocked_ips(username: str = Depends(authenticate)):
    return incident_logger.get_blocked_ips(active_only=True)


@app.post("/api/blocked-ips/{ip}/unblock")
async def unblock_ip(ip: str, username: str = Depends(authenticate)):
    a = _get_agent()
    if a:
        result = a.force_unblock(ip)
        return result
    raise HTTPException(status_code=500, detail="Agent not available")


@app.post("/api/blocked-ips/{ip}/block")
async def manual_block(ip: str, username: str = Depends(authenticate)):
    a = _get_agent()
    if a:
        return a.force_block(ip, reason="Manual block via dashboard")
    raise HTTPException(status_code=500, detail="Agent not available")


# ─── API: Traffic ─────────────────────────────────────────────────

@app.get("/api/traffic")
async def get_traffic(username: str = Depends(authenticate)):
    a = _get_agent()
    if a:
        return a.sniffer.aggregator.get_aggregated()
    return {}


# ─── API: Alerts ──────────────────────────────────────────────────

@app.get("/api/alerts")
async def get_alerts(
    limit: int = Query(50, ge=1, le=1000),
    username: str = Depends(authenticate),
):
    a = _get_agent()
    if a:
        return a.alert_manager.get_recent_alerts(limit)
    return []


# ─── API: Agent Decisions ─────────────────────────────────────────

@app.get("/api/decisions")
async def get_decisions(
    count: int = Query(50, ge=1, le=500),
    username: str = Depends(authenticate),
):
    a = _get_agent()
    if a:
        return a.get_recent_decisions(count)
    return []


# ─── API: IP History ──────────────────────────────────────────────

@app.get("/api/ip/{ip}/history")
async def get_ip_history(ip: str, username: str = Depends(authenticate)):
    a = _get_agent()
    if a:
        return a.risk_scorer.get_ip_history(ip)
    return []


# ─── API: System Logs ─────────────────────────────────────────────

@app.get("/api/logs")
async def get_logs(
    count: int = Query(100, ge=1, le=5000),
    severity: str = Query(None),
    ip: str = Query(None),
    username: str = Depends(authenticate),
):
    a = _get_agent()
    if a:
        return a.log_collector.get_recent_entries(
            count=count, severity=severity, ip=ip,
        )
    return []


# ─── API: Live Analyze ────────────────────────────────────────────

@app.post("/api/analyze")
async def analyze_traffic(data: dict, username: str = Depends(authenticate)):
    a = _get_agent()
    if a:
        return a.analyze_traffic_snapshot(data)
    return {"error": "Agent not available"}


# ─── API: Faux Positifs ───────────────────────────────────────────

@app.post("/api/false-positives/{incident_id}")
async def mark_false_positive(
    incident_id: int,
    data: dict,
    username: str = Depends(authenticate),
):
    a = _get_agent()
    if a:
        result = a.mark_false_positive(
            incident_id=incident_id,
            reason=data.get("reason", "No reason provided"),
            category=data.get("category", "other"),
            auto_unblock=data.get("auto_unblock", True),
            add_to_whitelist=data.get("add_to_whitelist", False),
            whitelist_duration_hours=data.get("whitelist_duration_hours"),
        )
        return result
    raise HTTPException(status_code=500, detail="Agent not available")


@app.delete("/api/false-positives/{incident_id}")
async def unmark_false_positive(incident_id: int, username: str = Depends(authenticate)):
    a = _get_agent()
    if a:
        return a.unmark_false_positive(incident_id)
    raise HTTPException(status_code=500, detail="Agent not available")


@app.get("/api/false-positives")
async def get_false_positives(
    limit: int = Query(100, ge=1, le=10000),
    offset: int = Query(0, ge=0),
    username: str = Depends(authenticate),
):
    return incident_logger.get_false_positives(limit=limit, offset=offset)


@app.get("/api/false-positives/stats")
async def get_fp_stats(username: str = Depends(authenticate)):
    return incident_logger.get_fp_stats()


@app.get("/api/false-positives/categories")
async def get_fp_categories(username: str = Depends(authenticate)):
    return incident_logger.get_fp_categories()


@app.get("/api/false-positives/ip/{ip}")
async def get_fp_by_ip(ip: str, username: str = Depends(authenticate)):
    return incident_logger.get_fp_ip_history(ip)


# ─── API: Liste Blanche ───────────────────────────────────────────

@app.get("/api/whitelist")
async def get_whitelist(username: str = Depends(authenticate)):
    a = _get_agent()
    if a:
        return a.get_whitelist()
    return incident_logger.get_whitelist(active_only=True)


@app.post("/api/whitelist")
async def add_to_whitelist(data: dict, username: str = Depends(authenticate)):
    ip = data.get("ip_address", "")
    if not _validate_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    a = _get_agent()
    if a:
        return a.add_to_whitelist(
            ip=ip,
            reason=data.get("reason", ""),
            expires_hours=data.get("expires_hours"),
        )
    raise HTTPException(status_code=500, detail="Agent not available")


@app.delete("/api/whitelist/{ip}")
async def remove_from_whitelist(ip: str, username: str = Depends(authenticate)):
    if not _validate_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    a = _get_agent()
    if a:
        return a.remove_from_whitelist(ip)
    raise HTTPException(status_code=500, detail="Agent not available")


# ─── WebSocket: Alerts ────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    a = _get_agent()
    if a:
        a.alert_manager.ws_manager.add_connection(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        if a:
            a.alert_manager.ws_manager.remove_connection(websocket)


# ─── WebSocket: Live Dashboard ────────────────────────────────────

@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    await websocket.accept()
    a = _get_agent()
    if a:
        a.alert_manager.ws_manager.add_connection(websocket)
    try:
        while True:
            if a:
                stats = a.get_stats()
                traffic = a.sniffer.aggregator.get_aggregated()
                decisions = a.get_recent_decisions(5)
                await websocket.send_json(_sanitize({
                    "type": "live_update",
                    "timestamp": time.time(),
                    "stats": stats,
                    "traffic_sample_count": len(traffic),
                    "recent_decisions": decisions,
                }))
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        if a:
            a.alert_manager.ws_manager.remove_connection(websocket)


# ─── API: Geolocalised Threats ────────────────────────────────────

@app.get("/api/geo-threats")
async def get_geo_threats(username: str = Depends(authenticate)):
    a = _get_agent()
    hybrid = _get_hybrid_status()
    geo_service = hybrid.get("services", {}).get("geolocation", {})
    if not a:
        return {
            "threats": [],
            "local": {"lat": 48.8566, "lon": 2.3522, "ip": "127.0.0.1"},
            "degraded": True,
            "reason": hybrid.get("reason"),
        }

    incidents = incident_logger.get_incidents(limit=500)
    seen_ips = {}
    threats = []

    # Detecter la passerelle locale
    local_ip = "127.0.0.1"
    local_lat, local_lon = 48.8566, 2.3522  # Defaut: Paris
    try:
        import socket
        hostname = socket.gethostname()
        local_ips = socket.gethostbyname_ex(hostname)[2]
        if local_ips:
            local_ip = local_ips[0]
    except Exception:
        pass

    # Lire la passerelle depuis /proc/net/route
    try:
        with open("/proc/net/route") as f:
            for line in f:
                fields = line.split()
                if fields[1] == "00000000":
                    gw_hex = fields[2]
                    gw = ".".join(str(int(gw_hex[i:i+2], 16)) for i in (0, 2, 4, 6))
                    gw_geo = geolocator.lookup(
                        gw,
                        allow_network=geo_service.get("effective_enabled", False),
                    )
                    if gw_geo.get("lat") is not None:
                        local_lat = gw_geo["lat"]
                        local_lon = gw_geo["lon"]
                    break
    except Exception:
        pass

    unique_ips = [inc["ip_address"] for inc in incidents if inc["ip_address"] not in seen_ips]
    geo_results = geolocator.lookup_batch(
        unique_ips,
        allow_network=geo_service.get("effective_enabled", False),
    )

    for inc in incidents:
        ip = inc["ip_address"]
        if ip in seen_ips:
            continue
        seen_ips[ip] = True

        geo = geo_results.get(ip, {})
        if geo.get("lat") is not None and geo.get("lon") is not None:
            threats.append({
                "ip": ip,
                "lat": geo["lat"],
                "lon": geo["lon"],
                "city": geo.get("city", ""),
                "country": geo.get("country", ""),
                "country_code": geo.get("country_code", ""),
                "continent": geo.get("continent", "Inconnu"),
                "isp": geo.get("isp", ""),
                "risk_level": inc.get("risk_level", "faible"),
                "risk_score": inc.get("risk_score", 0),
                "source_type": "external",
            })

    return {
        "threats": threats,
        "local": {"lat": local_lat, "lon": local_lon, "ip": local_ip},
        "degraded": not geo_service.get("effective_enabled", False),
        "reason": geo_service.get("reason"),
    }


# ─── Factory ──────────────────────────────────────────────────────

def create_app(ids_agent) -> FastAPI:
    """Lie l'agent au dashboard et retourne l'app FastAPI."""
    global agent
    agent = ids_agent
    global incident_logger
    incident_logger = ids_agent.incident_logger
    return app
