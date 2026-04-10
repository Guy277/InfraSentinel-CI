import json
import logging
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from uuid import uuid4

logger = logging.getLogger(__name__)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DeferredSyncQueue:
    """File locale persistante pour les evenements a rejouer plus tard."""

    def __init__(self, queue_path: str):
        self.path = Path(queue_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._items = []
        self._load()

    def _load(self):
        with self._lock:
            if not self.path.exists():
                self._items = []
                return
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                self._items = raw if isinstance(raw, list) else []
            except Exception as exc:
                logger.warning(f"Failed to load deferred sync queue: {exc}")
                self._items = []

    def _save_locked(self):
        temp_path = self.path.with_suffix(f"{self.path.suffix}.tmp")
        temp_path.write_text(
            json.dumps(self._items, indent=2, ensure_ascii=True),
            encoding="utf-8",
        )
        temp_path.replace(self.path)

    def enqueue(self, event_type: str, payload: dict, service: str = None) -> dict:
        item = {
            "id": f"{int(time.time() * 1000)}-{uuid4().hex[:8]}",
            "event_type": event_type,
            "service": service or "",
            "payload": payload,
            "created_at": _utc_now_iso(),
            "attempts": 0,
            "last_attempt_at": None,
        }
        with self._lock:
            self._items.append(item)
            self._save_locked()
        return dict(item)

    def _update_attempt_locked(self, item_id: str):
        for item in self._items:
            if item["id"] == item_id:
                item["attempts"] = int(item.get("attempts", 0)) + 1
                item["last_attempt_at"] = _utc_now_iso()
                break

    def _remove_ids_locked(self, item_ids: set[str]):
        self._items = [item for item in self._items if item.get("id") not in item_ids]

    def flush(self, handler, service: str = None, limit: int = 50) -> dict:
        with self._lock:
            candidates = [
                dict(item)
                for item in self._items
                if service is None or item.get("service") == service
            ][:limit]

        if not candidates:
            return {
                "attempted": 0,
                "flushed": 0,
                "failed": 0,
                "remaining": self.count(service=service),
            }

        succeeded_ids = set()
        failed_ids = set()

        for item in candidates:
            ok = False
            try:
                ok = bool(handler(dict(item)))
            except Exception as exc:
                logger.error(f"Deferred sync handler failed for {item.get('id')}: {exc}")
            if ok:
                succeeded_ids.add(item["id"])
            else:
                failed_ids.add(item["id"])

        with self._lock:
            for item_id in failed_ids:
                self._update_attempt_locked(item_id)
            if succeeded_ids:
                self._remove_ids_locked(succeeded_ids)
            if succeeded_ids or failed_ids:
                self._save_locked()

        return {
            "attempted": len(candidates),
            "flushed": len(succeeded_ids),
            "failed": len(failed_ids),
            "remaining": self.count(service=service),
        }

    def count(self, service: str = None) -> int:
        with self._lock:
            if service is None:
                return len(self._items)
            return sum(1 for item in self._items if item.get("service") == service)

    def get_stats(self) -> dict:
        with self._lock:
            by_service = {}
            for item in self._items:
                key = item.get("service") or "unspecified"
                by_service[key] = by_service.get(key, 0) + 1
            return {
                "pending_total": len(self._items),
                "by_service": by_service,
            }


class HybridModeManager:
    """Gere le mode connecte/hors connexion et les services externes."""

    DEFAULT_SERVICES = {
        "core_detection": {"label": "Detection locale", "requires_internet": False},
        "local_storage": {"label": "Stockage local", "requires_internet": False},
        "dashboard_local": {"label": "Dashboard local", "requires_internet": False},
        "geolocation": {"label": "Geolocalisation IP", "requires_internet": True},
        "webhooks": {"label": "Webhooks", "requires_internet": True},
        "chatbot": {"label": "Chatbot IA cloud", "requires_internet": True},
    }

    def __init__(
        self,
        check_urls: list[str],
        interval_seconds: int,
        timeout_seconds: float,
        queue_path: str,
    ):
        self._check_urls = list(check_urls)
        self._interval_seconds = max(5, int(interval_seconds))
        self._timeout_seconds = max(1.0, float(timeout_seconds))
        self.queue = DeferredSyncQueue(queue_path)

        self._lock = threading.Lock()
        self._callbacks = []
        self._thread = None
        self._running = False

        self._online = False
        self._reason = "Mode hors connexion par defaut (offline-first)."
        self._checks = 0
        self._last_check = None
        self._last_change = None

        self._services = {}
        for name, meta in self.DEFAULT_SERVICES.items():
            self.register_service(
                name=name,
                label=meta["label"],
                requires_internet=meta["requires_internet"],
                configured=True,
                runtime_available=True,
            )

    def register_service(
        self,
        name: str,
        label: str,
        requires_internet: bool,
        configured: bool = True,
        runtime_available: bool = True,
        config_reason: str = "",
        runtime_reason: str = "",
    ):
        with self._lock:
            self._services[name] = {
                "name": name,
                "label": label,
                "requires_internet": bool(requires_internet),
                "configured": bool(configured),
                "runtime_available": bool(runtime_available),
                "config_reason": config_reason,
                "runtime_reason": runtime_reason,
                "effective_enabled": False,
                "reason": "",
            }
            self._refresh_services_locked()

    def set_service_config(self, name: str, configured: bool, reason: str = ""):
        with self._lock:
            service = self._services.get(name)
            if not service:
                return
            service["configured"] = bool(configured)
            service["config_reason"] = reason
            self._refresh_services_locked()

    def set_service_runtime(self, name: str, available: bool, reason: str = ""):
        with self._lock:
            service = self._services.get(name)
            if not service:
                return
            service["runtime_available"] = bool(available)
            service["runtime_reason"] = reason
            self._refresh_services_locked()

    def add_callback(self, callback):
        self._callbacks.append(callback)

    def start(self):
        if self._running:
            return
        self._running = True
        online, reason = self._probe_connectivity()
        self._apply_connectivity_state(online, reason, force=True)
        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="hybrid-connectivity",
        )
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def is_online(self) -> bool:
        with self._lock:
            return self._online

    def can_use_service(self, name: str) -> bool:
        with self._lock:
            service = self._services.get(name)
            if not service:
                return self._online
            return bool(service["effective_enabled"])

    def get_service_status(self, name: str) -> dict:
        with self._lock:
            service = self._services.get(name)
            return self._serialize_service(service) if service else {}

    def enqueue_sync_event(self, event_type: str, payload: dict, service: str = None) -> dict:
        return self.queue.enqueue(event_type=event_type, payload=payload, service=service)

    def flush_service_queue(self, service: str, handler, limit: int = 50) -> dict:
        return self.queue.flush(handler=handler, service=service, limit=limit)

    def get_status(self) -> dict:
        with self._lock:
            services = {
                name: self._serialize_service(service)
                for name, service in self._services.items()
            }
            return {
                "online": self._online,
                "mode": "connecte" if self._online else "hors_connexion",
                "reason": self._reason,
                "checks": self._checks,
                "last_check": self._last_check,
                "last_change": self._last_change,
                "queue": self.queue.get_stats(),
                "services": services,
            }

    def _serialize_service(self, service: dict) -> dict:
        return {
            "name": service["name"],
            "label": service["label"],
            "requires_internet": service["requires_internet"],
            "configured": service["configured"],
            "runtime_available": service["runtime_available"],
            "effective_enabled": service["effective_enabled"],
            "reason": service["reason"],
        }

    def _monitor_loop(self):
        while self._running:
            time.sleep(self._interval_seconds)
            if not self._running:
                break
            online, reason = self._probe_connectivity()
            self._apply_connectivity_state(online, reason)

    def _probe_connectivity(self) -> tuple[bool, str]:
        errors = []

        # Quick low-level Internet reachability checks (no TLS/DNS required).
        for host, port in self.DEFAULT_TCP_CHECKS:
            sock = None
            try:
                sock = socket.create_connection((host, port), timeout=self._timeout_seconds)
                return True, f"Connectivite externe disponible via TCP {host}:{port}"
            except Exception as exc:
                errors.append(f"tcp://{host}:{port}: {exc.__class__.__name__}")
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass

        for url in self._check_urls:
            try:
                request = Request(
                    url,
                    headers={"User-Agent": "InfraSentinel-CI/1.0"},
                )
                with urlopen(request, timeout=self._timeout_seconds) as response:
                    status = getattr(response, "status", 200)
                    if status < 500:
                        return True, f"Connectivite externe disponible via {url}"
                    errors.append(f"{url}: HTTP {status}")
            except Exception as exc:
                errors.append(f"{url}: {exc.__class__.__name__}")

        if not errors:
            return False, "Aucun endpoint de verification configure."
        return False, f"Services externes injoignables ({'; '.join(errors[:2])})"

    def _apply_connectivity_state(self, online: bool, reason: str, force: bool = False):
        callbacks = list(self._callbacks)
        with self._lock:
            self._checks += 1
            self._last_check = _utc_now_iso()
            changed = force or (online != self._online)
            if changed:
                self._last_change = self._last_check
            self._online = bool(online)
            self._reason = reason
            self._refresh_services_locked()

        if changed or force:
            mode = "connecte" if online else "hors connexion"
            logger.info(f"Hybrid mode switched to {mode}: {reason}")
            status = self.get_status()
            for callback in callbacks:
                try:
                    callback(status)
                except Exception as exc:
                    logger.error(f"Hybrid callback error: {exc}")

    def _refresh_services_locked(self):
        for service in self._services.values():
            if not service["configured"]:
                service["effective_enabled"] = False
                service["reason"] = service["config_reason"] or "Desactive par configuration."
                continue
            if not service["runtime_available"]:
                service["effective_enabled"] = False
                service["reason"] = service["runtime_reason"] or "Indisponible."
                continue
            if service["requires_internet"] and not self._online:
                service["effective_enabled"] = False
                service["reason"] = "Suspendu automatiquement en mode hors connexion."
                continue
            service["effective_enabled"] = True
            service["reason"] = "Disponible."
    DEFAULT_TCP_CHECKS = [
        ("1.1.1.1", 53),
        ("8.8.8.8", 53),
    ]
