import smtplib
import logging
import time
import json
import asyncio
import threading
import enum
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque

import numpy as np

from config.settings import (
    SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD,
    ALERT_EMAIL, SMTP_USE_TLS
)

logger = logging.getLogger(__name__)


def _sanitize(obj):
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [_sanitize(i) for i in obj]
    elif isinstance(obj, (np.bool_,)):
        return bool(obj)
    elif isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, enum.Enum):
        return obj.value
    return obj


class WebSocketManager:
    def __init__(self):
        self._connections = set()
        self._lock = threading.Lock()
        self._message_queue = deque(maxlen=1000)

    def add_connection(self, ws):
        with self._lock:
            self._connections.add(ws)

    def remove_connection(self, ws):
        with self._lock:
            self._connections.discard(ws)

    async def broadcast(self, message: dict):
        with self._lock:
            connections = list(self._connections)

        dead = []
        for ws in connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)

        with self._lock:
            for ws in dead:
                self._connections.discard(ws)

        self._message_queue.append(message)

    def get_recent_messages(self, count=50) -> list:
        return list(self._message_queue)[-count:]

    @property
    def connection_count(self):
        with self._lock:
            return len(self._connections)


class EmailNotifier:
    def __init__(self):
        self.smtp_server = SMTP_SERVER
        self.smtp_port = SMTP_PORT
        self.smtp_user = SMTP_USER
        self.smtp_password = SMTP_PASSWORD
        self.recipient = ALERT_EMAIL
        self.use_tls = SMTP_USE_TLS

    def send_alert(self, subject: str, body: str) -> bool:
        if not self.smtp_user or not self.smtp_password:
            logger.warning("SMTP not configured, email alert skipped")
            return False

        try:
            msg = MIMEMultipart()
            msg["From"] = self.smtp_user
            msg["To"] = self.recipient
            msg["Subject"] = f"[IDS/IPS Alert] {subject}"
            msg.attach(MIMEText(body, "html"))

            server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10)
            if self.use_tls:
                server.starttls()
            server.login(self.smtp_user, self.smtp_password)
            server.send_message(msg)
            server.quit()
            logger.info(f"Email alert sent: {subject}")
            return True
        except Exception as e:
            logger.error(f"Email send error: {e}")
            return False


class AlertManager:
    def __init__(self):
        self.ws_manager = WebSocketManager()
        self.email_notifier = EmailNotifier()
        self._alert_history = deque(maxlen=10000)

    async def send_alert(self, incident_data: dict, methods: list = None) -> list:
        if methods is None:
            methods = ["websocket", "log"]

        alert_id = f"alert_{int(time.time() * 1000)}"
        results = []

        alert = {
            "id": alert_id,
            "type": "incident",
            "timestamp": time.time(),
            "data": _sanitize(incident_data),
        }

        for method in methods:
            if method == "websocket":
                try:
                    await self.ws_manager.broadcast(alert)
                    results.append({"method": "websocket", "status": "sent"})
                except Exception as e:
                    results.append({"method": "websocket", "status": "failed", "error": str(e)})

            elif method == "email":
                if incident_data.get("risk_level") == "critique":
                    subject = f"Critical Threat: {incident_data.get('ip_address', 'unknown')}"
                    body = self._build_email_body(incident_data)
                    sent = self.email_notifier.send_alert(subject, body)
                    results.append({"method": "email", "status": "sent" if sent else "failed"})

            elif method == "log":
                logger.warning(
                    f"ALERT: IP={incident_data.get('ip_address')} "
                    f"Score={incident_data.get('risk_score')} "
                    f"Level={incident_data.get('risk_level')} "
                    f"Action={incident_data.get('action_taken')}"
                )
                results.append({"method": "log", "status": "sent"})

        self._alert_history.append(alert)
        return results

    def _build_email_body(self, data: dict) -> str:
        return f"""
        <html>
        <body>
        <h2 style="color: red;">IDS/IPS Critical Alert</h2>
        <table border="1" cellpadding="8" cellspacing="0">
            <tr><td><b>IP Address</b></td><td>{data.get('ip_address', 'N/A')}</td></tr>
            <tr><td><b>Risk Score</b></td><td>{data.get('risk_score', 'N/A')}</td></tr>
            <tr><td><b>Risk Level</b></td><td>{data.get('risk_level', 'N/A')}</td></tr>
            <tr><td><b>Action Taken</b></td><td>{data.get('action_taken', 'N/A')}</td></tr>
            <tr><td><b>Timestamp</b></td><td>{data.get('timestamp', 'N/A')}</td></tr>
            <tr><td><b>Details</b></td><td><pre>{json.dumps(data.get('details', {}), indent=2)}</pre></td></tr>
        </table>
        </body>
        </html>
        """

    def get_recent_alerts(self, count=100) -> list:
        return [_sanitize(a) for a in list(self._alert_history)[-count:]]
