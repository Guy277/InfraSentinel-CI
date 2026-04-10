import logging
import asyncio
import aiohttp

logger = logging.getLogger(__name__)


class WebhookManager:
    """Gestionnaire de webhooks pour Slack, Discord et autres."""

    def __init__(self):
        self._webhooks = {}
        self._enabled = False
        self._hybrid_manager = None

    def set_hybrid_manager(self, hybrid_manager):
        self._hybrid_manager = hybrid_manager

    def has_targets(self) -> bool:
        return bool(self._webhooks)

    def configure(self, slack_url: str = None, discord_url: str = None):
        """Configure les URLs de webhooks."""
        if slack_url:
            self._webhooks["slack"] = slack_url
            self._enabled = True
        if discord_url:
            self._webhooks["discord"] = discord_url
            self._enabled = True

    def is_enabled(self) -> bool:
        return self._enabled

    def send_alert(self, alert_type: str, title: str, message: str, severity: str, ip: str = None):
        """Envoie une alerte via webhooks configurés."""
        if not self._enabled:
            return

        if self._hybrid_manager and not self._hybrid_manager.can_use_service("webhooks"):
            reason = self._hybrid_manager.get_service_status("webhooks").get("reason", "")
            for name, url in self._webhooks.items():
                payload = self._build_payload(name, alert_type, title, message, severity, ip)
                self._queue_event(name, url, payload, alert_type, title, severity, ip, message, reason)
            logger.info(f"Webhooks queued while offline: {title}")
            return

        for name, url in self._webhooks.items():
            payload = self._build_payload(name, alert_type, title, message, severity, ip)
            sent = self._send_async(name, url, payload)
            if not sent:
                self._queue_event(
                    name, url, payload, alert_type, title, severity, ip, message,
                    "Webhook delivery failed; queued for retry.",
                )

    def _build_payload(self, target_name: str, alert_type: str, title: str, message: str, severity: str, ip: str = None) -> dict:
        """Construit le payload selon le type de webhook."""
        color_map = {
            "critical": "FF0000",
            "high": "FF4400",
            "medium": "FFAA00",
            "low": "00AAFF",
        }

        color = color_map.get(severity, "00AAFF")

        if target_name == "slack":
            return {
                "attachments": [{
                    "color": color,
                    "title": title,
                    "text": message,
                    "fields": [
                        {"title": "Type", "value": alert_type, "short": True},
                        {"title": "Severity", "value": severity.upper(), "short": True},
                    ]
                }]
            }

        if target_name == "discord":
            return {
                "embeds": [{
                    "title": title,
                    "description": message,
                    "color": int(color, 16),
                    "fields": [
                        {"name": "Type", "value": alert_type, "inline": True},
                        {"name": "Severity", "value": severity.upper(), "inline": True},
                    ]
                }]
            }

        return {"text": f"[{severity.upper()}] {title}: {message}"}

    def _send_async(self, name: str, url: str, payload: dict) -> bool:
        """Envoie le webhook de manière asynchrone."""
        loop = None
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return bool(loop.run_until_complete(self._send_async_helper(url, payload)))
        except Exception as e:
            logger.error(f"Webhook {name} error: {e}")
            return False
        finally:
            if loop is not None:
                loop.close()

    async def _send_async_helper(self, url: str, payload: dict) -> bool:
        """Helper asynchrone pour envoyer le webhook."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=10) as resp:
                    if resp.status >= 400:
                        logger.warning(f"Webhook failed: {resp.status}")
                        return False
                    else:
                        logger.info(f"Webhook sent successfully")
                        return True
        except Exception as e:
            logger.error(f"Webhook error: {e}")
        return False

    def _queue_event(
        self,
        name: str,
        url: str,
        payload: dict,
        alert_type: str,
        title: str,
        severity: str,
        ip: str,
        message: str,
        reason: str,
    ):
        if not self._hybrid_manager:
            return
        self._hybrid_manager.enqueue_sync_event(
            event_type="webhook",
            service="webhooks",
            payload={
                "name": name,
                "url": url,
                "payload": payload,
                "alert_type": alert_type,
                "title": title,
                "severity": severity,
                "ip": ip,
                "message": message,
                "reason": reason,
            },
        )

    def flush_pending(self) -> dict:
        if not self._hybrid_manager or not self._enabled:
            return {"attempted": 0, "flushed": 0, "failed": 0, "remaining": 0}
        if not self._hybrid_manager.can_use_service("webhooks"):
            return {"attempted": 0, "flushed": 0, "failed": 0, "remaining": self._hybrid_manager.queue.count(service="webhooks")}
        return self._hybrid_manager.flush_service_queue(
            service="webhooks",
            handler=self._flush_queue_item,
            limit=100,
        )

    def _flush_queue_item(self, item: dict) -> bool:
        payload = item.get("payload", {})
        return self._send_async(
            payload.get("name", "webhook"),
            payload.get("url", ""),
            payload.get("payload", {}),
        )


_webhook_manager = WebhookManager()


def get_webhook_manager() -> WebhookManager:
    return _webhook_manager
