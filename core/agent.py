import logging
import time
import threading
import asyncio
from datetime import datetime
from typing import Optional, Callable

from config.settings import NETWORK_INTERFACE
from capture.sniffer import NetworkSniffer
from capture.port_scanner import PortScanner
from capture.log_collector import LogCollector
from ai_engine.anomaly_detector import AnomalyDetector
from ai_engine.risk_scorer import RiskScorer
from ai_engine.signature_detector import get_signature_detector
from ips.blocker import IPBlocker
from ips.alert_manager import AlertManager
from ips.incident_logger import IncidentLogger
from ips.webhook_manager import get_webhook_manager
from core.hybrid_manager import HybridModeManager
from core.events import (
    SecurityEvent, AgentDecision, RiskLevel, ActionType,
    ThreatType, TrafficStats,
)
from config.settings import AUTO_BLOCK_CRITICAL, AGGREGATION_WINDOW, AUTO_WHITELIST_PRIVATE, WHITELIST_IPS, RETRAIN_ENABLED, RETRAIN_INTERVAL_HOURS, RETRAIN_MIN_SAMPLES, CHATBOT_ENABLED, CHATBOT_MODEL, SLACK_WEBHOOK_URL, DISCORD_WEBHOOK_URL, RULES_PATH, CONNECTIVITY_CHECK_URLS, CONNECTIVITY_CHECK_INTERVAL, CONNECTIVITY_CHECK_TIMEOUT, HYBRID_QUEUE_PATH

logger = logging.getLogger(__name__)


class SecurityAgent:
    """Agent IA autonome de protection des systemes d'information.

    Orchestre la capture reseau, la detection d'anomalies par IA,
    la reponse automatique et la supervision via dashboard.

    Pipeline:
        Capture -> Analyse IA -> Decision -> Reponse -> Journalisation
    """

    VERSION = "1.0.0"

    def __init__(self):
        # Couche 1 - Capture
        # Laisse le sniffer auto-detecter l'interface si aucune valeur n'est fournie.
        self.sniffer = NetworkSniffer(interface=NETWORK_INTERFACE or None)
        self.scanner = PortScanner()
        self.log_collector = LogCollector()

        # Couche 2 - IA
        self.detector = AnomalyDetector()
        self.risk_scorer = RiskScorer()
        self.signature_detector = get_signature_detector()
        self.signature_detector.load_from_directory(RULES_PATH)

        # Couche 3 - Reponse
        self.blocker = IPBlocker()
        self.alert_manager = AlertManager()
        self.incident_logger = IncidentLogger()
        self.webhook_manager = get_webhook_manager()
        self.webhook_manager.configure(SLACK_WEBHOOK_URL, DISCORD_WEBHOOK_URL)
        self.hybrid_manager = HybridModeManager(
            check_urls=CONNECTIVITY_CHECK_URLS,
            interval_seconds=CONNECTIVITY_CHECK_INTERVAL,
            timeout_seconds=CONNECTIVITY_CHECK_TIMEOUT,
            queue_path=HYBRID_QUEUE_PATH,
        )
        self.webhook_manager.set_hybrid_manager(self.hybrid_manager)

        # Etat interne
        self._running = False
        self._analysis_thread = None
        self._event_loop = None
        self._scan_results = {}
        self._decision_callbacks: list[Callable] = []

        # Historique de decisions
        self._decisions: list[AgentDecision] = []
        self._max_decisions = 5000

        # Statistiques
        self._stats = {
            "start_time": None,
            "packets_analyzed": 0,
            "incidents_detected": 0,
            "ips_blocked": 0,
            "alerts_sent": 0,
            "decisions_made": 0,
            "false_positives_corrected": 0,
        }

        # Politique de securite
        self.policy = SecurityPolicy()

        # Retraining config
        self._retrain_enabled = False
        self._retrain_thread = None
        self._last_retrain_time = None

        # Chatbot
        self.chatbot = None

        # Services hybrides
        self.hybrid_manager.add_callback(self._on_connectivity_change)
        self.hybrid_manager.set_service_config(
            "webhooks",
            configured=bool(self.webhook_manager.has_targets()),
            reason="Aucun webhook configure."
        )
        self.hybrid_manager.set_service_config(
            "chatbot",
            configured=CHATBOT_ENABLED,
            reason="Chatbot desactive dans la configuration."
        )
        self.hybrid_manager.set_service_runtime("geolocation", True)

    # ─── Initialisation ───────────────────────────────────────────

    def initialize(self) -> bool:
        """Initialise l'agent: charge ou entraine le modele IA,
        branche les callbacks."""
        logger.info(f"SecurityAgent v{self.VERSION} - Initializing...")

        # Charger ou entrainer le modele
        if not self.detector.load_model():
            logger.info("Training AI model with synthetic data...")
            success = self.detector.train()
            if not success:
                logger.error("Failed to train model")
                return False
            logger.info("AI model trained successfully")
        else:
            logger.info("AI model loaded from disk")

        # Brancher les callbacks de capture
        self.scanner.add_callback(self._on_scan_result)
        self.log_collector.add_callback(self._on_log_entry)

        # Brancher le callback de blocage
        self.blocker.add_callback(self._on_ip_blocked)

        # Whitelist automatique des IPs privees
        self._setup_whitelist()

        logger.info("SecurityAgent initialized successfully")

        # Configurer le re-training automatique si active
        self._configure_retraining()

        # Configurer le chatbot indépendamment du retraining
        self._configure_chatbot()

        return True

    def _configure_retraining(self):
        """Configure et demarre le re-training automatique du modele IA."""
        if not RETRAIN_ENABLED:
            logger.info("Auto-retraining disabled (set RETRAIN_ENABLED=true to enable)")
            return

        self._retrain_enabled = True
        logger.info(f"Auto-retraining enabled: every {RETRAIN_INTERVAL_HOURS}h, min {RETRAIN_MIN_SAMPLES} samples")

        self._retrain_thread = threading.Thread(
            target=self._retrain_loop, daemon=True, name="ai-retrain"
        )
        self._retrain_thread.start()

    def _configure_chatbot(self):
        """Configure et active le chatbot hybride (local + cloud optionnel)."""
        if not CHATBOT_ENABLED:
            self.hybrid_manager.set_service_config(
                "chatbot", configured=False, reason="Chatbot desactive dans la configuration."
            )
            if self.chatbot:
                self.chatbot.disable("Chatbot desactive dans la configuration.")
            logger.info("Chatbot disabled (set CHATBOT_ENABLED=true to enable)")
            return

        try:
            from chatbot.security_chatbot import SecurityChatbot
            if self.chatbot is None:
                self.chatbot = SecurityChatbot(agent=self)
            if self.chatbot.enable(model=CHATBOT_MODEL):
                status = self.chatbot.get_status()
                cloud_configured = bool(status.get("cloud_available"))
                cloud_reason = status.get("reason") or "Cloud chatbot indisponible."
                self.hybrid_manager.set_service_runtime(
                    "chatbot",
                    cloud_configured,
                    "" if cloud_configured else cloud_reason,
                )
                self.chatbot.set_cloud_enabled(
                    self.hybrid_manager.is_online(),
                    "Cloud chatbot suspendu en mode hors connexion.",
                )
                logger.info(
                    "Chatbot enabled in %s mode (model=%s)",
                    status.get("mode"),
                    CHATBOT_MODEL,
                )
            else:
                self.hybrid_manager.set_service_runtime(
                    "chatbot",
                    False,
                    self.chatbot.get_status().get("reason") or "Activation du chatbot impossible.",
                )
                logger.warning(f"Chatbot failed to enable (provider={self.chatbot.provider})")
        except Exception as e:
            self.hybrid_manager.set_service_runtime("chatbot", False, str(e))
            logger.error(f"Failed to initialize chatbot: {e}")

    def _retrain_loop(self):
        """Boucle de re-training periodique."""
        import time
        interval_seconds = RETRAIN_INTERVAL_HOURS * 3600

        while self._running:
            time.sleep(interval_seconds)
            if not self._running:
                break

            logger.info("Starting scheduled model retraining...")
            self._do_retrain()

    def _do_retrain(self) -> bool:
        """Execute le re-training du modele avec les faux positifs connus."""
        try:
            fps = self.incident_logger.get_false_positives(limit=10000)
            if len(fps) < RETRAIN_MIN_SAMPLES:
                logger.info(f"Not enough false positives for retraining ({len(fps)} < {RETRAIN_MIN_SAMPLES})")
                return False

            fp_features = []
            for fp in fps:
                details = fp.get("details", {})
                stats = details.get("stats", {})
                if stats:
                    feature = [
                        stats.get("packet_count", 0),
                        stats.get("total_bytes", 0),
                        stats.get("unique_ports", 0),
                        stats.get("frequency", 0),
                        stats.get("unique_dst_ips", 0),
                        stats.get("syn_count", 0),
                        stats.get("syn_ratio", 0),
                        stats.get("bytes_per_packet", 0),
                    ]
                    fp_features.append(feature)

            if not fp_features:
                logger.warning("No valid features extracted from false positives")
                return False

            success = self.detector.retrain_with_false_positives(fp_features)
            if success:
                self._last_retrain_time = datetime.now()
                logger.info(f"Model retrained successfully with {len(fp_features)} FP samples")
            return success

        except Exception as e:
            logger.error(f"Retraining failed: {e}")
            return False

    def _setup_whitelist(self):
        """Whiteliste automatiquement les IPs privees et les IPs configurees."""
        import ipaddress
        import socket

        # IPs configurees manuellement dans .env
        for ip in WHITELIST_IPS:
            self.incident_logger.add_to_whitelist(
                ip_address=ip,
                reason="Configured whitelist entry",
                source="config",
            )

        if not AUTO_WHITELIST_PRIVATE:
            return

        # Reseaux privees RFC 1918
        private_networks = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
        ]

        # IP locale de la machine
        try:
            hostname = socket.gethostname()
            local_ips = socket.gethostbyname_ex(hostname)[2]
            for ip in local_ips:
                self.incident_logger.add_to_whitelist(
                    ip_address=ip,
                    reason="Local machine IP",
                    source="auto",
                )
        except Exception:
            pass

        # Passerelle par defaut
        try:
            with open("/proc/net/route") as f:
                for line in f:
                    fields = line.split()
                    if fields[1] == "00000000":
                        gw_hex = fields[2]
                        gw = ".".join(str(int(gw_hex[i:i+2], 16)) for i in (0, 2, 4, 6))
                        self.incident_logger.add_to_whitelist(
                            ip_address=gw,
                            reason="Default gateway",
                            source="auto",
                        )
                        break
        except Exception:
            pass

        logger.info("Whitelist setup complete (private IPs auto-whitelisted)")

    # ─── Cycle de vie ─────────────────────────────────────────────

    def start(self):
        """Demarre l'agent: capture, analyse, reponse en temps reel."""
        if self._running:
            logger.warning("Agent already running")
            return

        self._running = True
        self._stats["start_time"] = datetime.now()
        self.hybrid_manager.start()

        # Demarrer les composants de capture
        self.sniffer.start()
        self.sniffer.packet_callback = self._on_packet
        self.blocker.start()
        self.scanner.start()
        self.log_collector.start()

        # Demarrer la boucle d'analyse IA
        self._analysis_thread = threading.Thread(
            target=self._analysis_loop, daemon=True, name="ai-analysis"
        )
        self._analysis_thread.start()

        logger.info(
            f"SecurityAgent started - monitoring interface: "
            f"{self.sniffer.interface}"
        )

    def stop(self):
        """Arrete proprement l'agent."""
        logger.info("Stopping SecurityAgent...")
        self._running = False

        self.sniffer.stop()
        self.blocker.stop()
        self.scanner.stop()
        self.log_collector.stop()
        self.hybrid_manager.stop()

        if self._analysis_thread:
            self._analysis_thread.join(timeout=10)

        logger.info(
            f"SecurityAgent stopped - "
            f"stats: {self._stats['incidents_detected']} incidents, "
            f"{self._stats['ips_blocked']} blocks"
        )

    # ─── Pipeline IA: Analyse -> Decision -> Reponse ─────────────

    def _analysis_loop(self):
        """Boucle principale d'analyse IA.
        Analyse le trafic agrege, detecte les anomalies,
        prend des decisions automatiques."""
        while self._running:
            try:
                # 1. Recuperer le trafic agrege
                aggregated = self.sniffer.aggregator.get_aggregated()
                if not aggregated:
                    time.sleep(AGGREGATION_WINDOW)
                    continue

                # 2. Mettre a jour les stats
                total_packets = sum(
                    s["packet_count"] for s in aggregated.values()
                )
                self._stats["packets_analyzed"] += total_packets

                # 3. Prediction IA (Isolation Forest)
                predictions = self.detector.predict(aggregated)

                # 4. Pour chaque IP, evaluer et decider
                for ip, prediction in predictions.items():
                    self._evaluate_ip(ip, prediction, aggregated.get(ip, {}))

                # 5. Nettoyer les anciennes entrees
                self.sniffer.aggregator.reset_old()

                time.sleep(AGGREGATION_WINDOW)

            except Exception as e:
                logger.error(f"Analysis loop error: {e}", exc_info=True)
                time.sleep(5)

    def _evaluate_ip(self, ip: str, prediction: dict, stats: dict):
        """Evalue une IP et prend une decision de securite."""
        # Ignorer si l'IP est deja bloquee
        if self.blocker.is_blocked(ip):
            return

        # Ignorer si l'IP est dans la liste blanche
        if self.incident_logger.is_whitelisted(ip):
            return

        # Calculer le risque complet
        scan_data = self._scan_results.get(ip)
        risk_details = self.risk_scorer.calculate_risk(ip, prediction, scan_data)

        # Determiner le type de menace
        threat_type = self._classify_threat(stats, risk_details)

        # Creer l'evenement de securite
        event = SecurityEvent(
            ip_address=ip,
            risk_score=risk_details["combined_score"],
            risk_level=RiskLevel(risk_details["risk_level"]),
            threat_type=threat_type,
            details=risk_details,
            packet_count=stats.get("packet_count", 0),
            protocol=", ".join(stats.get("protocols", [])),
        )

        # Laisser l'agent prendre sa decision
        decision = self._make_decision(event, stats)

        # Executer la decision
        self._execute_decision(decision)

        # Stocker pour historique
        self._decisions.append(decision)
        if len(self._decisions) > self._max_decisions:
            self._decisions = self._decisions[-self._max_decisions:]

        self._stats["decisions_made"] += 1

    def _classify_threat(self, stats: dict, risk: dict) -> ThreatType:
        """Classifie le type de menace base sur le comportement."""
        syn_ratio = stats.get("syn_count", 0) / max(stats.get("packet_count", 1), 1)
        unique_ports = stats.get("unique_ports", 0)
        frequency = stats.get("frequency", 0)
        total_bytes = stats.get("total_bytes", 0)

        if syn_ratio > 0.8 and unique_ports > 50:
            return ThreatType.PORT_SCAN
        if frequency > 100 and syn_ratio > 0.7:
            return ThreatType.DOS_ATTACK
        if unique_ports < 5 and frequency > 10:
            return ThreatType.BRUTE_FORCE
        if total_bytes > 100000 and frequency < 20:
            return ThreatType.DATA_EXFILTRATION
        if risk.get("is_anomaly"):
            return ThreatType.ANOMALY
        return ThreatType.UNKNOWN

    def _make_decision(self, event: SecurityEvent, stats: dict) -> AgentDecision:
        """Le coeur de l'intelligence de l'agent.
        Prend une decision basee sur la politique et le contexte."""
        should_block = False
        should_alert = True
        alert_channels = ["websocket", "log"]
        reasoning = ""

        # Politique: blocage automatique pour niveau critique
        if event.risk_level == RiskLevel.CRITIQUE:
            if self.policy.auto_block_critical:
                should_block = True
                reasoning = "Auto-block: critical risk level"
                alert_channels.append("email")
            else:
                reasoning = "Critical risk detected, monitoring only"

        # Politique: alerte pour niveau moyen
        elif event.risk_level == RiskLevel.MOYEN:
            if event.threat_type in (ThreatType.PORT_SCAN, ThreatType.DOS_ATTACK):
                if self.policy.auto_block_medium_threats:
                    should_block = True
                    reasoning = f"Auto-block: medium risk with {event.threat_type.value}"
            else:
                reasoning = "Medium risk, alerting and monitoring"

        # Politique: surveillance pour niveau faible
        else:
            if not self.policy.alert_on_low:
                should_alert = False
            reasoning = "Low risk, passive monitoring"

        # Verifier les recidives
        if should_block:
            is_recidive = self.blocker.is_blocked(event.ip_address)
            if is_recidive:
                reasoning += " (recidive: extended block)"
                event.block_duration = self.policy.base_block_duration * 2

        if should_block:
            alert_channels.append("block")
            event.action_taken = ActionType.BLOCKED
            event.blocked = True
        elif should_alert:
            event.action_taken = ActionType.ALERTED
        else:
            event.action_taken = ActionType.MONITORED

        return AgentDecision(
            event=event,
            should_block=should_block,
            should_alert=should_alert,
            should_log=True,
            alert_channels=alert_channels,
            reasoning=reasoning,
            confidence=event.risk_score,
        )

    def _execute_decision(self, decision: AgentDecision):
        """Execute la decision prise par l'agent."""
        event = decision.event
        ip = event.ip_address
        self._stats["incidents_detected"] += 1

        # 1. Bloquer si necessaire
        if decision.should_block:
            recidive = self.blocker.is_blocked(ip)
            block_result = self.blocker.block_ip(
                ip,
                reason=f"{event.threat_type.value}: score={event.risk_score:.4f}",
                duration=event.block_duration or self.policy.base_block_duration,
                is_recidive=recidive,
            )
            if block_result.get("blocked"):
                self._stats["ips_blocked"] += 1
                self.incident_logger.log_blocked_ip(
                    ip,
                    reason=decision.reasoning,
                    block_until=datetime.fromtimestamp(
                        time.time() + block_result.get("duration", 3600)
                    ),
                )

        # 2. Journaliser dans la base
        incident_id = self.incident_logger.log_incident(
            ip_address=ip,
            risk_score=event.risk_score,
            risk_level=event.risk_level.value,
            action_taken=event.action_taken.value,
            details=event.details,
            packet_count=event.packet_count,
        )
        event.id = incident_id

        # 3. Envoyer les alertes
        if decision.should_alert:
            incident_data = event.to_dict()
            if self._event_loop and self._event_loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    self.alert_manager.send_alert(
                        incident_data, decision.alert_channels
                    ),
                    self._event_loop,
                )
            if self.webhook_manager.is_enabled():
                self.webhook_manager.send_alert(
                    alert_type=event.threat_type.value,
                    title=f"Threat detected: {event.threat_type.value}",
                    message=decision.reasoning,
                    severity=event.severity_label,
                    ip=ip,
                )
            self._stats["alerts_sent"] += 1

        # 4. Notifier les callbacks externes
        for callback in self._decision_callbacks:
            try:
                callback(decision)
            except Exception as e:
                logger.error(f"Decision callback error: {e}")

        logger.info(
            f"[{event.severity_label}] IP={ip} "
            f"Score={event.risk_score:.4f} "
            f"Type={event.threat_type.value} "
            f"Action={event.action_taken.value} "
            f"Reason={decision.reasoning}"
        )

    # ─── Callbacks internes ───────────────────────────────────────

    def _on_scan_result(self, result: dict):
        self._scan_results.update(result)

    def _on_packet(self, meta):
        if not meta or not hasattr(meta, "src_ip"):
            return
        if self.signature_detector.count() == 0:
            return
        try:
            from scapy.all import TCP, UDP, Raw
            pass
        except ImportError:
            return

    def _on_log_entry(self, entry):
        if entry.ip_address and entry.severity in ("warning", "error"):
            logger.info(
                f"Suspicious log from {entry.ip_address}: "
                f"{entry.message[:120]}"
            )

    def _on_ip_blocked(self, result: dict):
        logger.info(f"IP blocked: {result}")

    def _on_connectivity_change(self, status: dict):
        mode = status.get("mode", "hors_connexion")
        logger.info(f"Hybrid connectivity update received: {mode}")

        if status.get("online"):
            self.hybrid_manager.set_service_runtime("geolocation", True)
            if CHATBOT_ENABLED:
                if self.chatbot is None:
                    self._configure_chatbot()
                else:
                    self.chatbot.set_cloud_enabled(True)
            flush_result = self.webhook_manager.flush_pending()
            if flush_result.get("flushed"):
                logger.info(f"Flushed {flush_result['flushed']} deferred webhook(s)")
        else:
            if self.chatbot:
                self.chatbot.set_cloud_enabled(
                    False,
                    "Cloud chatbot suspendu en mode hors connexion.",
                )

    # ─── API publique ─────────────────────────────────────────────

    def add_decision_callback(self, callback: Callable):
        """Ajoute un callback appele a chaque decision de l'agent."""
        self._decision_callbacks.append(callback)

    def set_event_loop(self, loop):
        """Assigne la boucle asyncio pour les WebSocket."""
        self._event_loop = loop

    def get_stats(self) -> dict:
        """Retourne les statistiques de l'agent."""
        stats = dict(self._stats)
        if stats["start_time"]:
            stats["uptime_seconds"] = (
                datetime.now() - stats["start_time"]
            ).total_seconds()
            stats["start_time"] = stats["start_time"].isoformat()
        stats["sniffer"] = self.sniffer.get_stats()
        stats["connections"] = self.alert_manager.ws_manager.connection_count
        stats["model_trained"] = self.detector.is_trained
        stats["version"] = self.VERSION
        stats["whitelist_count"] = len(self.incident_logger.get_whitelist(active_only=True))
        stats["fp_stats"] = self.incident_logger.get_fp_stats()
        stats["chatbot_enabled"] = self.chatbot.is_enabled() if self.chatbot else False
        stats["chatbot_model"] = self.chatbot.model_name if self.chatbot and self.chatbot.is_enabled() else None
        stats["hybrid"] = self.hybrid_manager.get_status()
        return stats

    def get_hybrid_status(self) -> dict:
        return self.hybrid_manager.get_status()

    def get_recent_decisions(self, count: int = 50) -> list:
        """Retourne les dernieres decisions de l'agent."""
        return [
            {
                "ip": d.event.ip_address,
                "score": d.event.risk_score,
                "level": d.event.risk_level.value,
                "threat": d.event.threat_type.value,
                "action": d.event.action_taken.value,
                "reasoning": d.reasoning,
                "timestamp": d.event.timestamp.isoformat() if hasattr(d.event.timestamp, 'isoformat') else str(d.event.timestamp),
                "blocked": d.should_block,
            }
            for d in self._decisions[-count:]
        ]

    def force_block(self, ip: str, reason: str = "Manual block") -> dict:
        """Bloque manuellement une IP."""
        return self.blocker.block_ip(ip, reason=reason)

    def force_unblock(self, ip: str) -> dict:
        """Debloque manuellement une IP."""
        result = self.blocker.unblock_ip(ip)
        self.incident_logger.unblock_ip(ip)
        return result

    def mark_false_positive(self, incident_id: int, reason: str,
                            category: str = "other", auto_unblock: bool = True,
                            add_to_whitelist: bool = False,
                            whitelist_duration_hours: int = None) -> dict:
        """Marque un incident comme faux positif.
        Optionnellement debloque l'IP et/ou l'ajoute a la liste blanche."""
        result = self.incident_logger.mark_false_positive(
            incident_id=incident_id,
            reason=reason,
            category=category,
            auto_unblock=auto_unblock,
            add_to_whitelist=add_to_whitelist,
            whitelist_duration_hours=whitelist_duration_hours,
        )
        if result and result.get("fp"):
            ip = result["fp"]["ip_address"]
            original_score = result["fp"].get("original_risk_score", 0) or 0
            self.risk_scorer.record_false_positive(ip, original_score)
            if result.get("unblocked"):
                self.blocker.unblock_ip(ip)
                self._stats["ips_blocked"] = max(0, self._stats["ips_blocked"] - 1)
            self._stats["false_positives_corrected"] += 1
            return result
        return {"error": "Failed to mark false positive"}

    def unmark_false_positive(self, incident_id: int) -> dict:
        """Annule le marquage faux positif d'un incident."""
        success = self.incident_logger.unmark_false_positive(incident_id)
        return {"success": success}

    def add_to_whitelist(self, ip: str, reason: str, expires_hours: int = None) -> dict:
        """Ajoute une IP a la liste blanche."""
        entry_id = self.incident_logger.add_to_whitelist(
            ip_address=ip, reason=reason, expires_hours=expires_hours,
        )
        return {"added": entry_id is not None, "id": entry_id}

    def remove_from_whitelist(self, ip: str) -> dict:
        """Retire une IP de la liste blanche."""
        success = self.incident_logger.remove_from_whitelist(ip)
        return {"removed": success}

    def export_incidents(self, fmt: str = "json", **filters) -> str:
        """Exporte les incidents au format JSON ou CSV."""
        return self.incident_logger.export_incidents(fmt=fmt, **filters)

    def get_whitelist(self) -> list:
        """Retourne la liste blanche active."""
        return self.incident_logger.get_whitelist(active_only=True)

    def analyze_traffic_snapshot(self, traffic_data: dict) -> dict:
        """Analyse instantanee d'un snapshot de trafic (pour les tests)."""
        predictions = self.detector.predict(traffic_data)
        results = {}
        for ip, pred in predictions.items():
            scan_data = self._scan_results.get(ip)
            risk = self.risk_scorer.calculate_risk(ip, pred, scan_data)
            threat = self._classify_threat(
                traffic_data.get(ip, {}), risk
            )
            results[ip] = {
                **pred,
                "risk_details": risk,
                "threat_type": threat.value,
            }
        return results

    def trigger_retrain(self, use_fp_only: bool = True) -> dict:
        """Declenche manuellement le re-training du modele.
        
        Args:
            use_fp_only: Si True, utilise uniquement les faux positifs pour re-entrainer
                        Si False, regenerate completely avec donnees synthetiques
        """
        try:
            if use_fp_only:
                fps = self.incident_logger.get_false_positives(limit=10000)
                if len(fps) < 10:
                    return {"success": False, "reason": "Not enough false positives (min 10)"}

                fp_features = []
                for fp in fps:
                    details = fp.get("details", {})
                    stats = details.get("stats", {})
                    if stats:
                        fp_features.append([
                            stats.get("packet_count", 0),
                            stats.get("total_bytes", 0),
                            stats.get("unique_ports", 0),
                            stats.get("frequency", 0),
                            stats.get("unique_dst_ips", 0),
                            stats.get("syn_count", 0),
                            stats.get("syn_ratio", 0),
                            stats.get("bytes_per_packet", 0),
                        ])

                success = self.detector.retrain_with_false_positives(fp_features)
                return {
                    "success": success,
                    "samples_used": len(fp_features),
                    "timestamp": datetime.now().isoformat(),
                }
            else:
                success = self.detector.train()
                return {
                    "success": success,
                    "mode": "synthetic",
                    "timestamp": datetime.now().isoformat(),
                }
        except Exception as e:
            logger.error(f"Manual retrain failed: {e}")
            return {"success": False, "error": str(e)}

    def get_retrain_status(self) -> dict:
        """Retourne le statut du re-training automatique."""
        return {
            "enabled": self._retrain_enabled,
            "last_retrain": self._last_retrain_time.isoformat() if self._last_retrain_time else None,
            "interval_hours": RETRAIN_INTERVAL_HOURS,
            "min_samples": RETRAIN_MIN_SAMPLES,
            "model_trained": self.detector.is_trained,
        }


class SecurityPolicy:
    """Politique de securite configurable de l'agent."""

    def __init__(self):
        from config.settings import (
            AUTO_BLOCK_CRITICAL, BLOCK_DURATION,
            RISK_LOW_MAX, RISK_MEDIUM_MAX,
        )
        self.auto_block_critical = AUTO_BLOCK_CRITICAL
        self.auto_block_medium_threats = False
        self.alert_on_low = False
        self.base_block_duration = BLOCK_DURATION
        self.risk_low_max = RISK_LOW_MAX
        self.risk_medium_max = RISK_MEDIUM_MAX
