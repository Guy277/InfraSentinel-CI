import logging
import json
import enum
from datetime import datetime, timedelta
from typing import Optional

import numpy as np

from database.db import SessionLocal
from database.models import Incident, Alert, BlockedIP, FalsePositive, WhitelistEntry, RiskLevel

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


class IncidentLogger:
    def __init__(self):
        self._session_factory = SessionLocal

    def log_incident(self, ip_address: str, risk_score: float, risk_level: str,
                     action_taken: str = "", details: dict = None,
                     port: int = None, protocol: str = None,
                     packet_count: int = 0) -> Optional[int]:
        session = self._session_factory()
        try:
            level_enum = RiskLevel(risk_level)
        except ValueError:
            level_enum = RiskLevel.MOYEN

        try:
            incident = Incident(
                ip_address=ip_address,
                risk_score=float(risk_score),
                risk_level=level_enum,
                action_taken=action_taken,
                details=_sanitize(details) if details else {},
                port=port,
                protocol=protocol,
                packet_count=int(packet_count),
            )
            session.add(incident)
            session.commit()
            incident_id = incident.id
            logger.info(f"Incident logged: id={incident_id} ip={ip_address} level={risk_level}")
            return incident_id
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to log incident: {e}")
            return None
        finally:
            session.close()

    def log_alert(self, incident_id: int, method: str, status: str = "sent") -> Optional[int]:
        session = self._session_factory()
        try:
            alert = Alert(
                incident_id=incident_id,
                method=method,
                status=status,
            )
            session.add(alert)
            session.commit()
            return alert.id
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to log alert: {e}")
            return None
        finally:
            session.close()

    def log_blocked_ip(self, ip_address: str, reason: str = "",
                       block_until: datetime = None) -> Optional[int]:
        session = self._session_factory()
        try:
            existing = session.query(BlockedIP).filter_by(ip_address=ip_address).first()
            if existing:
                existing.block_count += 1
                existing.is_active = 1
                existing.reason = reason
                existing.block_until = block_until
                existing.blocked_at = datetime.now()
                session.commit()
                return existing.id

            blocked = BlockedIP(
                ip_address=ip_address,
                reason=reason,
                block_until=block_until,
                is_active=1,
            )
            session.add(blocked)
            session.commit()
            return blocked.id
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to log blocked IP: {e}")
            return None
        finally:
            session.close()

    def unblock_ip(self, ip_address: str) -> bool:
        session = self._session_factory()
        try:
            blocked = session.query(BlockedIP).filter_by(ip_address=ip_address, is_active=1).first()
            if blocked:
                blocked.is_active = 0
                session.commit()
                return True
            return False
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to unblock IP in DB: {e}")
            return False
        finally:
            session.close()

    def get_incidents(self, limit=100, offset=0, risk_level: str = None,
                      ip: str = None, start_date: datetime = None,
                      end_date: datetime = None) -> list:
        session = self._session_factory()
        try:
            query = session.query(Incident)
            if risk_level:
                try:
                    query = query.filter(Incident.risk_level == RiskLevel(risk_level))
                except ValueError:
                    pass
            if ip:
                query = query.filter(Incident.ip_address == ip)
            if start_date:
                query = query.filter(Incident.timestamp >= start_date)
            if end_date:
                query = query.filter(Incident.timestamp <= end_date)

            query = query.order_by(Incident.timestamp.desc()).limit(limit).offset(offset)
            return [inc.to_dict() for inc in query.all()]
        except Exception as e:
            logger.error(f"Failed to get incidents: {e}")
            return []
        finally:
            session.close()

    def get_incident(self, incident_id: int) -> Optional[dict]:
        session = self._session_factory()
        try:
            inc = session.query(Incident).filter_by(id=incident_id).first()
            return inc.to_dict() if inc else None
        except Exception as e:
            logger.error(f"Failed to get incident: {e}")
            return None
        finally:
            session.close()

    def get_blocked_ips(self, active_only=True) -> list:
        session = self._session_factory()
        try:
            query = session.query(BlockedIP)
            if active_only:
                query = query.filter_by(is_active=1)
            return [b.to_dict() for b in query.all()]
        except Exception as e:
            logger.error(f"Failed to get blocked IPs: {e}")
            return []
        finally:
            session.close()

    def get_incident_stats(self) -> dict:
        session = self._session_factory()
        try:
            total = session.query(Incident).count()
            from sqlalchemy import func
            by_level = dict(
                session.query(Incident.risk_level, func.count(Incident.id))
                .group_by(Incident.risk_level)
                .all()
            )
            blocked_count = session.query(BlockedIP).filter_by(is_active=1).count()
            alert_count = session.query(Alert).count()

            return {
                "total_incidents": total,
                "by_level": {k.value if hasattr(k, 'value') else str(k): v for k, v in by_level.items()},
                "active_blocks": blocked_count,
                "total_alerts": alert_count,
            }
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {}
        finally:
            session.close()

    def export_incidents(self, fmt="json", **filters) -> str:
        incidents = self.get_incidents(limit=10000, **filters)
        if fmt == "json":
            return json.dumps(incidents, indent=2, default=str)
        elif fmt == "csv":
            if not incidents:
                return ""
            headers = list(incidents[0].keys())
            lines = [",".join(headers)]
            for inc in incidents:
                row = [str(inc.get(h, "")) for h in headers]
                lines.append(",".join(row))
            return "\n".join(lines)
        return ""

    # ─── Gestion des faux positifs ─────────────────────────────

    def mark_false_positive(self, incident_id: int, reason: str,
                            category: str = "other", marked_by: str = "admin",
                            auto_unblock: bool = True,
                            add_to_whitelist: bool = False,
                            whitelist_duration_hours: int = None) -> Optional[dict]:
        session = self._session_factory()
        try:
            incident = session.query(Incident).filter_by(id=incident_id).first()
            if not incident:
                logger.error(f"Incident {incident_id} not found")
                return None

            existing_fp = session.query(FalsePositive).filter_by(incident_id=incident_id).first()
            if existing_fp:
                logger.warning(f"Incident {incident_id} already marked as false positive")
                return existing_fp.to_dict()

            fp = FalsePositive(
                incident_id=incident_id,
                ip_address=incident.ip_address,
                category=category,
                reason=reason,
                marked_by=marked_by,
                auto_unblocked=False,
                added_to_whitelist=False,
                original_risk_score=incident.risk_score,
                original_risk_level=incident.risk_level.value if incident.risk_level else None,
                original_threat_type=incident.details.get("threat_type") if incident.details else None,
            )

            incident.is_false_positive = True
            session.add(fp)
            session.flush()

            result = {"fp": fp.to_dict(), "unblocked": False, "whitelisted": False}

            if auto_unblock:
                blocked = session.query(BlockedIP).filter_by(
                    ip_address=incident.ip_address, is_active=1
                ).first()
                if blocked:
                    blocked.is_active = 0
                    fp.auto_unblocked = True
                    result["unblocked"] = True
                    logger.info(f"Auto-unblocked {incident.ip_address} (false positive)")

            if add_to_whitelist:
                expires = None
                if whitelist_duration_hours:
                    expires = datetime.now() + timedelta(hours=whitelist_duration_hours)
                wl_entry = WhitelistEntry(
                    ip_address=incident.ip_address,
                    reason=f"False positive: {reason}",
                    added_by=marked_by,
                    source="false_positive",
                    fp_id=fp.id,
                    expires_at=expires,
                    is_active=True,
                )
                session.add(wl_entry)
                fp.added_to_whitelist = True
                result["whitelisted"] = True
                logger.info(f"Added {incident.ip_address} to whitelist (false positive)")

            session.commit()
            result["fp"] = fp.to_dict()
            logger.info(f"Marked incident {incident_id} as false positive: {reason}")
            return result
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to mark false positive: {e}")
            return None
        finally:
            session.close()

    def unmark_false_positive(self, incident_id: int) -> bool:
        session = self._session_factory()
        try:
            fp = session.query(FalsePositive).filter_by(incident_id=incident_id).first()
            if not fp:
                return False

            ip_address = fp.ip_address

            incident = session.query(Incident).filter_by(id=incident_id).first()
            if incident:
                incident.is_false_positive = False

            if fp.added_to_whitelist:
                wl = session.query(WhitelistEntry).filter_by(
                    ip_address=ip_address, source="false_positive", is_active=True
                ).first()
                if wl:
                    wl.is_active = False

            session.delete(fp)
            session.commit()
            logger.info(f"Unmarked incident {incident_id} as false positive")
            return True
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to unmark false positive: {e}")
            return False
        finally:
            session.close()

    def get_false_positives(self, limit=100, offset=0) -> list:
        session = self._session_factory()
        try:
            fps = session.query(FalsePositive).order_by(
                FalsePositive.marked_at.desc()
            ).limit(limit).offset(offset).all()
            return [fp.to_dict() for fp in fps]
        except Exception as e:
            logger.error(f"Failed to get false positives: {e}")
            return []
        finally:
            session.close()

    def get_fp_stats(self) -> dict:
        session = self._session_factory()
        try:
            from sqlalchemy import func as f
            total_fp = session.query(FalsePositive).count()
            total_incidents = session.query(Incident).count()

            by_category = dict(
                session.query(FalsePositive.category, f.count(FalsePositive.id))
                .group_by(FalsePositive.category)
                .all()
            )

            recent_fps = session.query(FalsePositive).order_by(
                FalsePositive.marked_at.desc()
            ).limit(10).all()

            return {
                "total_false_positives": total_fp,
                "total_incidents": total_incidents,
                "fp_rate": round(total_fp / max(total_incidents, 1), 4),
                "by_category": {k: v for k, v in by_category.items()},
                "recent": [fp.to_dict() for fp in recent_fps],
            }
        except Exception as e:
            logger.error(f"Failed to get FP stats: {e}")
            return {}
        finally:
            session.close()

    def get_fp_categories(self) -> list:
        return [
            {"value": "legitimate_traffic", "label": "Trafic legitime"},
            {"value": "scheduled_task", "label": "Tache planifiee"},
            {"value": "monitoring_tool", "label": "Outil de monitoring"},
            {"value": "backup_activity", "label": "Activite de sauvegarde"},
            {"value": "known_service", "label": "Service connu"},
            {"value": "scanner_fp", "label": "Fausse detection du scanner"},
            {"value": "ai_model_error", "label": "Erreur du modele IA"},
            {"value": "other", "label": "Autre"},
        ]

    # ─── Gestion de la liste blanche ───────────────────────────

    def add_to_whitelist(self, ip_address: str, reason: str,
                         added_by: str = "admin", source: str = "manual",
                         expires_hours: int = None) -> Optional[int]:
        session = self._session_factory()
        try:
            existing = session.query(WhitelistEntry).filter_by(
                ip_address=ip_address, is_active=True
            ).first()
            if existing:
                logger.info(f"{ip_address} already in whitelist")
                return existing.id

            expires = None
            if expires_hours:
                expires = datetime.now() + timedelta(hours=expires_hours)

            entry = WhitelistEntry(
                ip_address=ip_address,
                reason=reason,
                added_by=added_by,
                source=source,
                expires_at=expires,
                is_active=True,
            )
            session.add(entry)
            session.commit()
            logger.info(f"Added {ip_address} to whitelist: {reason}")
            return entry.id
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to add to whitelist: {e}")
            return None
        finally:
            session.close()

    def remove_from_whitelist(self, ip_address: str) -> bool:
        session = self._session_factory()
        try:
            entry = session.query(WhitelistEntry).filter_by(
                ip_address=ip_address, is_active=True
            ).first()
            if entry:
                entry.is_active = False
                session.commit()
                logger.info(f"Removed {ip_address} from whitelist")
                return True
            return False
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to remove from whitelist: {e}")
            return False
        finally:
            session.close()

    def is_whitelisted(self, ip_address: str) -> bool:
        session = self._session_factory()
        try:
            entry = session.query(WhitelistEntry).filter_by(
                ip_address=ip_address, is_active=True
            ).first()
            if not entry:
                return False
            if entry.expires_at and datetime.now() >= entry.expires_at:
                entry.is_active = False
                session.commit()
                return False
            return True
        except Exception as e:
            logger.error(f"Failed to check whitelist: {e}")
            return False
        finally:
            session.close()

    def get_whitelist(self, active_only=True) -> list:
        session = self._session_factory()
        try:
            query = session.query(WhitelistEntry)
            if active_only:
                query = query.filter_by(is_active=True)
            entries = query.order_by(WhitelistEntry.added_at.desc()).all()
            return [e.to_dict() for e in entries]
        except Exception as e:
            logger.error(f"Failed to get whitelist: {e}")
            return []
        finally:
            session.close()

    def get_fp_ip_history(self, ip_address: str) -> list:
        session = self._session_factory()
        try:
            fps = session.query(FalsePositive).filter_by(
                ip_address=ip_address
            ).order_by(FalsePositive.marked_at.desc()).all()
            return [fp.to_dict() for fp in fps]
        except Exception as e:
            logger.error(f"Failed to get FP history for IP: {e}")
            return []
        finally:
            session.close()
