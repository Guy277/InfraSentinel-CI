from sqlalchemy import Column, Integer, String, Float, DateTime, Enum, ForeignKey, Text, JSON, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum

from database.db import Base


class RiskLevel(enum.Enum):
    FAIBLE = "faible"
    MOYEN = "moyen"
    CRITIQUE = "critique"


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), nullable=False, index=True)
    risk_score = Column(Float, nullable=False)
    risk_level = Column(Enum(RiskLevel), nullable=False)
    action_taken = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    details = Column(JSON)
    port = Column(Integer)
    protocol = Column(String(10))
    packet_count = Column(Integer, default=0)
    is_false_positive = Column(Boolean, default=False, index=True)

    alerts = relationship("Alert", back_populates="incident", cascade="all, delete-orphan")
    false_positive = relationship("FalsePositive", back_populates="incident", uselist=False)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value if self.risk_level else None,
            "action_taken": self.action_taken,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "details": self.details,
            "port": self.port,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "is_false_positive": self.is_false_positive,
        }


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    sent_at = Column(DateTime(timezone=True), server_default=func.now())
    method = Column(String(50), nullable=False)
    status = Column(String(20), default="sent")

    incident = relationship("Incident", back_populates="alerts")

    def to_dict(self):
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "method": self.method,
            "status": self.status,
        }


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), nullable=False, unique=True, index=True)
    blocked_at = Column(DateTime(timezone=True), server_default=func.now())
    block_until = Column(DateTime(timezone=True))
    reason = Column(Text)
    block_count = Column(Integer, default=1)
    is_active = Column(Integer, default=1)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "blocked_at": self.blocked_at.isoformat() if self.blocked_at else None,
            "block_until": self.block_until.isoformat() if self.block_until else None,
            "reason": self.reason,
            "block_count": self.block_count,
            "is_active": bool(self.is_active),
        }


class FalsePositive(Base):
    __tablename__ = "false_positives"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, unique=True)
    ip_address = Column(String(45), nullable=False, index=True)
    category = Column(String(50), nullable=False, default="other")
    reason = Column(Text, nullable=False)
    marked_by = Column(String(100), default="admin")
    marked_at = Column(DateTime(timezone=True), server_default=func.now())
    auto_unblocked = Column(Boolean, default=False)
    added_to_whitelist = Column(Boolean, default=False)
    original_risk_score = Column(Float)
    original_risk_level = Column(String(20))
    original_threat_type = Column(String(50))

    incident = relationship("Incident", back_populates="false_positive")

    def to_dict(self):
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "ip_address": self.ip_address,
            "category": self.category,
            "reason": self.reason,
            "marked_by": self.marked_by,
            "marked_at": self.marked_at.isoformat() if self.marked_at else None,
            "auto_unblocked": self.auto_unblocked,
            "added_to_whitelist": self.added_to_whitelist,
            "original_risk_score": self.original_risk_score,
            "original_risk_level": self.original_risk_level,
            "original_threat_type": self.original_threat_type,
        }


class WhitelistEntry(Base):
    __tablename__ = "whitelist"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), nullable=False, unique=True, index=True)
    reason = Column(Text, nullable=False)
    added_by = Column(String(100), default="admin")
    added_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)
    source = Column(String(50), default="manual")
    fp_id = Column(Integer, ForeignKey("false_positives.id"), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "reason": self.reason,
            "added_by": self.added_by,
            "added_at": self.added_at.isoformat() if self.added_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active": self.is_active,
            "source": self.source,
        }
