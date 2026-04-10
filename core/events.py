from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
from enum import Enum


class RiskLevel(Enum):
    FAIBLE = "faible"
    MOYEN = "moyen"
    CRITIQUE = "critique"


class ActionType(Enum):
    MONITORED = "monitored"
    ALERTED = "alerted"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"


class ThreatType(Enum):
    ANOMALY = "anomaly"
    PORT_SCAN = "port_scan"
    DOS_ATTACK = "dos_attack"
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE = "malware"
    SUSPICIOUS_LOG = "suspicious_log"
    UNKNOWN = "unknown"


@dataclass
class TrafficStats:
    ip_address: str
    packet_count: int = 0
    total_bytes: int = 0
    unique_ports: int = 0
    ports: list = field(default_factory=list)
    protocols: list = field(default_factory=list)
    frequency: float = 0.0
    unique_dst_ips: int = 0
    syn_count: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    @property
    def syn_ratio(self) -> float:
        return self.syn_count / max(self.packet_count, 1)

    @property
    def bytes_per_packet(self) -> float:
        return self.total_bytes / max(self.packet_count, 1)

    def to_features(self) -> list:
        return [
            self.packet_count, self.total_bytes, self.unique_ports,
            self.frequency, self.unique_dst_ips, self.syn_count,
            self.syn_ratio, self.bytes_per_packet,
        ]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Prediction:
    ip_address: str
    risk_score: float
    risk_level: RiskLevel
    is_anomaly: bool
    raw_score: float
    threat_type: ThreatType = ThreatType.UNKNOWN
    confidence: float = 0.0
    features: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk_level"] = self.risk_level.value
        d["threat_type"] = self.threat_type.value
        return d


@dataclass
class SecurityEvent:
    id: Optional[int] = None
    ip_address: str = ""
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.FAIBLE
    threat_type: ThreatType = ThreatType.UNKNOWN
    action_taken: ActionType = ActionType.MONITORED
    timestamp: str = ""
    details: dict = field(default_factory=dict)
    port: Optional[int] = None
    protocol: Optional[str] = None
    packet_count: int = 0
    blocked: bool = False
    block_duration: int = 0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk_level"] = self.risk_level.value
        d["threat_type"] = self.threat_type.value
        d["action_taken"] = self.action_taken.value
        return d

    @property
    def severity_label(self) -> str:
        labels = {
            RiskLevel.FAIBLE: "INFO",
            RiskLevel.MOYEN: "WARNING",
            RiskLevel.CRITIQUE: "CRITICAL",
        }
        return labels.get(self.risk_level, "INFO")


@dataclass
class AgentDecision:
    event: SecurityEvent
    should_block: bool = False
    should_alert: bool = True
    should_log: bool = True
    alert_channels: list = field(default_factory=lambda: ["websocket", "log"])
    reasoning: str = ""
    confidence: float = 0.0

    @property
    def actions(self) -> list:
        acts = []
        if self.should_log:
            acts.append("log")
        if self.should_alert:
            acts.extend(self.alert_channels)
        if self.should_block:
            acts.append("block")
        return acts
