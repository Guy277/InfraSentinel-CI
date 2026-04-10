import logging
import time
from collections import defaultdict

from config.settings import RISK_LOW_MAX, RISK_MEDIUM_MAX

logger = logging.getLogger(__name__)


class VulnerabilityAssessment:
    SUSPICIOUS_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        110: "POP3", 135: "MSRPC", 139: "NetBIOS", 445: "SMB",
        1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
        27017: "MongoDB", 11211: "Memcached",
    }

    HIGH_RISK_PORTS = {23, 445, 3389, 5900, 6379, 11211, 27017}

    @staticmethod
    def assess_ports(ports: list) -> dict:
        open_suspicious = []
        open_high_risk = []
        for port_info in ports:
            port_num = port_info.get("port", 0)
            if port_num in VulnerabilityAssessment.HIGH_RISK_PORTS:
                open_high_risk.append({
                    "port": port_num,
                    "service": VulnerabilityAssessment.SUSPICIOUS_PORTS.get(port_num, "unknown"),
                    "risk": "high",
                })
            elif port_num in VulnerabilityAssessment.SUSPICIOUS_PORTS:
                open_suspicious.append({
                    "port": port_num,
                    "service": VulnerabilityAssessment.SUSPICIOUS_PORTS.get(port_num, "unknown"),
                    "risk": "medium",
                })

        score = 0.0
        score += len(open_high_risk) * 0.15
        score += len(open_suspicious) * 0.05
        score = min(1.0, score)

        return {
            "vulnerability_score": round(score, 4),
            "high_risk_ports": open_high_risk,
            "suspicious_ports": open_suspicious,
            "total_open": len(ports),
        }


class RiskScorer:
    def __init__(self):
        self.ip_history = defaultdict(list)
        self.ip_baseline = {}
        self._max_history = 100
        self._fp_ips = {}  # ip -> {count, last_fp_score_reduction}

    def calculate_risk(self, ip: str, prediction: dict, scan_data: dict = None) -> dict:
        base_score = prediction.get("risk_score", 0)
        stats = prediction.get("stats", {})

        behavioral_score = self._behavioral_analysis(ip, stats)
        vuln_score = 0
        if scan_data:
            vuln = VulnerabilityAssessment.assess_ports(scan_data.get("ports", []))
            vuln_score = vuln["vulnerability_score"]

        combined_score = (
            base_score * 0.5 +
            behavioral_score * 0.3 +
            vuln_score * 0.2
        )
        combined_score = min(1.0, combined_score)

        # Appliquer la reduction de score pour les faux positifs precedents
        fp_reduction = self._get_fp_reduction(ip)
        if fp_reduction > 0:
            combined_score = max(0.0, combined_score - fp_reduction)

        risk_level = self._classify(combined_score)

        self.ip_history[ip].append({
            "timestamp": time.time(),
            "score": combined_score,
            "level": risk_level,
        })
        if len(self.ip_history[ip]) > self._max_history:
            self.ip_history[ip] = self.ip_history[ip][-self._max_history:]

        details = {
            "base_score": round(base_score, 4),
            "behavioral_score": round(behavioral_score, 4),
            "vulnerability_score": round(vuln_score, 4),
            "combined_score": round(combined_score, 4),
            "risk_level": risk_level,
            "is_anomaly": prediction.get("is_anomaly", False),
            "packet_count": stats.get("packet_count", 0),
            "unique_ports": stats.get("unique_ports", 0),
            "syn_count": stats.get("syn_count", 0),
            "frequency": stats.get("frequency", 0),
        }

        if fp_reduction > 0:
            details["fp_reduction_applied"] = round(fp_reduction, 4)

        history = self.ip_history[ip]
        if len(history) >= 3:
            recent_scores = [h["score"] for h in history[-5:]]
            details["trend"] = "increasing" if recent_scores[-1] > recent_scores[0] else "decreasing"
            details["avg_recent_score"] = round(sum(recent_scores) / len(recent_scores), 4)

        return details

    def _behavioral_analysis(self, ip: str, stats: dict) -> float:
        score = 0.0

        freq = stats.get("frequency", 0)
        if freq > 100:
            score += 0.3
        elif freq > 50:
            score += 0.2
        elif freq > 10:
            score += 0.1

        unique_ports = stats.get("unique_ports", 0)
        if unique_ports > 100:
            score += 0.3
        elif unique_ports > 20:
            score += 0.2
        elif unique_ports > 5:
            score += 0.1

        syn_ratio = stats.get("syn_count", 0) / max(stats.get("packet_count", 1), 1)
        if syn_ratio > 0.8:
            score += 0.3
        elif syn_ratio > 0.5:
            score += 0.15

        history = self.ip_history.get(ip, [])
        if len(history) > 1:
            recent_avg = sum(h["score"] for h in history[-5:]) / min(len(history), 5)
            if recent_avg > 0.7:
                score += 0.1

        return min(1.0, score)

    def _classify(self, score: float) -> str:
        if score <= RISK_LOW_MAX:
            return "faible"
        elif score <= RISK_MEDIUM_MAX:
            return "moyen"
        return "critique"

    def get_ip_history(self, ip: str) -> list:
        return list(self.ip_history.get(ip, []))

    def get_all_high_risk(self, threshold=0.7) -> list:
        result = []
        for ip, history in self.ip_history.items():
            if history and history[-1]["score"] >= threshold:
                result.append({"ip": ip, **history[-1]})
        return sorted(result, key=lambda x: x["score"], reverse=True)

    def record_false_positive(self, ip: str, original_score: float):
        """Enregistre un faux positif pour une IP.
        Plus le nombre de FPs est eleve, plus la reduction de score est forte."""
        if ip not in self._fp_ips:
            self._fp_ips[ip] = {"count": 0, "total_reduction": 0.0}
        self._fp_ips[ip]["count"] += 1
        # Reduction progressive: 0.1 par FP, max 0.5
        reduction = min(0.5, self._fp_ips[ip]["count"] * 0.1)
        self._fp_ips[ip]["total_reduction"] = reduction
        logger.info(
            f"FP recorded for {ip}: count={self._fp_ips[ip]['count']}, "
            f"reduction={reduction:.2f}"
        )

    def _get_fp_reduction(self, ip: str) -> float:
        """Retourne la reduction de score pour une IP ayant des FPs precedents."""
        fp_info = self._fp_ips.get(ip)
        if fp_info:
            return fp_info["total_reduction"]
        return 0.0

    def clear_fp_history(self, ip: str):
        """Supprime l'historique de faux positifs d'une IP."""
        if ip in self._fp_ips:
            del self._fp_ips[ip]
