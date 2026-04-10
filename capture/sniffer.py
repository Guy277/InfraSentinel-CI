import os
import threading
import time
import logging
from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf

from config.settings import NETWORK_INTERFACE, CAPTURE_FILTER, PACKET_BATCH_SIZE, AGGREGATION_WINDOW
from ai_engine.signature_detector import get_signature_detector

logger = logging.getLogger(__name__)


class PacketMetadata:
    __slots__ = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "length", "timestamp", "flags")

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, length, timestamp, flags=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.length = length
        self.timestamp = timestamp
        self.flags = flags

    def to_dict(self):
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "length": self.length,
            "timestamp": self.timestamp,
            "flags": self.flags,
        }


class TrafficAggregator:
    def __init__(self, window=AGGREGATION_WINDOW):
        self.window = window
        self.ip_stats = defaultdict(lambda: {
            "packet_count": 0,
            "total_bytes": 0,
            "ports": set(),
            "protocols": set(),
            "timestamps": [],
            "dst_ips": set(),
            "syn_count": 0,
            "first_seen": None,
            "last_seen": None,
        })
        self._lock = threading.Lock()

    def add_packet(self, meta: PacketMetadata):
        with self._lock:
            stats = self.ip_stats[meta.src_ip]
            stats["packet_count"] += 1
            stats["total_bytes"] += meta.length
            if meta.dst_port:
                stats["ports"].add(meta.dst_port)
            stats["protocols"].add(meta.protocol)
            stats["timestamps"].append(meta.timestamp)
            stats["dst_ips"].add(meta.dst_ip)
            if meta.flags and "S" in str(meta.flags):
                stats["syn_count"] += 1
            if stats["first_seen"] is None:
                stats["first_seen"] = meta.timestamp
            stats["last_seen"] = meta.timestamp

    def get_aggregated(self):
        with self._lock:
            result = {}
            now = time.time()
            for ip, stats in list(self.ip_stats.items()):
                if stats["last_seen"] and (now - stats["last_seen"]) > self.window * 60:
                    continue
                timestamps = sorted(stats["timestamps"])
                freq = 0
                if len(timestamps) > 1:
                    span = timestamps[-1] - timestamps[0]
                    if span > 0:
                        freq = len(timestamps) / span
                result[ip] = {
                    "packet_count": stats["packet_count"],
                    "total_bytes": stats["total_bytes"],
                    "unique_ports": len(stats["ports"]),
                    "ports": list(stats["ports"])[:50],
                    "protocols": list(stats["protocols"]),
                    "frequency": round(freq, 4),
                    "unique_dst_ips": len(stats["dst_ips"]),
                    "syn_count": stats["syn_count"],
                    "first_seen": stats["first_seen"],
                    "last_seen": stats["last_seen"],
                }
            return result

    def reset_old(self, max_age=None):
        if max_age is None:
            max_age = self.window * 120
        with self._lock:
            now = time.time()
            to_remove = [ip for ip, s in self.ip_stats.items() if s["last_seen"] and (now - s["last_seen"]) > max_age]
            for ip in to_remove:
                del self.ip_stats[ip]


class NetworkSniffer:
    def __init__(self, interface=None, packet_callback=None):
        if interface:
            self.interface = interface
        elif os.getenv("NETWORK_INTERFACE"):
            self.interface = os.getenv("NETWORK_INTERFACE")
        else:
            self.interface = self._detect_interface()
        self.filter = CAPTURE_FILTER
        self.packet_callback = packet_callback
        self.aggregator = TrafficAggregator()
        self._running = False
        self._thread = None
        self._packet_count = 0
        self._start_time = None

    @staticmethod
    def _detect_interface():
        """Detecte l'interface reseau par defaut (Linux/Windows)."""
        import platform
        system = platform.system()
        
        if system == "Windows":
            return NetworkSniffer._detect_interface_windows()
        else:
            return NetworkSniffer._detect_interface_linux()
    
    @staticmethod
    def _detect_interface_windows():
        """Detecte l'interface par defaut sur Windows via les interfaces Scapy/Npcap."""
        try:
            candidates = []
            for iface in conf.ifaces.values():
                name = getattr(iface, "name", "") or ""
                network_name = getattr(iface, "network_name", "") or ""
                description = getattr(iface, "description", "") or ""
                text = " ".join([name, description]).lower()

                if not network_name:
                    continue
                if any(token in text for token in ["loopback", "miniport", "vmware", "hyper-v", "vethernet", "virtual", "vpn", "expressvpn"]):
                    continue

                score = 0
                if "wi-fi" in text or "wifi" in text or "wireless" in text:
                    score += 30
                if "ethernet" in text:
                    score += 20
                if "intel" in text or "realtek" in text or "broadcom" in text:
                    score += 10

                candidates.append((score, network_name, name, description))

            if candidates:
                candidates.sort(reverse=True)
                return candidates[0][1]

            interfaces = get_if_list()
            for iface_name in interfaces:
                iface_lower = iface_name.lower()
                if "loopback" in iface_lower:
                    continue
                return iface_name

            return "Wi-Fi"
        except Exception:
            return "Ethernet"
    
    @staticmethod
    def _detect_interface_linux():
        """Detecte l'interface par defaut sur Linux."""
        try:
            with open("/proc/net/route") as f:
                for line in f:
                    fields = line.split()
                    if len(fields) >= 2 and fields[1] == "00000000" and fields[0] != "lo":
                        return fields[0]
        except Exception:
            pass
        try:
            import netifaces
            for iface in netifaces.interfaces():
                if iface != "lo":
                    return iface
        except ImportError:
            pass
        return "eth0"

    def _check_signatures(self, payload: bytes, proto: str, src_ip: str) -> bool:
        if not payload:
            return False
        try:
            detector = get_signature_detector()
            if detector.count() == 0:
                return False
            rule = detector.detect(payload, proto)
            if rule:
                logger.warning(f"SIGMATCH: {rule.msg} from {src_ip}")
                self._signature_callback(src_ip, rule)
                return True
        except Exception as e:
            logger.debug(f"Signature check error: {e}")
        return False

    def _signature_callback(self, ip: str, rule):
        if self.packet_callback:
            self.packet_callback({"type": "signature", "ip": ip, "rule": rule})

    def _process_packet(self, packet):
        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        src_port = None
        dst_port = None
        protocol = "IP"
        flags = None
        payload = None

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            protocol = "TCP"
            flags = str(tcp.flags)
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            protocol = "UDP"
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        meta = PacketMetadata(
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=len(packet),
            timestamp=time.time(),
            flags=flags,
        )

        self.aggregator.add_packet(meta)
        self._packet_count += 1

        if payload and self._check_signatures(payload, protocol.lower(), ip_layer.src):
            logger.warning(f"Signature match! IP={ip_layer.src} proto={protocol}")

        if self.packet_callback:
            self.packet_callback(meta)

    def start(self):
        if self._running:
            logger.warning("Sniffer already running")
            return

        self._running = True
        self._start_time = time.time()
        self._thread = threading.Thread(target=self._sniff, daemon=True)
        self._thread.start()
        logger.info(f"Sniffer started on interface {self.interface} (filter={self.filter or 'none'})")

    def _sniff(self):
        while self._running:
            try:
                sniff(
                    iface=self.interface,
                    filter=self.filter if self.filter else None,
                    prn=self._process_packet,
                    store=0,
                    stop_filter=lambda _: not self._running,
                )
            except PermissionError:
                logger.error("Permission denied: run as root for packet capture")
                break
            except Exception as e:
                if self._running:
                    logger.error(f"Sniffer error: {e} — restarting in 2s")
                    time.sleep(2)
                else:
                    break
        logger.info("Sniffer thread exited")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info(f"Sniffer stopped. Total packets captured: {self._packet_count}")

    def get_stats(self):
        elapsed = time.time() - self._start_time if self._start_time else 0
        return {
            "interface": self.interface,
            "packets_captured": self._packet_count,
            "elapsed_seconds": round(elapsed, 2),
            "packets_per_second": round(self._packet_count / elapsed, 2) if elapsed > 0 else 0,
            "running": self._running,
        }
