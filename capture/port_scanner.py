import threading
import time
import logging

logger = logging.getLogger(__name__)

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    logger.warning("python-nmap not available. Port scanning will be disabled.")


class PortScanner:
    def __init__(self, targets=None, interval=None):
        from config.settings import SCAN_TARGETS, SCAN_INTERVAL
        self.targets = targets or SCAN_TARGETS
        self.interval = interval or SCAN_INTERVAL
        self._running = False
        self._thread = None
        self._scan_results = {}
        self._lock = threading.Lock()
        self._callbacks = []

    def add_callback(self, callback):
        self._callbacks.append(callback)

    def scan_host(self, target, arguments="-sS -sV -O --top-ports 100"):
        if not NMAP_AVAILABLE:
            logger.error("nmap not available")
            return None

        try:
            scanner = nmap.PortScanner()
            result = scanner.scan(hosts=target, arguments=arguments)
            scan_data = {}
            for host in result["scan"]:
                host_info = result["scan"][host]
                scan_data[host] = {
                    "state": host_info.get("status", {}).get("state", "unknown"),
                    "hostname": host_info.get("hostnames", [{}])[0].get("name", ""),
                    "os": self._extract_os(host_info),
                    "ports": self._extract_ports(host_info),
                    "scan_time": time.time(),
                }
            with self._lock:
                self._scan_results.update(scan_data)
            return scan_data
        except Exception as e:
            logger.error(f"Scan error for {target}: {e}")
            return None

    def _extract_os(self, host_info):
        os_matches = host_info.get("osmatch", [])
        if os_matches:
            return os_matches[0].get("name", "unknown")
        return "unknown"

    def _extract_ports(self, host_info):
        ports = []
        for proto in host_info.get("tcp", {}):
            port_info = host_info["tcp"][proto]
            ports.append({
                "port": proto,
                "state": port_info.get("state", "unknown"),
                "service": port_info.get("name", "unknown"),
                "version": port_info.get("version", ""),
                "product": port_info.get("product", ""),
            })
        return ports

    def scan_network(self, arguments="-sn"):
        if not NMAP_AVAILABLE:
            return []

        try:
            scanner = nmap.PortScanner()
            live_hosts = []
            for target in self.targets:
                result = scanner.scan(hosts=target, arguments=arguments)
                for host in result["scan"]:
                    if result["scan"][host]["status"]["state"] == "up":
                        live_hosts.append(host)
            logger.info(f"Network scan found {len(live_hosts)} live hosts")
            return live_hosts
        except Exception as e:
            logger.error(f"Network scan error: {e}")
            return []

    def _periodic_scan(self):
        while self._running:
            logger.info("Starting periodic port scan")
            for target in self.targets:
                result = self.scan_host(target)
                if result:
                    for callback in self._callbacks:
                        try:
                            callback(result)
                        except Exception as e:
                            logger.error(f"Scan callback error: {e}")
            time.sleep(self.interval)

    def start(self):
        if not NMAP_AVAILABLE:
            logger.warning("Cannot start scanner: nmap not available")
            return
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._periodic_scan, daemon=True)
        self._thread.start()
        logger.info("Port scanner started")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("Port scanner stopped")

    def get_results(self):
        with self._lock:
            return dict(self._scan_results)
