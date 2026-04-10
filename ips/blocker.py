import subprocess
import logging
import time
import threading
import platform
from datetime import datetime, timedelta
from ipaddress import ip_address

from config.settings import BLOCK_DURATION, MAX_BLOCK_DURATION, RECIDIVE_MULTIPLIER, AUTO_BLOCK_CRITICAL

logger = logging.getLogger(__name__)

IS_WINDOWS = platform.system() == "Windows"


def _is_ipv6(ip: str) -> bool:
    try:
        return ip_address(ip).version == 6
    except ValueError:
        return False


class IPBlocker:
    def __init__(self):
        self._blocked = {}
        self._lock = threading.Lock()
        self._unblock_thread = None
        self._running = False
        self._callbacks = []

    def add_callback(self, callback):
        self._callbacks.append(callback)

    def block_ip(self, ip: str, reason: str = "", duration: int = None, is_recidive: bool = False) -> dict:
        if duration is None:
            duration = BLOCK_DURATION

        if is_recidive:
            prev_blocks = self._blocked.get(ip, {}).get("block_count", 0)
            duration = min(int(duration * (RECIDIVE_MULTIPLIER ** prev_blocks)), MAX_BLOCK_DURATION)

        with self._lock:
            if ip in self._blocked and self._blocked[ip].get("is_active"):
                self._blocked[ip]["block_count"] = self._blocked[ip].get("block_count", 0) + 1
                self._blocked[ip]["block_until"] = datetime.now() + timedelta(seconds=duration)
                self._blocked[ip]["reason"] = reason
                self._blocked[ip]["duration"] = duration
                logger.info(f"Extended block for {ip} (count: {self._blocked[ip]['block_count']})")
            else:
                self._blocked[ip] = {
                    "ip_address": ip,
                    "blocked_at": datetime.now(),
                    "block_until": datetime.now() + timedelta(seconds=duration),
                    "reason": reason,
                    "duration": duration,
                    "is_active": True,
                    "block_count": 1,
                }

        success = self._apply_iptables_block(ip)
        result = {
            "ip": ip,
            "blocked": success,
            "duration": duration,
            "reason": reason,
            "block_count": self._blocked[ip]["block_count"],
        }

        for callback in self._callbacks:
            try:
                callback(result)
            except Exception as e:
                logger.error(f"Block callback error: {e}")

        return result

    def unblock_ip(self, ip: str) -> dict:
        with self._lock:
            if ip not in self._blocked:
                return {"ip": ip, "unblocked": False, "reason": "not found"}
            self._blocked[ip]["is_active"] = False

        success = self._remove_iptables_block(ip)
        logger.info(f"Unblocked IP {ip}: {success}")
        return {"ip": ip, "unblocked": success}

    def _apply_iptables_block(self, ip: str) -> bool:
        if IS_WINDOWS:
            return self._apply_windows_firewall_block(ip)
        else:
            return self._apply_iptables_block_linux(ip)
    
    def _apply_iptables_block_linux(self, ip: str) -> bool:
        is_ipv6 = _is_ipv6(ip)
        iptables_cmd = "ip6tables" if is_ipv6 else "iptables"
        
        try:
            result = subprocess.run(
                [iptables_cmd, "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                return True

            subprocess.run(
                [iptables_cmd, "-I", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, check=True, timeout=5
            )
            logger.info(f"{iptables_cmd} rule added: DROP all from {ip}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"{iptables_cmd} error for {ip}: {e}")
            return False
        except FileNotFoundError:
            logger.error(f"{iptables_cmd} not found. Blocking simulated.")
            return True
        except Exception as e:
            logger.error(f"Block error for {ip}: {e}")
            return False
    
    def _apply_windows_firewall_block(self, ip: str) -> bool:
        """Bloque une IP via Windows Firewall."""
        rule_name = f"IDS_BLOCK_{ip.replace('.', '_')}"
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}",
                 "dir=in",
                 "action=block",
                 f"remoteip={ip}",
                 "enable=yes"],
                capture_output=True,
                timeout=10
            )
            logger.info(f"Windows Firewall rule added: block {ip}")
            return True
        except Exception as e:
            logger.error(f"Windows Firewall block error for {ip}: {e}")
            return False

    def _remove_iptables_block(self, ip: str) -> bool:
        if IS_WINDOWS:
            return self._remove_windows_firewall_block(ip)
        else:
            return self._remove_iptables_block_linux(ip)
    
    def _remove_iptables_block_linux(self, ip: str) -> bool:
        is_ipv6 = _is_ipv6(ip)
        iptables_cmd = "ip6tables" if is_ipv6 else "iptables"
        
        try:
            while True:
                result = subprocess.run(
                    [iptables_cmd, "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, timeout=5
                )
                if result.returncode != 0:
                    break
            logger.info(f"{iptables_cmd} rules removed for {ip}")
            return True
        except Exception as e:
            logger.error(f"Unblock error for {ip}: {e}")
            return False
    
    def _remove_windows_firewall_block(self, ip: str) -> bool:
        """Debloque une IP du Windows Firewall."""
        rule_name = f"IDS_BLOCK_{ip.replace('.', '_')}"
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={rule_name}"],
                capture_output=True,
                timeout=10
            )
            logger.info(f"Windows Firewall rule removed: {rule_name}")
            return True
        except Exception as e:
            logger.error(f"Windows Firewall unblock error for {ip}: {e}")
            return False

    def _check_expired_blocks(self):
        while self._running:
            now = datetime.now()
            with self._lock:
                for ip, info in list(self._blocked.items()):
                    if info.get("is_active") and info.get("block_until") and now >= info["block_until"]:
                        info["is_active"] = False
                        self._remove_iptables_block(ip)
                        logger.info(f"Auto-unblocked {ip} (expired)")
            time.sleep(10)

    def start(self):
        self._running = True
        self._unblock_thread = threading.Thread(target=self._check_expired_blocks, daemon=True)
        self._unblock_thread.start()
        logger.info("IP blocker started")

    def stop(self):
        self._running = False
        if self._unblock_thread:
            self._unblock_thread.join(timeout=5)
        logger.info("IP blocker stopped")

    def get_blocked_ips(self) -> list:
        with self._lock:
            return [info.copy() for info in self._blocked.values()]

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            info = self._blocked.get(ip)
            if info and info.get("is_active"):
                if info.get("block_until") and datetime.now() >= info["block_until"]:
                    info["is_active"] = False
                    return False
                return True
            return False
