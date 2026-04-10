import os
import re
import time
import threading
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

SYSLOG_PATHS = [
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/kern.log",
]

SUSPICIOUS_PATTERNS = [
    re.compile(r"Failed password for .* from (\S+)"),
    re.compile(r"Invalid user .* from (\S+)"),
    re.compile(r"Connection closed by authenticating user .* (\S+)"),
    re.compile(r"refused connect from (\S+)"),
    re.compile(r"segfault at"),
    re.compile(r"Out of memory"),
    re.compile(r"iptables.*DROP.*SRC=(\S+)"),
    re.compile(r"iptables.*REJECT.*SRC=(\S+)"),
    re.compile(r"pam_unix.*authentication failure.*rhost=(\S+)"),
    re.compile(r"sshd.*Failed.*from (\S+)"),
]


class LogEntry:
    __slots__ = ("source", "timestamp", "message", "severity", "ip_address", "raw_line")

    def __init__(self, source, timestamp, message, severity="info", ip_address=None, raw_line=None):
        self.source = source
        self.timestamp = timestamp
        self.message = message
        self.severity = severity
        self.ip_address = ip_address
        self.raw_line = raw_line

    def to_dict(self):
        return {
            "source": self.source,
            "timestamp": self.timestamp,
            "message": self.message,
            "severity": self.severity,
            "ip_address": self.ip_address,
        }


class LogCollector:
    def __init__(self, log_paths=None):
        self.log_paths = log_paths or self._find_available_logs()
        self._running = False
        self._threads = []
        self._callbacks = []
        self._file_positions = {}
        self._entries = []
        self._lock = threading.Lock()
        self._max_entries = 10000

    def _find_available_logs(self):
        available = []
        for path in SYSLOG_PATHS:
            if os.path.isfile(path) and os.access(path, os.R_OK):
                available.append(path)
        if not available:
            logger.warning("No system log files found or accessible")
        return available

    def add_callback(self, callback):
        self._callbacks.append(callback)

    def _parse_line(self, line, source):
        line = line.strip()
        if not line:
            return None

        ip_address = None
        severity = "info"

        for pattern in SUSPICIOUS_PATTERNS:
            match = pattern.search(line)
            if match:
                severity = "warning"
                if match.lastindex and match.group(1):
                    potential_ip = match.group(1)
                    if re.match(r"\d+\.\d+\.\d+\.\d+", potential_ip):
                        ip_address = potential_ip
                if any(kw in line.lower() for kw in ["failed", "invalid", "refused", "error"]):
                    severity = "error"
                break

        return LogEntry(
            source=source,
            timestamp=time.time(),
            message=line[:1000],
            severity=severity,
            ip_address=ip_address,
            raw_line=line,
        )

    def _tail_file(self, filepath):
        try:
            with open(filepath, "r", errors="replace") as f:
                f.seek(0, 2)
                self._file_positions[filepath] = f.tell()

                while self._running:
                    current_size = os.path.getsize(filepath)
                    if current_size < self._file_positions.get(filepath, 0):
                        self._file_positions[filepath] = 0

                    f.seek(self._file_positions[filepath])
                    line = f.readline()

                    if line:
                        self._file_positions[filepath] = f.tell()
                        entry = self._parse_line(line, filepath)
                        if entry:
                            with self._lock:
                                self._entries.append(entry)
                                if len(self._entries) > self._max_entries:
                                    self._entries = self._entries[-self._max_entries:]
                            for callback in self._callbacks:
                                try:
                                    callback(entry)
                                except Exception as e:
                                    logger.error(f"Log callback error: {e}")
                    else:
                        time.sleep(0.5)

        except Exception as e:
            logger.error(f"Error tailing {filepath}: {e}")

    def start(self):
        if self._running:
            return
        self._running = True

        for path in self.log_paths:
            t = threading.Thread(target=self._tail_file, args=(path,), daemon=True)
            t.start()
            self._threads.append(t)

        logger.info(f"Log collector started, monitoring {len(self.log_paths)} files")

    def stop(self):
        self._running = False
        for t in self._threads:
            t.join(timeout=5)
        self._threads.clear()
        logger.info("Log collector stopped")

    def get_recent_entries(self, count=100, severity=None, ip=None):
        with self._lock:
            entries = self._entries
            if severity:
                entries = [e for e in entries if e.severity == severity]
            if ip:
                entries = [e for e in entries if e.ip_address == ip]
            return [e.to_dict() for e in entries[-count:]]

    def get_stats(self):
        with self._lock:
            total = len(self._entries)
            by_severity = {}
            for e in self._entries:
                by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
            return {
                "total_entries": total,
                "by_severity": by_severity,
                "monitored_files": len(self.log_paths),
                "running": self._running,
            }
