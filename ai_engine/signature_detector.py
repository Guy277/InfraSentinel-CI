import re
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class SignatureRule:
    def __init__(self, sid: int, msg: str, pattern: str, 
                 proto: str = "tcp", action: str = "alert",
                 source: str = "any", sport: str = "any",
                 dest: str = "any", dport: str = "any",
                 threshold: int = None, reference: str = None):
        self.sid = sid
        self.msg = msg
        self.pattern = pattern
        self.proto = proto.lower()
        self.action = action
        self.source = source
        self.sport = sport
        self.dest = dest
        self.dport = dport
        self.threshold = threshold
        self.reference = reference
        self._regex = self._build_regex()
        self._compiled = re.compile(self._regex) if self._regex else None

    def _build_regex(self) -> Optional[str]:
        if not self.pattern:
            return None
        pattern = self.pattern.replace("|", "\\|")
        if content_match := re.search(r'content:"([^"]+)"', self.pattern):
            pattern = content_match.group(1)
        escaped = pattern.replace(".", r"\.").replace("*", r".*").replace("?", ".")
        return escaped

    def match(self, payload: bytes) -> bool:
        if not self._compiled or not payload:
            return False
        try:
            return bool(self._compiled.search(payload))
        except re.error:
            return False

    def __repr__(self):
        return f"<SignatureRule sid={self.sid} msg={self.msg}>"


class SignatureDetector:
    def __init__(self):
        self._signatures = {}
        self._by_proto = {"tcp": [], "udp": [], "icmp": [], "any": []}
        self._stats = {"matches": 0, "checks": 0}

    def load_from_file(self, filepath: str) -> int:
        """Charge les règles depuis un fichier Snort/Suricata."""
        loaded = 0
        try:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    rule = self._parse_rule(line)
                    if rule:
                        self.add_signature(rule)
                        loaded += 1
            logger.info(f"Loaded {loaded} signatures from {filepath}")
        except FileNotFoundError:
            logger.warning(f"Rules file not found: {filepath}")
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
        return loaded

    def load_from_directory(self, dirpath: str) -> int:
        """Charge toutes les règles depuis un répertoire."""
        total = 0
        path = Path(dirpath)
        if not path.exists():
            return 0
        for f in path.glob("*.rules"):
            total += self.load_from_file(str(f))
        for f in path.glob("*.conf"):
            total += self.load_from_file(str(f))
        logger.info(f"Total signatures loaded: {total}")
        return total

    def _parse_rule(self, line: str) -> Optional[SignatureRule]:
        try:
            parts = line.split("(")
            if len(parts) < 2:
                return None
            
            header = parts[0].strip().split()
            if len(header) < 4:
                return None
            
            action = header[0]
            proto = header[1]
            source = header[2] if len(header) > 2 else "any"
            dest = header[4] if len(header) > 4 else "any"

            options = parts[1].rstrip(")").split(";")
            msg, pattern, sid, reference = None, None, 0, None
            
            for opt in options:
                opt = opt.strip()
                if opt.startswith("msg:"):
                    msg = opt.split(":", 1)[1].strip('"')
                elif opt.startswith("content:"):
                    pattern = opt.split(":", 1)[1].strip('"')
                elif opt.startswith("sid:"):
                    sid = int(opt.split(":", 1)[1].strip(";"))
                elif opt.startswith("reference:"):
                    reference = opt.split(":", 1)[1].strip(";")
            
            if not sid or not pattern:
                return None
            
            return SignatureRule(sid, msg, pattern, proto, action, 
                            source, dest, reference=reference)
        except Exception as e:
            logger.debug(f"Parse error: {e}")
            return None

    def add_signature(self, rule: SignatureRule):
        self._signatures[rule.sid] = rule
        if rule.proto in self._by_proto:
            self._by_proto[rule.proto].append(rule)
        else:
            self._by_proto["any"].append(rule)

    def detect(self, payload: bytes, proto: str = "tcp") -> Optional[SignatureRule]:
        """Vérifie si le payload correspond à une signature."""
        if not payload or not self._signatures:
            return None
        
        self._stats["checks"] += 1
        
        for rule in self._by_proto.get(proto, []) + self._by_proto.get("any", []):
            if rule.match(payload):
                self._stats["matches"] += 1
                return rule
        
        return None

    def get_signature(self, sid: int) -> Optional[SignatureRule]:
        return self._signatures.get(sid)

    def count(self) -> int:
        return len(self._signatures)

    def get_stats(self) -> dict:
        return dict(self._stats)


_signature_detector = SignatureDetector()


def get_signature_detector() -> SignatureDetector:
    return _signature_detector