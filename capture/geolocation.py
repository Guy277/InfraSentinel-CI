import logging
import json
import time
import threading
import ipaddress
from urllib.request import urlopen, Request
from urllib.error import URLError

logger = logging.getLogger(__name__)


class GeoLocator:
    """Geolocalise les adresses IP via ip-api.com (gratuit, sans cle API).
    Supporte le batch (jusqu'a 100 IPs par requete) et le cache."""

    API_URL = "http://ip-api.com/batch"
    SINGLE_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query"
    FIELDS = "status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query"
    CACHE_TTL = 3600  # 1 heure
    RATE_LIMIT_DELAY = 1.0  # ip-api: 45 req/min en gratuit
    BATCH_SIZE = 100

    def __init__(self):
        self._cache = {}  # ip -> {data, timestamp}
        self._lock = threading.Lock()
        self._last_request_time = 0
        self._stats = {
            "total_lookups": 0,
            "cache_hits": 0,
            "api_calls": 0,
            "failures": 0,
        }

    def lookup(self, ip: str, allow_network: bool = True) -> dict:
        """Geolocalise une seule IP. Retourne les donnees geo ou un dict vide."""
        if not ip or self._is_private(ip):
            return self._make_empty_result(ip)

        with self._lock:
            cached = self._cache.get(ip)
            if cached and (time.time() - cached["timestamp"]) < self.CACHE_TTL:
                self._stats["cache_hits"] += 1
                return cached["data"]

        if not allow_network:
            return self._make_empty_result(ip)

        self._stats["total_lookups"] += 1
        data = self._fetch_single(ip)

        with self._lock:
            self._cache[ip] = {"data": data, "timestamp": time.time()}

        return data

    def lookup_batch(self, ips: list, allow_network: bool = True) -> dict:
        """Geolocalise un lot d'IPs. Retourne {ip: geo_data}."""
        result = {}
        to_fetch = []

        with self._lock:
            for ip in ips:
                if not ip or self._is_private(ip):
                    result[ip] = self._make_empty_result(ip)
                    continue
                cached = self._cache.get(ip)
                if cached and (time.time() - cached["timestamp"]) < self.CACHE_TTL:
                    self._stats["cache_hits"] += 1
                    result[ip] = cached["data"]
                else:
                    if allow_network:
                        to_fetch.append(ip)
                    else:
                        result[ip] = self._make_empty_result(ip)

        if not to_fetch:
            return result

        self._stats["total_lookups"] += len(to_fetch)

        for i in range(0, len(to_fetch), self.BATCH_SIZE):
            batch = to_fetch[i:i + self.BATCH_SIZE]
            fetched = self._fetch_batch(batch)
            with self._lock:
                for ip, data in fetched.items():
                    self._cache[ip] = {"data": data, "timestamp": time.time()}
            result.update(fetched)

        return result

    def get_stats(self) -> dict:
        return dict(self._stats)

    def _fetch_single(self, ip: str) -> dict:
        """Appel API pour une seule IP."""
        self._wait_rate_limit()
        url = self.SINGLE_API_URL.format(ip=ip)
        try:
            req = Request(url, headers={"User-Agent": "IDS-IPS-GeoLocator/1.0"})
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                self._stats["api_calls"] += 1
                if data.get("status") == "success":
                    return self._normalize(data, ip)
                else:
                    logger.warning(f"Geo lookup failed for {ip}: {data.get('message')}")
                    return self._make_empty_result(ip)
        except (URLError, json.JSONDecodeError, Exception) as e:
            self._stats["failures"] += 1
            logger.error(f"Geo lookup error for {ip}: {e}")
            return self._make_empty_result(ip)

    def _fetch_batch(self, ips: list) -> dict:
        """Appel API batch pour plusieurs IPs."""
        self._wait_rate_limit()
        result = {}
        try:
            body = json.dumps(ips).encode()
            req = Request(
                self.API_URL,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "IDS-IPS-GeoLocator/1.0",
                },
                method="POST",
            )
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                self._stats["api_calls"] += 1
                for entry in data:
                    ip = entry.get("query", "")
                    if entry.get("status") == "success":
                        result[ip] = self._normalize(entry, ip)
                    else:
                        result[ip] = self._make_empty_result(ip)
        except (URLError, json.JSONDecodeError, Exception) as e:
            self._stats["failures"] += 1
            logger.error(f"Batch geo lookup error: {e}")
            for ip in ips:
                if ip not in result:
                    result[ip] = self._make_empty_result(ip)
        return result

    def _wait_rate_limit(self):
        """Respecte la limite de debit ip-api.com."""
        with self._lock:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.RATE_LIMIT_DELAY:
                time.sleep(self.RATE_LIMIT_DELAY - elapsed)
            self._last_request_time = time.time()

    @staticmethod
    def _normalize(data: dict, ip: str) -> dict:
        country_code = data.get("countryCode", "")
        return {
            "ip": ip,
            "country": data.get("country", ""),
            "country_code": country_code,
            "continent": GeoLocator.get_continent(country_code),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "timezone": data.get("timezone", ""),
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
            "as": data.get("as", ""),
        }

    @staticmethod
    def _make_empty_result(ip: str) -> dict:
        return {
            "ip": ip or "",
            "country": "",
            "country_code": "",
            "continent": "Inconnu",
            "region": "",
            "city": "",
            "lat": None,
            "lon": None,
            "timezone": "",
            "isp": "",
            "org": "",
            "as": "",
        }

    COUNTRY_TO_CONTINENT = {
        # Afrique
        "DZ": "Afrique", "AO": "Afrique", "BJ": "Afrique", "BW": "Afrique", "BF": "Afrique",
        "BI": "Afrique", "CM": "Afrique", "CV": "Afrique", "CF": "Afrique", "TD": "Afrique",
        "KM": "Afrique", "CG": "Afrique", "CD": "Afrique", "CI": "Afrique", "DJ": "Afrique",
        "EG": "Afrique", "GQ": "Afrique", "ER": "Afrique", "SZ": "Afrique", "ET": "Afrique",
        "GA": "Afrique", "GM": "Afrique", "GH": "Afrique", "GN": "Afrique", "GW": "Afrique",
        "KE": "Afrique", "LS": "Afrique", "LR": "Afrique", "LY": "Afrique", "MG": "Afrique",
        "MW": "Afrique", "ML": "Afrique", "MR": "Afrique", "MU": "Afrique", "MA": "Afrique",
        "MZ": "Afrique", "NA": "Afrique", "NE": "Afrique", "NG": "Afrique", "RW": "Afrique",
        "ST": "Afrique", "SN": "Afrique", "SC": "Afrique", "SL": "Afrique", "SO": "Afrique",
        "ZA": "Afrique", "SS": "Afrique", "SD": "Afrique", "TZ": "Afrique", "TG": "Afrique",
        "TN": "Afrique", "UG": "Afrique", "ZM": "Afrique", "ZW": "Afrique",
        # Amérique du Nord
        "CA": "Amérique du Nord", "US": "Amérique du Nord", "MX": "Amérique du Nord",
        "GT": "Amérique du Nord", "BZ": "Amérique du Nord", "HN": "Amérique du Nord",
        "SV": "Amérique du Nord", "NI": "Amérique du Nord", "CR": "Amérique du Nord",
        "PA": "Amérique du Nord", "CU": "Amérique du Nord", "JM": "Amérique du Nord",
        "HT": "Amérique du Nord", "DO": "Amérique du Nord", "TT": "Amérique du Nord",
        "BS": "Amérique du Nord", "BB": "Amérique du Nord",
        # Amérique du Sud
        "AR": "Amérique du Sud", "BO": "Amérique du Sud", "BR": "Amérique du Sud",
        "CL": "Amérique du Sud", "CO": "Amérique du Sud", "EC": "Amérique du Sud",
        "GY": "Amérique du Sud", "PY": "Amérique du Sud", "PE": "Amérique du Sud",
        "SR": "Amérique du Sur", "UY": "Amérique du Sud", "VE": "Amérique du Sud",
        # Asie
        "AF": "Asie", "AM": "Asie", "AZ": "Asie", "BH": "Asie", "BD": "Asie",
        "BT": "Asie", "BN": "Asie", "KH": "Asie", "CN": "Asie", "CY": "Asie",
        "GE": "Asie", "IN": "Asie", "ID": "Asie", "IR": "Asie", "IQ": "Asie",
        "IL": "Asie", "JP": "Asie", "JO": "Asie", "KZ": "Asie", "KW": "Asie",
        "KG": "Asie", "LA": "Asie", "LB": "Asie", "MY": "Asie", "MV": "Asie",
        "MN": "Asie", "MM": "Asie", "NP": "Asie", "KP": "Asie", "OM": "Asie",
        "PK": "Asie", "PH": "Asie", "QA": "Asie", "SA": "Asie", "SG": "Asie",
        "KR": "Asie", "LK": "Asie", "SY": "Asie", "TW": "Asie", "TJ": "Asie",
        "TH": "Asie", "TL": "Asie", "TM": "Asie", "AE": "Asie", "UZ": "Asie",
        "VN": "Asie", "YE": "Asie",
        # Europe
        "AL": "Europe", "AD": "Europe", "AT": "Europe", "BY": "Europe", "BE": "Europe",
        "BA": "Europe", "BG": "Europe", "HR": "Europe", "CZ": "Europe", "DK": "Europe",
        "EE": "Europe", "FI": "Europe", "FR": "Europe", "DE": "Europe", "GR": "Europe",
        "HU": "Europe", "IS": "Europe", "IE": "Europe", "IT": "Europe", "LV": "Europe",
        "LI": "Europe", "LT": "Europe", "LU": "Europe", "MT": "Europe", "MD": "Europe",
        "MC": "Europe", "ME": "Europe", "NL": "Europe", "MK": "Europe", "NO": "Europe",
        "PL": "Europe", "PT": "Europe", "RO": "Europe", "RU": "Europe", "RS": "Europe",
        "SK": "Europe", "SI": "Europe", "ES": "Europe", "SE": "Europe", "CH": "Europe",
        "TR": "Europe", "UA": "Europe", "GB": "Europe", "VA": "Europe",
        # Océanie
        "AU": "Océanie", "FJ": "Océanie", "KI": "Océanie", "MH": "Océanie",
        "FM": "Océanie", "NR": "Océanie", "NZ": "Océanie", "PW": "Océanie",
        "PG": "Océanie", "WS": "Océanie", "SB": "Océanie", "TO": "Océanie",
        "TV": "Océanie", "VU": "Océanie",
    }

    @classmethod
    def get_continent(cls, country_code: str) -> str:
        """Retourne le continent a partir du code pays."""
        return cls.COUNTRY_TO_CONTINENT.get(country_code, "Inconnu")

    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_reserved
        except ValueError:
            return True

    def get_cached(self, ip: str) -> dict:
        """Retourne les donnees en cache pour une IP, sans appel API."""
        with self._lock:
            cached = self._cache.get(ip)
            if cached:
                return cached["data"]
        return self._make_empty_result(ip)

    def get_all_cached(self) -> dict:
        """Retourne toutes les donnees en cache."""
        with self._lock:
            return {
                ip: entry["data"]
                for ip, entry in self._cache.items()
                if entry["data"].get("lat") is not None
            }

    def get_stats(self) -> dict:
        return dict(self._stats)
