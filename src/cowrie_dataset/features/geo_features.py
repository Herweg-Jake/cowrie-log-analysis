"""
Geography-based feature extraction (F47-F52).

These features capture the attacker's location based on their IP address.
We use MaxMind's GeoLite2 database for IP geolocation. The paper uses:
  - Continent code
  - Country name
  - Region name
  - City name
  - Latitude/Longitude

Geographic features can be useful because:
  - Attack patterns vary by region
  - Some regions have more compromised hosts (botnets)
  - Geo-impossible logins are suspicious (user in US, login from Russia)

For the MVP, if GeoLite2 isn't available, we just return empty geo data.
The pipeline will still work, just without geo features.
"""

import logging
from typing import Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# Try to import geoip2 - it's optional
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    logger.warning("geoip2 not installed - geographic features will be empty")


class GeoEnricher:
    """
    Enriches IP addresses with geographic information using GeoLite2.
    
    Usage:
        enricher = GeoEnricher("/path/to/GeoLite2-City.mmdb")
        geo_data = enricher.lookup("1.2.3.4")
        # geo_data = {"continent_code": "AS", "country_name": "China", ...}
    
    If the database isn't available or the IP can't be found, returns
    empty geo data (all fields are empty strings or 0).
    
    Note: You need to download the GeoLite2-City database from MaxMind.
    It's free but requires registration: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
    """
    
    def __init__(self, db_path: Optional[Path | str] = None):
        """
        Args:
            db_path: Path to GeoLite2-City.mmdb file. If None or the file
                    doesn't exist, geo lookups will return empty data.
        """
        self._reader = None
        self._db_path = db_path
        
        if not GEOIP2_AVAILABLE:
            logger.warning("geoip2 library not available")
            return
        
        if db_path is None:
            logger.info("No GeoLite2 database path provided - geo features disabled")
            return
        
        db_path = Path(db_path)
        if not db_path.exists():
            logger.warning(f"GeoLite2 database not found at {db_path}")
            return
        
        try:
            self._reader = geoip2.database.Reader(str(db_path))
            logger.info(f"Loaded GeoLite2 database from {db_path}")
        except Exception as e:
            logger.error(f"Failed to load GeoLite2 database: {e}")
    
    def lookup(self, ip: str) -> dict[str, Any]:
        """
        Look up geographic info for an IP address.
        
        Returns a dict with F47-F52 features. If the lookup fails for
        any reason, returns empty/zero values.
        """
        empty_result = _empty_geo_features()
        
        if self._reader is None:
            return empty_result
        
        # Skip private/reserved IPs
        if _is_private_ip(ip):
            return empty_result
        
        try:
            response = self._reader.city(ip)
            
            return {
                "F47_continent_code": response.continent.code or "",
                "F48_country_name": response.country.name or "",
                "F48_country_iso": response.country.iso_code or "",
                "F49_region_name": response.subdivisions.most_specific.name if response.subdivisions else "",
                "F50_city_name": response.city.name or "",
                "F51_longitude": response.location.longitude or 0.0,
                "F52_latitude": response.location.latitude or 0.0,
                
                # Extra geo features
                "extra_timezone": response.location.time_zone or "",
                "extra_accuracy_radius": response.location.accuracy_radius or 0,
            }
            
        except geoip2.errors.AddressNotFoundError:
            # IP not in database - common for private ranges, new allocations
            return empty_result
        except Exception as e:
            logger.debug(f"Geo lookup failed for {ip}: {e}")
            return empty_result
    
    def close(self):
        """Close the database reader."""
        if self._reader:
            self._reader.close()
            self._reader = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def extract_geo_features(session, enricher: Optional[GeoEnricher] = None) -> dict[str, Any]:
    """
    Extract geographic features for a session's source IP.
    
    Args:
        session: The Session object
        enricher: Optional GeoEnricher instance. If None, returns empty features.
    
    Returns dict with F47-F52 features plus extras.
    """
    if enricher is None:
        return _empty_geo_features()
    
    return enricher.lookup(session.src_ip)


def _empty_geo_features() -> dict[str, Any]:
    """Return empty geo features when lookup isn't possible."""
    return {
        "F47_continent_code": "",
        "F48_country_name": "",
        "F48_country_iso": "",
        "F49_region_name": "",
        "F50_city_name": "",
        "F51_longitude": 0.0,
        "F52_latitude": 0.0,
        "extra_timezone": "",
        "extra_accuracy_radius": 0,
    }


def _is_private_ip(ip: str) -> bool:
    """
    Check if an IP is in a private/reserved range.
    
    These won't be in GeoLite2 and aren't useful for geo analysis anyway.
    """
    # Quick and dirty check - could use ipaddress module for accuracy
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        # 172.16.0.0 - 172.31.255.255
        try:
            second_octet = int(ip.split(".")[1])
            if 16 <= second_octet <= 31:
                return True
        except (IndexError, ValueError):
            pass
    if ip.startswith("127.") or ip.startswith("0."):
        return True
    return False
