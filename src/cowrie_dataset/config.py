"""
Config management for the cowrie-dataset pipeline.

We use environment variables (loaded from .env) so you can easily switch
between local dev and production without changing code. The Settings class
validates and provides typed access to all config values.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv


# Load .env file if it exists (won't override existing env vars)
load_dotenv()


@dataclass
class Settings:
    """
    All the config knobs for the pipeline in one place.
    
    Instantiate this once at startup and pass it around. Makes testing
    easier too since you can just create a Settings with custom values.
    """
    
    # Elasticsearch connection
    es_host: str = field(default_factory=lambda: os.getenv("ES_HOST", "http://localhost:9200"))
    es_user: Optional[str] = field(default_factory=lambda: os.getenv("ES_USER") or None)
    es_password: Optional[str] = field(default_factory=lambda: os.getenv("ES_PASSWORD") or None)
    es_index_prefix: str = field(default_factory=lambda: os.getenv("ES_INDEX_PREFIX", "cowrie-sessions"))
    
    # Data paths
    honeypot_data_dir: Path = field(
        default_factory=lambda: Path(os.getenv("HONEYPOT_DATA_DIR", "/opt/honeypot"))
    )
    geolite_db_path: Optional[Path] = field(
        default_factory=lambda: Path(os.getenv("GEOLITE_DB_PATH")) if os.getenv("GEOLITE_DB_PATH") else None
    )
    
    # Processing settings
    bulk_size: int = field(default_factory=lambda: int(os.getenv("BULK_SIZE", "500")))
    locations: list[str] = field(default_factory=lambda: _parse_locations())
    
    def get_location_path(self, location: str) -> Path:
        """Get the full path for a specific honeypot location's data directory."""
        return self.honeypot_data_dir / location
    
    def get_index_name(self, suffix: str = "") -> str:
        """
        Generate an ES index name. We use a single index for MVP,
        but this could be extended for time-based indices later.
        """
        if suffix:
            return f"{self.es_index_prefix}-{suffix}"
        return self.es_index_prefix
    
    def __post_init__(self):
        """Validate settings after initialization."""
        # Make sure honeypot_data_dir is a Path object
        if isinstance(self.honeypot_data_dir, str):
            self.honeypot_data_dir = Path(self.honeypot_data_dir)
        
        # Same for geolite path
        if isinstance(self.geolite_db_path, str):
            self.geolite_db_path = Path(self.geolite_db_path)


def _parse_locations() -> list[str]:
    """
    Parse the LOCATIONS env var into a list of location names.
    Returns default list if not set or set to 'all'.
    """
    locations_str = os.getenv("LOCATIONS", "all")
    
    if locations_str.lower() == "all":
        # These are the known locations from the honeypot setup
        return [
            "ssh-amsterdam",
            "ssh-bangalore", 
            "ssh-london",
            "ssh-ny",
            "ssh-singapore",
            "ssh-toronto"
        ]
    
    # Split by comma and strip whitespace
    return [loc.strip() for loc in locations_str.split(",") if loc.strip()]


# Global settings instance for convenience
# You can import this directly or create your own Settings instance
settings = Settings()
