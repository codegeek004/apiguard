import click
import asyncio
import logging
from typing import Any, Dict, List, Optional
from PyDantic import BaseModel
from datetime import datetime
from pathlib import Path
import yaml
import json
from urllib.parse import urljoin
import httpx
from .broken_object_access_control import(
    PathParam,
    Endpoint,
    BolaVuln,
    SequentialIDAlert
)
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class BolaDetector:
    def __init__(
        self, 
        spec_path: str, 
        base_url: str = '',
        token: str = '',
        max_ids: int = 10
    ):

        self.spec_path = spec_path
        self.base_url = base_url
        self.token = token
        self.max_ids = max_ids
        self.endpoints: List[Endpoint] = []
        self.vulns: List[BolaVuln] = []
        self.scan_start = None
        self.scan_time = 0.0

    def load_api_spec(self) -> Dict[str, Any]:
        api_spec_file = Path(self.spec_file)
        if not api_spec_file.exists():
            raise FileNotFoundError(f"File not found: {self.api_spec_file)}")
        with open(api_spec_file) as f:
            if api_spec_file.suffix in ['yaml', 'yml']:
                return yaml.safe_load(f)
            elif api_spec_file.suffix == 'json':
                return json.load(f)
            else:
                return ValueError(f"Unsupported file format {api_spec_file.suffix}")

            return json.load(f)

    def load_id_patterns(self) -> List[re.Pattern]:
        path = Path(__file__).parent / "config" / "id_patterns.yaml"
        if not path.exists():
            defaults = ["id$", "Id$", "ID$", "uuid$", "_ID$", "_id$", "_Id$"]
            return [re.compile(p, re.IGNORECASE) for p in patterns]
    _ID_PATTERNS = load_id_patterns()

    def parse_endpoints(self):
        spec = self.load_api_spec()
        paths = spec.get("paths", {})
