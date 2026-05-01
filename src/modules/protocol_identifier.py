import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.utils import logger

_SIG_DB_PATH = Path(__file__).parent.parent.parent / "data" / "mesh_signatures.json"


@dataclass
class ProtocolMatch:
    protocol_id:  str
    name:         str
    confidence:   int          # 0–100
    evidence:     list[str]    = field(default_factory=list)
    cve_tags:     list[str]    = field(default_factory=list)


class ProtocolIdentifier:
    def __init__(self):
        self._db = self._load_db()

    def from_devices(self, devices: list[dict]):
        results: dict[str, ProtocolMatch] = {}
        for dev in devices:
            self._score_device(dev, results)
        return self._ranked(results)

    def from_capture_file(self, path: str):
        data = json.loads(Path(path).read_text())
        results: dict[str, ProtocolMatch] = {}
        for beacon in data:
            dev = {
                "uuids":            [],
                "manufacturer_data": {beacon.get("ad_type"): bytes.fromhex(beacon.get("raw", ""))},
                "name":              beacon.get("name", ""),
                "service_data":      {},
            }
            self._score_device(dev, results)
        return self._ranked(results)

    def from_firmware(self, firmware_info: Any):
        strings = [s.lower() for s in getattr(firmware_info, "strings", [])]
        results: dict[str, ProtocolMatch] = {}

        for proto in self._db["protocols"]:
            pid = proto["id"]
            score = 0
            evidence: list[str] = []
            for pat in proto["indicators"].get("string_patterns", []):
                hits = [s for s in strings if pat in s]
                if hits:
                    score += 15
                    evidence.append(f"string '{pat}' in firmware")

            for url in getattr(firmware_info, "urls", []):
                for pat in proto["indicators"].get("string_patterns", []):
                    if pat in url.lower():
                        score += 20
                        evidence.append(f"URL match: {url}")

            if score > 0:
                m = results.setdefault(pid, ProtocolMatch(pid, proto["name"], 0,
                                                          cve_tags=proto.get("cve_tags", [])))
                m.confidence = min(100, m.confidence + score)
                m.evidence.extend(evidence)

        return self._ranked(results)

    def identify(self, devices: list[dict] | None = None,
                 capture_file: str | None = None,
                 firmware_info: Any = None):
        all_results: dict[str, ProtocolMatch] = {}

        def _merge(matches: list[ProtocolMatch]):
            for m in matches:
                existing = all_results.get(m.protocol_id)
                if existing:
                    existing.confidence = min(100, existing.confidence + m.confidence // 2)
                    existing.evidence.extend(m.evidence)
                else:
                    all_results[m.protocol_id] = m

        if devices:
            _merge(self.from_devices(devices))
        if capture_file:
            _merge(self.from_capture_file(capture_file))
        if firmware_info:
            _merge(self.from_firmware(firmware_info))

        matches = self._ranked(all_results)
        _print_matches(matches)
        return matches

    def _score_device(self, dev: dict, results: dict):
        uuids = [u.lower() for u in dev.get("uuids", [])]
        mfr   = dev.get("manufacturer_data", {})
        svc_data = dev.get("service_data", {})
        name  = (dev.get("name") or "").lower()

        for proto in self._db["protocols"]:
            pid = proto["id"]
            ind = proto["indicators"]
            score = 0
            evidence: list[str] = []

            for su in ind.get("service_uuids", []):
                su_n = su.lower().replace("0x", "")
                if any(su_n in u for u in uuids):
                    score += 35
                    evidence.append(f"service UUID {su}")
                if any(su_n in u for u in svc_data):
                    score += 35
                    evidence.append(f"service data UUID {su}")

            for cid_str in ind.get("company_ids", []):
                cid = int(cid_str, 16) if isinstance(cid_str, str) else cid_str
                if cid in mfr:
                    score += 40
                    evidence.append(f"company ID {cid:#06x}")

            for pat in ind.get("string_patterns", []):
                if pat in name:
                    score += 10
                    evidence.append(f"name match '{pat}'")

            if score > 0:
                m = results.setdefault(pid, ProtocolMatch(pid, proto["name"], 0,
                                                          cve_tags=proto.get("cve_tags", [])))
                m.confidence = min(100, m.confidence + score)
                m.evidence.extend(evidence)

    @staticmethod
    def _ranked(results: dict):
        return sorted(results.values(), key=lambda x: x.confidence, reverse=True)

    @staticmethod
    def _load_db():
        try:
            return json.loads(_SIG_DB_PATH.read_text())
        except Exception:
            logger.warning("mesh_signatures.json not found — using empty DB")
            return {"protocols": []}


def _print_matches(matches: list[ProtocolMatch]):
    from rich.table import Table
    from rich import box
    from rich.console import Console
    console = Console()

    if not matches:
        logger.warning("No protocol identified")
        return

    t = Table(title="Protocol Identification", box=box.ROUNDED, border_style="cyan")
    t.add_column("Protocol",   style="bold white", width=22)
    t.add_column("Confidence", style="bold cyan",  width=12)
    t.add_column("Evidence",   style="dim",        width=60)

    for m in matches:
        bar_len = m.confidence // 5
        bar = "[green]" + "█" * bar_len + "[/]" + "░" * (20 - bar_len)
        t.add_row(m.name, f"{bar} {m.confidence}%",
                  "; ".join(m.evidence[:3]))

    console.print(t)
