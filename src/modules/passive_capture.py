import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
    BLEAK_OK = True
except ImportError:
    BLEAK_OK = False

from src.utils import logger


@dataclass
class CapturedBeacon:
    timestamp: float
    mac:       str
    name:      str
    rssi:      int
    ad_type:   int | None
    raw_ad:    bytes
    mesh_hint: str | None   # sig_mesh | wirepas | thread | custom | None


@dataclass
class CaptureSession:
    beacons:      list[CapturedBeacon] = field(default_factory=list)
    pcap_file:    str | None = None
    duration:     float = 0.0
    device_count: int = 0


_MESH_AD_TYPES = {0x2A: "sig_mesh", 0x2B: "sig_mesh", 0x29: "sig_mesh"}
_COMPANY_WIREPAS = 0x0077


def _detect_mesh(adv: "AdvertisementData"):
    raw = adv.manufacturer_data or {}

    # SIG Mesh: AD type 0x2A/0x2B/0x29 in service_data or raw
    for uuid in adv.service_data:
        uid = uuid.lower().replace("-", "")
        if "1827" in uid or "1828" in uid:
            return "sig_mesh"

    # Wirepas: company ID 0x0077
    if _COMPANY_WIREPAS in raw:
        return "wirepas"

    # Thread: UUID FFFB
    for uuid in (adv.service_uuids or []):
        if "fffb" in uuid.lower():
            return "thread"

    return None


class PassiveCapture:
    def __init__(self, adapter: str = "hci0", output_dir: str = "./output"):
        self.adapter    = adapter
        self.output_dir = Path(output_dir)
        self._session   = CaptureSession()
        self._seen: dict[str, int] = {}
        self._cbs: list[Callable[[CapturedBeacon], None]] = []

    def on_beacon(self, cb: Callable[[CapturedBeacon], None]):
        self._cbs.append(cb)

    async def capture(self, duration: float = 30.0, save_json: bool = True):
        if not BLEAK_OK:
            logger.error("bleak not installed — cannot capture BLE packets")
            return self._session

        self._session = CaptureSession()
        start = time.time()

        def _callback(device: "BLEDevice", adv: "AdvertisementData"):
            mesh_hint = _detect_mesh(adv)
            raw_bytes = b""
            for k, v in (adv.manufacturer_data or {}).items():
                raw_bytes = bytes([k & 0xFF, k >> 8]) + v
                break

            b = CapturedBeacon(
                timestamp  = time.time() - start,
                mac        = device.address,
                name       = device.name or "",
                rssi       = adv.rssi,
                ad_type    = 0xFF if raw_bytes else None,
                raw_ad     = raw_bytes,
                mesh_hint  = mesh_hint,
            )
            self._session.beacons.append(b)

            if device.address not in self._seen:
                self._seen[device.address] = 0
                hint_str = f" [bold yellow][{mesh_hint}][/]" if mesh_hint else ""
                logger.info(f"  {device.address}  {device.name or '(unknown)':20}  RSSI={adv.rssi}{hint_str}")

            self._seen[device.address] += 1
            for cb in self._cbs:
                cb(b)

        logger.info(f"Passive BLE capture — {duration}s on {self.adapter}")
        async with BleakScanner(detection_callback=_callback, adapter=self.adapter):
            await asyncio.sleep(duration)

        self._session.duration     = time.time() - start
        self._session.device_count = len(self._seen)

        if save_json:
            self._session.pcap_file = self._save(self._session)

        _print_summary(self._session)
        return self._session

    def _save(self, session: CaptureSession):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        ts = int(time.time())
        dest = self.output_dir / f"capture_{ts}.json"
        data = [
            {
                "t": b.timestamp, "mac": b.mac, "name": b.name,
                "rssi": b.rssi, "ad_type": b.ad_type,
                "raw": b.raw_ad.hex(), "mesh": b.mesh_hint,
            }
            for b in session.beacons
        ]
        with open(dest, "w") as f:
            json.dump(data, f, indent=2)
        logger.success(f"Capture saved → {dest}")
        return str(dest)


def _print_summary(session: CaptureSession):
    from rich.table import Table
    from rich import box
    from rich.console import Console
    from collections import Counter

    console = Console()
    mesh_counts = Counter(b.mesh_hint for b in session.beacons if b.mesh_hint)
    total = len(session.beacons)

    t = Table(title="Capture Summary", box=box.ROUNDED, border_style="cyan")
    t.add_column("Metric", style="bold white")
    t.add_column("Value",  style="cyan")
    t.add_row("Duration",       f"{session.duration:.1f}s")
    t.add_row("Total beacons",  str(total))
    t.add_row("Unique devices", str(session.device_count))
    for proto, cnt in mesh_counts.most_common():
        t.add_row(f"  [{proto}]", str(cnt))
    console.print(t)
