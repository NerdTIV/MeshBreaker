import asyncio
import socket
import struct
import subprocess
from dataclasses import dataclass, field

from bleak import BleakScanner
from bleak.backends.device import BLEDevice

from src.utils import logger


@dataclass
class BTDevice:
    mac: str
    name: str
    rssi: int
    is_ble: bool
    manufacturer: str = None
    uuids: list[str] = field(default_factory=list)
    raw_adv: bytes = b""


class BLEScanner:
    def __init__(self, adapter: str = "hci0", timeout: float = 10.0):
        self.adapter = adapter
        self.timeout = timeout

    async def scan(self, passive: bool = False) -> list[BTDevice]:
        logger.info(f"BLE scan ({self.timeout}s, {'passive' if passive else 'active'})…")
        devices: list[BTDevice] = []

        def _cb(device: BLEDevice, adv):
            manufacturer = None
            if adv.manufacturer_data:
                first_key = next(iter(adv.manufacturer_data))
                manufacturer = f"0x{first_key:04X}"
            devices.append(BTDevice(
                mac=device.address,
                name=device.name or "<unknown>",
                rssi=adv.rssi,
                is_ble=True,
                manufacturer=manufacturer,
                uuids=list(adv.service_uuids or []),
                raw_adv=b"",
            ))

        try:
            scanner = BleakScanner(detection_callback=_cb,
                                   bluez={"adapter": self.adapter})
            await scanner.start()
            await asyncio.sleep(self.timeout)
            await scanner.stop()
        except Exception as e:
            if "No Bluetooth" in str(e) or "not available" in str(e).lower():
                raise RuntimeError("No Bluetooth adapter found. Plug in a USB dongle.") from e
            raise

        seen = {}
        for d in devices:
            seen[d.mac] = d
        return sorted(seen.values(), key=lambda x: x.rssi, reverse=True)


class ClassicScanner:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def scan(self) -> list[BTDevice]:
        logger.info(f"BT Classic scan ({self.timeout}s)…")
        devices: list[BTDevice] = []
        try:
            out = subprocess.check_output(
                ["hcitool", "scan", "--flush"],
                timeout=self.timeout + 5,
                stderr=subprocess.DEVNULL,
            ).decode()
            for line in out.strip().splitlines()[1:]:
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    mac  = parts[0].strip()
                    name = parts[1].strip() if len(parts) > 1 else "<unknown>"
                    devices.append(BTDevice(mac=mac, name=name, rssi=0, is_ble=False))
        except FileNotFoundError:
            logger.error("hcitool not found — install bluez")
        except subprocess.TimeoutExpired:
            pass
        except subprocess.CalledProcessError as e:
            logger.error(f"hcitool error: {logger.describe(e)}")
        return devices
