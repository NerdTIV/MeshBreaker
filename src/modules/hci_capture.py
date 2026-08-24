"""
Raw AD capture through the Linux HCI monitor socket.

The problem this exists to solve: BlueZ decides what an application is allowed
to see. Through bleak you get names, service UUIDs, service data and
manufacturer data — and nothing else. Mesh traffic lives in AD types BlueZ
does not surface at all:

    0x29  PB-ADV        provisioning
    0x2A  Mesh Message  network PDUs
    0x2B  Mesh Beacon   secure network / unprovisioned device beacons

So a capture taken with bleak can never contain provisioning traffic, however
much of it is in the air. That is not a missing feature in bleak, it is where
the BlueZ D-Bus API draws the line.

The way around it without buying hardware is the monitor socket — the same
interface `btmon` uses. It hands over every HCI packet BlueZ sees, including
the complete advertising payload, so we can parse the AD structures ourselves
and recover the mesh types.

    +--------------+        +---------+        +------------------+
    |  BLE adverts | -----> |  BlueZ  | -----> | D-Bus -> bleak   |  filtered
    +--------------+        +----+----+        +------------------+
                                 |
                                 +----------->  HCI monitor socket    complete

Requirements and honest limits:

    - **Linux only.** This is a Linux kernel interface; there is no Windows or
      macOS equivalent. On Windows use an nRF52840 with Sniffle.
    - **Root, or CAP_NET_RAW.** Opening the monitor socket is privileged.
    - **Something has to be scanning.** The monitor is passive: it shows you
      what the adapter already receives. We drive a scan ourselves so you do
      not have to run one in another terminal.
    - It sees what the *adapter* receives, so it is still one radio hopping
      the three advertising channels. It does not give you channel selection
      or connection following — for that you still want a real sniffer.

Reference: Linux `include/net/bluetooth/hci_sock.h`, and the btsnoop/monitor
header format in `monitor/` of bluez.
"""

import asyncio
import json
import socket
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path

from src.utils import logger
from src.utils.capture_io import AD_TYPE_NAMES, MESH_AD_TYPES

AF_BLUETOOTH = 31
BTPROTO_HCI = 1
HCI_CHANNEL_MONITOR = 2

MON_NEW_INDEX = 0
MON_DEL_INDEX = 1
MON_COMMAND_PKT = 2
MON_EVENT_PKT = 3

HCI_EV_LE_META = 0x3E
LE_ADVERTISING_REPORT = 0x02
LE_EXT_ADVERTISING_REPORT = 0x0D


@dataclass
class ADStructure:
    """One AD structure out of an advertising payload."""

    ad_type: int
    data: bytes

    @property
    def name(self) -> str:
        return AD_TYPE_NAMES.get(self.ad_type, f"Unknown 0x{self.ad_type:02X}")

    @property
    def is_mesh(self) -> bool:
        return self.ad_type in MESH_AD_TYPES


@dataclass
class HCICaptureSession:
    frames: list[dict] = field(default_factory=list)
    duration: float = 0.0
    ad_types: dict[int, int] = field(default_factory=dict)
    output_file: str | None = None

    @property
    def mesh_frames(self) -> int:
        return sum(count for t, count in self.ad_types.items() if t in MESH_AD_TYPES)


def parse_ad_structures(payload: bytes) -> list[ADStructure]:
    """Split an advertising payload into its AD structures.

    Format is a chain of [length][type][data...], where length covers the type
    byte plus the data. A zero length is the conventional end marker, and
    truncated trailing structures are common on real captures.
    """
    out: list[ADStructure] = []
    index = 0
    while index < len(payload):
        length = payload[index]
        if length == 0:
            break
        if index + 1 + length > len(payload):
            break
        ad_type = payload[index + 1]
        data = payload[index + 2:index + 1 + length]
        out.append(ADStructure(ad_type=ad_type, data=data))
        index += 1 + length
    return out


def parse_le_advertising_report(data: bytes) -> list[dict]:
    """Parse an LE Advertising Report event body.

    Layout after the subevent code:
        num_reports (1)
        then per report:
            event_type (1) address_type (1) address (6)
            data_length (1) data (data_length) rssi (1, signed)
    """
    reports: list[dict] = []
    if not data:
        return reports

    num_reports = data[0]
    offset = 1
    for _ in range(num_reports):
        if offset + 9 > len(data):
            break
        event_type = data[offset]
        address_type = data[offset + 1]
        address = data[offset + 2:offset + 8]
        data_length = data[offset + 8]
        offset += 9

        if offset + data_length > len(data):
            break
        payload = data[offset:offset + data_length]
        offset += data_length

        rssi = 0
        if offset < len(data):
            rssi = struct.unpack("b", data[offset:offset + 1])[0]
            offset += 1

        reports.append({
            "event_type": event_type,
            "address_type": address_type,
            "mac": ":".join(f"{b:02X}" for b in reversed(address)),
            "payload": payload,
            "rssi": rssi,
        })
    return reports


def parse_le_ext_advertising_report(data: bytes) -> list[dict]:
    """Parse an LE Extended Advertising Report event body.

    A Bluetooth 5 controller reports through this instead of the legacy
    event, and BlueZ switches to extended scanning on its own when the
    controller supports it. An Intel AX200 does; a legacy-only parser sees
    nothing at all on one and reports an empty capture, which reads as
    "nothing is advertising" rather than "this event was not decoded".

    Layout after the subevent code:
        num_reports (1)
        then per report, sequential (not the parallel arrays of the
        legacy event):
            event_type (2) address_type (1) address (6)
            primary_phy (1) secondary_phy (1) sid (1) tx_power (1)
            rssi (1, signed) periodic_interval (2)
            direct_address_type (1) direct_address (6)
            data_length (1) data (data_length)
    """
    reports: list[dict] = []
    if not data:
        return reports

    num_reports = data[0]
    offset = 1
    for _ in range(num_reports):
        if offset + 24 > len(data):
            break
        event_type = struct.unpack("<H", data[offset:offset + 2])[0]
        address_type = data[offset + 2]
        address = data[offset + 3:offset + 9]
        rssi = struct.unpack("b", data[offset + 13:offset + 14])[0]
        data_length = data[offset + 23]
        offset += 24

        if offset + data_length > len(data):
            break
        payload = data[offset:offset + data_length]
        offset += data_length

        reports.append({
            "event_type": event_type,
            "address_type": address_type,
            "mac": ":".join(f"{b:02X}" for b in reversed(address)),
            "payload": payload,
            "rssi": rssi,
        })
    return reports


def _parse_monitor_packet(packet: bytes) -> list[dict]:
    """Pull LE advertising reports out of one monitor-socket packet.

    Each packet starts with a 6-byte monitor header:
        opcode (2, LE)  index (2, LE)  length (2, LE)
    """
    if len(packet) < 6:
        return []

    opcode, _index, length = struct.unpack("<HHH", packet[0:6])
    body = packet[6:6 + length]

    if opcode != MON_EVENT_PKT or len(body) < 2:
        return []

    event_code = body[0]
    if event_code != HCI_EV_LE_META:
        return []

    if len(body) < 3:
        return []
    subevent = body[2]
    if subevent == LE_ADVERTISING_REPORT:
        return parse_le_advertising_report(body[3:])
    if subevent == LE_EXT_ADVERTISING_REPORT:
        return parse_le_ext_advertising_report(body[3:])
    return []


class HCIMonitorCapture:
    """Capture complete advertising payloads via the HCI monitor socket."""

    def __init__(self, adapter: str = "hci0", output_dir: str = "./output"):
        self.adapter = adapter
        self.output_dir = Path(output_dir)
        self.session = HCICaptureSession()
        self.scan_failed = False

    @staticmethod
    def available() -> tuple[bool, str]:
        """Can we actually do this here? Returns (ok, reason if not)."""
        import sys
        if not sys.platform.startswith("linux"):
            return False, ("The HCI monitor socket is a Linux kernel interface. "
                           "On this platform use an nRF52840 with Sniffle instead: "
                           "meshbreaker sniff --backend sniffle")
        try:
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
            sock.close()
        except PermissionError:
            return False, ("Opening a raw HCI socket needs root. Re-run with sudo, "
                           "or grant the capability once:\n"
                           "    sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)")
        except OSError as e:
            return False, f"Cannot open a Bluetooth socket: {e}"
        return True, ""

    def _open_monitor(self) -> socket.socket:
        """Open and bind a socket on the HCI monitor channel.

        Python's own `bind()` cannot do this. CPython's socket module parses
        exactly one field for BTPROTO_HCI and hardcodes the channel to
        HCI_CHANNEL_RAW, so `bind((dev, channel))` is rejected outright with
        "wrong format" and there is no way to ask for the monitor channel
        through the high-level API.

        So we build the 6-byte sockaddr_hci ourselves and call bind(2) through
        libc:

            struct sockaddr_hci {
                unsigned short hci_family;    /* AF_BLUETOOTH */
                unsigned short hci_dev;       /* 0xFFFF = all adapters */
                unsigned short hci_channel;   /* HCI_CHANNEL_MONITOR */
            };
        """
        import ctypes
        import ctypes.util
        import os

        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)

        libc_path = ctypes.util.find_library("c")
        if libc_path is None:
            sock.close()
            raise OSError("Cannot locate libc to bind the monitor channel")
        libc = ctypes.CDLL(libc_path, use_errno=True)

        addr = struct.pack("<HHH", AF_BLUETOOTH, 0xFFFF, HCI_CHANNEL_MONITOR)
        if libc.bind(sock.fileno(), addr, len(addr)) != 0:
            err = ctypes.get_errno()
            sock.close()
            raise OSError(err, os.strerror(err))

        sock.setblocking(False)
        return sock

    async def capture(self, duration: float = 30.0, save: bool = True,
                      drive_scan: bool = True) -> HCICaptureSession:
        ok, reason = self.available()
        if not ok:
            logger.error("Cannot use the HCI monitor socket")
            for line in reason.splitlines():
                logger.info(f"  {line}")
            return self.session

        try:
            sock = self._open_monitor()
        except PermissionError:
            logger.error("Permission denied opening the HCI monitor socket — needs root")
            logger.info("  sudo meshbreaker hci-capture")
            return self.session
        except OSError as e:
            logger.error(f"Could not open the HCI monitor socket: {e}")
            return self.session

        logger.info(f"HCI monitor capture — {duration}s, full AD payloads")
        logger.info("  This sees AD types BlueZ does not expose to bleak, "
                    "including PB-ADV")

        scanner_task = None
        if drive_scan:
            scanner_task = asyncio.create_task(self._drive_scan(duration))
            await asyncio.sleep(1.5)
            if self.scan_failed:
                sock.close()
                scanner_task.cancel()
                logger.error("Nothing is scanning, so the monitor would record "
                             "an empty capture")
                logger.info("  Fix the error above and run this again, or drive "
                            "a scan yourself and pass --no-scan")
                return self.session

        start = time.time()
        try:
            await self.read_loop(sock, duration, start)
        finally:
            sock.close()
            if scanner_task:
                scanner_task.cancel()
                try:
                    await scanner_task
                except (asyncio.CancelledError, Exception):
                    pass

        self.session.duration = time.time() - start
        if save and self.session.frames:
            self.session.output_file = self._save()

        _print_summary(self.session)
        return self.session

    async def read_loop(self, sock, duration: float, start: float | None = None):
        """Consume monitor packets off `sock` until `duration` elapses.

        Split out from capture() on purpose: opening the monitor channel needs
        root and a real controller, but everything that happens afterwards is
        ordinary socket reading and parsing. Keeping it separate means the
        whole decode path can be tested by handing it one end of a socketpair
        and writing real monitor-format packets into the other, leaving only
        the privileged bind() untested.
        """
        if start is None:
            start = time.time()
        loop = asyncio.get_running_loop()

        while time.time() - start < duration:
            try:
                packet = await asyncio.wait_for(loop.sock_recv(sock, 4096), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            except OSError as e:
                logger.warning(f"Monitor read failed: {e}")
                break
            if not packet:
                continue
            for report in _parse_monitor_packet(packet):
                self._record(report, time.time() - start)

        return self.session

    async def _drive_scan(self, duration: float):
        """Put the adapter into scanning mode so the monitor has traffic."""
        try:
            from bleak import BleakScanner
        except ImportError:
            logger.warning("bleak not installed — start a scan yourself, e.g. "
                           "'bluetoothctl scan on'")
            return
        try:
            async with BleakScanner(adapter=self.adapter):
                await asyncio.sleep(duration)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.scan_failed = True
            from src.core.adapter_manager import report_ble_error
            if not report_ble_error(e):
                logger.warning(f"Could not start scanning: {logger.describe(e)}")
            logger.info("  Start one yourself with: bluetoothctl scan on")

    def _record(self, report: dict, timestamp: float):
        """Store one AD structure per frame, so `raw` starts with the AD type."""
        structures = parse_ad_structures(report["payload"])
        name = ""
        for structure in structures:
            if structure.ad_type in (0x08, 0x09):
                name = structure.data.decode("utf-8", errors="replace")

        for structure in structures:
            self.session.ad_types[structure.ad_type] = (
                self.session.ad_types.get(structure.ad_type, 0) + 1)

            self.session.frames.append({
                "t": timestamp,
                "mac": report["mac"],
                "name": name,
                "rssi": report["rssi"],
                "addr_type": report.get("address_type"),
                "ad_type": structure.ad_type,
                "raw": bytes([structure.ad_type]).hex() + structure.data.hex(),
                "mesh": "sig_mesh" if structure.is_mesh else None,
            })

            if structure.is_mesh:
                logger.data(f"  {report['mac']}  {structure.name}  "
                            f"{structure.data.hex()[:40]}")

    def _save(self) -> str:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        dest = self.output_dir / f"hci_capture_{int(time.time())}.json"
        dest.write_text(json.dumps(self.session.frames, indent=2))
        logger.success(f"Capture saved → {dest}")
        return str(dest)


def _print_summary(session: HCICaptureSession):
    from rich.table import Table
    from rich import box
    from rich.console import Console

    console = Console(emoji=False)

    if not session.frames:
        logger.warning("No advertising reports captured")
        logger.info("  Check an adapter is up (hciconfig) and something is advertising")
        return

    t = Table(title=f"HCI Monitor Capture — {len(session.frames)} AD structures "
                    f"in {session.duration:.1f}s",
              box=box.ROUNDED, border_style="cyan")
    t.add_column("AD type", style="bold white", width=9)
    t.add_column("Name", style="cyan", width=34)
    t.add_column("Count", style="dim", width=8)
    t.add_column("Mesh", width=6)

    for ad_type, count in sorted(session.ad_types.items(), key=lambda x: -x[1]):
        is_mesh = ad_type in MESH_AD_TYPES
        t.add_row(f"0x{ad_type:02X}", AD_TYPE_NAMES.get(ad_type, "Unknown"),
                  str(count), "[green]yes[/]" if is_mesh else "—")
    console.print(t)

    if session.mesh_frames:
        logger.success(f"{session.mesh_frames} mesh AD structures captured — "
                       "run 'meshbreaker provisioning --capture <file>' to analyse them")
    else:
        logger.info("No mesh AD types seen. Either nothing mesh is in range, or it "
                    "is out of radio reach of this adapter.")
