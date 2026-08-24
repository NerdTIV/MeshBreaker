"""
Multi-channel sniffing and connection following.

The problem this solves: BLE advertises on three channels (37, 38, 39) and a
radio can only listen to one at a time. The CONNECT_IND packet that sets up a
connection goes out on whichever channel the initiator picked. Miss it and you
cannot follow that connection, because everything you need to compute the hop
sequence lives in that one packet.

Three ways to deal with it, in increasing order of cost:

  1. **Parallel HCI adapters** (this module, `MultiAdapterSniffer`).
     Cheap dongles cannot be pinned to a channel — BlueZ hops them for you.
     But running several in parallel multiplies your dwell time, so you miss
     far fewer adverts, and comparing RSSI across adapters gives you a rough
     idea of where a device physically is. Good enough for discovery and mesh
     beacon capture. Not enough to follow a connection.

  2. **Sniffle on an nRF52840 dongle** (~20 EUR). Real channel control, catches
     CONNECT_IND, follows the hop sequence itself. This is the sweet spot.

  3. **Ubertooth One** (~120 EUR) or an SDR. Ubertooth follows connections too.
     An SDR captures the whole 80 MHz band and de-hops offline, which is the
     most robust option and the most work.

We drive 1 directly, and shell out to 2 and 3 when they are installed.
"""

import asyncio
import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from src.utils import logger
from src.modules.channel_map import (
    ADV_CHANNELS, channel_to_freq, parse_connect_ind,
    predict_hops, print_connection_params, wifi_overlap,
)


@dataclass
class SniffHit:
    """One advert seen by one adapter."""

    timestamp: float
    mac: str
    name: str
    rssi: int
    adapter: str
    raw: str = ""


@dataclass
class SniffResult:
    hits: list[SniffHit] = field(default_factory=list)
    adapters_used: list[str] = field(default_factory=list)
    duration: float = 0.0
    output_file: str | None = None

    @property
    def unique_devices(self) -> int:
        return len({h.mac for h in self.hits})


class MultiAdapterSniffer:
    """Run several HCI adapters at once and merge what they see.

    Be honest about the limitation: each adapter still hops 37/38/39 under
    BlueZ's control. We are buying coverage through parallelism, not through
    channel assignment. For actual per-channel capture use SniffleBackend.
    """

    def __init__(self, adapters: list[str], output_dir: str = "./output"):
        self.adapters = adapters
        self.output_dir = Path(output_dir)
        self.result = SniffResult(adapters_used=list(adapters))

    async def run(self, duration: float = 30.0, save: bool = True) -> SniffResult:
        try:
            from bleak import BleakScanner
        except ImportError:
            logger.error("bleak not installed")
            return self.result

        logger.info(f"Parallel sniff on {len(self.adapters)} adapters for {duration}s")
        logger.info(f"  adapters: {', '.join(self.adapters)}")
        start = time.time()
        seen_per_adapter: dict[str, set] = {a: set() for a in self.adapters}

        def _make_callback(adapter_name: str):
            def _cb(device, adv):
                raw = b""
                for company, payload in (adv.manufacturer_data or {}).items():
                    raw = bytes([company & 0xFF, company >> 8]) + payload
                    break
                self.result.hits.append(SniffHit(
                    timestamp=time.time() - start,
                    mac=device.address,
                    name=device.name or "",
                    rssi=adv.rssi,
                    adapter=adapter_name,
                    raw=raw.hex(),
                ))
                seen_per_adapter[adapter_name].add(device.address)
            return _cb

        async def _scan_on(adapter_name: str):
            try:
                scanner = BleakScanner(
                    detection_callback=_make_callback(adapter_name),
                    adapter=adapter_name,
                )
                async with scanner:
                    await asyncio.sleep(duration)
            except Exception as e:
                logger.error(f"Adapter {adapter_name} failed: {e}")

        await asyncio.gather(*[_scan_on(a) for a in self.adapters])
        self.result.duration = time.time() - start

        for adapter, macs in seen_per_adapter.items():
            logger.info(f"  {adapter}: {len(macs)} unique devices")

        if save:
            self.result.output_file = self._save()
        _print_sniff_summary(self.result, seen_per_adapter)
        return self.result

    def _save(self) -> str:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        dest = self.output_dir / f"sniff_{int(time.time())}.json"
        data = [
            {"t": h.timestamp, "mac": h.mac, "name": h.name, "rssi": h.rssi,
             "ad_type": 0xFF if h.raw else None, "raw": h.raw,
             "mesh": None, "adapter": h.adapter}
            for h in self.result.hits
        ]
        dest.write_text(json.dumps(data, indent=2))
        logger.success(f"Sniff saved → {dest}")
        return str(dest)


class SniffleBackend:
    """Drive Sniffle running on an nRF52840 dongle.

    Sniffle is the practical way to do channel-level BLE sniffing on a budget.
    Flash the firmware onto a dongle, then its host script gives you channel
    selection, connection following and pcap output.

    Project: https://github.com/nccgroup/Sniffle
    """

    TOOL = "sniff_receiver.py"

    def __init__(self, serial_port: str = "/dev/ttyACM0", output_dir: str = "./output"):
        self.serial_port = serial_port
        self.output_dir = Path(output_dir)

    @staticmethod
    def available() -> bool:
        return shutil.which(SniffleBackend.TOOL) is not None

    def build_command(self, channel: int = 37, duration: float = 30.0,
                      target_mac: str | None = None, pcap: str | None = None) -> list[str]:
        cmd = [self.TOOL, "-s", self.serial_port, "-c", str(channel)]
        if target_mac:
            cmd += ["-m", target_mac]
        if pcap:
            cmd += ["-o", pcap]
        return cmd

    def run(self, channel: int = 37, duration: float = 30.0,
            target_mac: str | None = None) -> dict:
        if not self.available():
            logger.error(f"{self.TOOL} not on PATH — install Sniffle first")
            logger.info("  git clone https://github.com/nccgroup/Sniffle")
            logger.info("  Flash python_cli/… firmware to the nRF52840, then add")
            logger.info("  the python_cli directory to your PATH.")
            return {"error": "sniffle not installed"}

        self.output_dir.mkdir(parents=True, exist_ok=True)
        pcap = str(self.output_dir / f"sniffle_ch{channel}_{int(time.time())}.pcap")
        cmd = self.build_command(channel, duration, target_mac, pcap)

        logger.info(f"Sniffle on channel {channel} ({channel_to_freq(channel)} MHz) "
                    f"for {duration}s")
        overlap = wifi_overlap(channel)
        if overlap:
            logger.warning(f"Channel {channel} overlaps {overlap} — expect packet loss "
                           "if that Wi-Fi channel is busy")
        logger.debug(f"  {' '.join(cmd)}")

        try:
            subprocess.run(cmd, timeout=duration + 10,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.error(f"Sniffle failed: {e}")
            return {"error": str(e)}

        logger.success(f"Capture → {pcap}")
        return {"backend": "sniffle", "channel": channel, "pcap": pcap}


class UbertoothBackend:
    """Drive an Ubertooth One.

    Ubertooth follows a connection once it has caught the CONNECT_IND, and can
    also run promiscuous mode against an already-established connection by
    recovering the Access Address statistically.
    """

    TOOL = "ubertooth-btle"

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir)

    @staticmethod
    def available() -> bool:
        return shutil.which(UbertoothBackend.TOOL) is not None

    def run(self, duration: float = 30.0, target_mac: str | None = None,
            promiscuous: bool = False) -> dict:
        if not self.available():
            logger.error(f"{self.TOOL} not on PATH — install ubertooth tools")
            logger.info("  sudo apt install ubertooth")
            return {"error": "ubertooth not installed"}

        self.output_dir.mkdir(parents=True, exist_ok=True)
        pcap = str(self.output_dir / f"ubertooth_{int(time.time())}.pcap")

        cmd = [self.TOOL, "-p" if promiscuous else "-f", "-c", pcap]
        if target_mac:
            cmd += ["-t", target_mac]

        logger.info(f"Ubertooth {'promiscuous' if promiscuous else 'follow'} mode, {duration}s")
        logger.debug(f"  {' '.join(cmd)}")
        try:
            subprocess.run(cmd, timeout=duration + 5,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.error(f"Ubertooth failed: {e}")
            return {"error": str(e)}

        logger.success(f"Capture → {pcap}")
        return {"backend": "ubertooth", "pcap": pcap}


def follow_from_connect_ind(connect_ind_hex: str, events: int = 20,
                            algorithm: int = 1) -> dict:
    """Take a captured CONNECT_IND and work out where the connection goes next.

    This is the payoff for catching that one packet: from here you know the
    Access Address to filter on, the CRC init to validate frames, and the exact
    channel the connection will use at every future event.
    """
    try:
        payload = bytes.fromhex(connect_ind_hex.replace(" ", "").replace(":", ""))
    except ValueError:
        logger.error("CONNECT_IND is not valid hex")
        return {"error": "invalid hex"}

    if len(payload) == 36:
        payload = payload[2:]

    try:
        params = parse_connect_ind(payload)
    except ValueError as e:
        logger.error(str(e))
        return {"error": str(e)}

    hops = predict_hops(params, events=events, algorithm=algorithm)
    print_connection_params(params, hops)

    return {
        "access_address": f"0x{params.access_address:08X}",
        "crc_init": f"0x{params.crc_init:06X}",
        "hop_increment": params.hop_increment,
        "interval_ms": params.interval_ms,
        "channels_used": len(params.used_channels),
        "algorithm": algorithm,
        "predicted_channels": hops,
    }


def _print_sniff_summary(result: SniffResult, seen_per_adapter: dict):
    from rich.table import Table
    from rich import box
    from rich.console import Console
    from collections import defaultdict

    console = Console()

    t = Table(title="Multi-Adapter Sniff", box=box.ROUNDED, border_style="cyan")
    t.add_column("Metric", style="bold white", width=22)
    t.add_column("Value", style="cyan")
    t.add_row("Duration", f"{result.duration:.1f}s")
    t.add_row("Adapters", ", ".join(result.adapters_used))
    t.add_row("Total adverts", str(len(result.hits)))
    t.add_row("Unique devices", str(result.unique_devices))
    console.print(t)

    all_macs = {h.mac for h in result.hits}
    if len(seen_per_adapter) > 1 and all_macs:
        exclusive = defaultdict(list)
        for mac in all_macs:
            seers = [a for a, macs in seen_per_adapter.items() if mac in macs]
            if len(seers) == 1:
                exclusive[seers[0]].append(mac)
        if exclusive:
            logger.info("Devices seen by only one adapter (weak signal or missed channel):")
            for adapter, macs in exclusive.items():
                logger.info(f"  {adapter}: {', '.join(macs[:5])}"
                            + (f" (+{len(macs)-5} more)" if len(macs) > 5 else ""))

    if len(result.adapters_used) > 1:
        best_rssi: dict[str, tuple[str, int]] = {}
        for h in result.hits:
            cur = best_rssi.get(h.mac)
            if cur is None or h.rssi > cur[1]:
                best_rssi[h.mac] = (h.adapter, h.rssi)
        logger.info("Closest adapter per device (strongest RSSI):")
        for mac, (adapter, rssi) in list(best_rssi.items())[:10]:
            logger.debug(f"  {mac}  {adapter}  {rssi} dBm")


def print_channel_plan(adapters: list[str]):
    """Show how adapters map onto advertising channels, and what it buys you."""
    from rich.table import Table
    from rich import box
    from rich.console import Console

    console = Console()
    t = Table(title="Advertising Channel Coverage", box=box.ROUNDED, border_style="magenta")
    t.add_column("Channel", style="bold magenta", width=8)
    t.add_column("Freq", style="cyan", width=10)
    t.add_column("WiFi overlap", style="dim", width=14)
    t.add_column("Covered by", style="white", width=26)

    for i, ch in enumerate(ADV_CHANNELS):
        if adapters:
            assigned = adapters[i % len(adapters)]
            covered = f"{assigned} (hopping)"
        else:
            covered = "—"
        t.add_row(str(ch), f"{channel_to_freq(ch)} MHz",
                  wifi_overlap(ch) or "—", covered)
    console.print(t)

    if len(adapters) < 3:
        logger.info(f"{len(adapters)} adapter(s): BlueZ hops each across all three "
                    "channels, so coverage is time-sliced rather than simultaneous.")
    logger.info("For true simultaneous per-channel capture, use Sniffle on three "
                "nRF52840 dongles, or an SDR.")
