import asyncio
import os
import random
import struct
import time
from dataclasses import dataclass, field

try:
    from bleak import BleakClient, BleakScanner
    BLEAK_OK = True
except ImportError:
    BLEAK_OK = False

from src.utils import logger


@dataclass
class MeshFuzzResult:
    strategy: str
    payload: bytes
    target_mac: str
    crashed: bool = False
    response: bytes | None = None
    elapsed_ms: float = 0.0
    note: str = ""


MESH_PROXY_IN_UUID  = "00002add-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT_UUID = "00002ade-0000-1000-8000-00805f9b34fb"

PDU_NET_PDU   = 0x00
PDU_MESH_BCN  = 0x01
PDU_PROXY_CFG = 0x02
PDU_PROV_PDU  = 0x03

_IVI_NID_MASK = 0x7F


def _craft_network_pdu(ivi: int = 0, nid: int = 0x68,
                        ctl: int = 0, ttl: int = 0x7F,
                        seq: int = 0, src: int = 0x0001,
                        dst: int = 0xFFFF, payload: bytes = b"\x00"):
    byte0 = ((ivi & 1) << 7) | (nid & 0x7F)
    byte1 = ((ctl & 1) << 7) | (ttl & 0x7F)
    seq_bytes = struct.pack(">I", seq)[1:]
    hdr = struct.pack(">BB", byte0, byte1) + seq_bytes + struct.pack(">HH", src, dst)
    return hdr + payload


def _craft_proxy_cfg(opcode: int = 0x00, data: bytes = b""):
    return bytes([opcode]) + data


class MeshFuzzer:
    def __init__(self, target: str, adapter: str = "hci0"):
        self.target  = target
        self.adapter = adapter
        self.results: list[MeshFuzzResult] = []

    async def fuzz_gatt_proxy(self, strategy: str = "all"):
        if not BLEAK_OK:
            logger.error("bleak not installed")
            return []
        if not self.target:
            logger.error("No target MAC set")
            return []

        strategies = {
            "net_pdu":       self._gen_net_pdus,
            "proxy_cfg":     self._gen_proxy_cfgs,
            "oversized":     self._gen_oversized,
            "malformed_ivi": self._gen_malformed_ivi,
            "seq_replay":    self._gen_seq_replay,
        }
        active = list(strategies.values()) if strategy == "all" else [strategies[strategy]]

        logger.info(f"GATT Mesh Proxy fuzz → {self.target}  strategies={len(active)}")
        all_payloads: list[tuple[str, bytes]] = []
        for fn in active:
            all_payloads.extend(fn())

        try:
            async with BleakClient(self.target, bluez={"adapter": self.adapter}) as client:
                for strat_name, payload in all_payloads:
                    r = await self._send_payload(client, strat_name, payload)
                    self.results.append(r)
                    if r.crashed:
                        logger.error(f"[CRASH] Strategy={strat_name}  payload={payload.hex()}")
                        break
        except Exception as e:
            logger.error(f"Connection failed: {e}")

        _print_fuzz_results(self.results)
        return self.results

    async def _send_payload(self, client, strategy: str, payload: bytes):
        t0 = time.time()
        crashed = False
        resp = None
        try:
            await client.write_gatt_char(MESH_PROXY_IN_UUID, payload, response=True)
        except Exception as e:
            note = str(e)
            if "disconnect" in note.lower() or "timeout" in note.lower():
                crashed = True
            return MeshFuzzResult(strategy, payload, self.target, crashed=crashed,
                                  elapsed_ms=(time.time()-t0)*1000, note=note)
        elapsed = (time.time() - t0) * 1000
        return MeshFuzzResult(strategy, payload, self.target, crashed=crashed,
                              elapsed_ms=elapsed)

    def _gen_net_pdus(self):
        out = []
        for seq in [0, 0xFFFFFF, 0x7FFFFF]:
            p = _craft_network_pdu(seq=seq, dst=0xFFFF)
            out.append(("net_pdu", p))
        out.append(("net_pdu", b"\x00" * 18))
        out.append(("net_pdu", b"\xFF" * 18))
        return out

    def _gen_proxy_cfgs(self):
        out = []
        for op in range(0x00, 0x10):
            p = _craft_proxy_cfg(opcode=op, data=os.urandom(8))
            out.append(("proxy_cfg", p))
        return out

    def _gen_oversized(self):
        return [
            ("oversized", b"\x00" * 64),
            ("oversized", b"\x00" * 256),
            ("oversized", b"\xFF" * 512),
            ("oversized", b"\xAA" * 1024),
        ]

    def _gen_malformed_ivi(self):
        out = []
        for ivi in [0, 1]:
            for nid in [0x00, 0x7F, 0xFF]:
                p = _craft_network_pdu(ivi=ivi, nid=nid, payload=b"\xDE\xAD\xBE\xEF")
                out.append(("malformed_ivi", p))
        return out

    def _gen_seq_replay(self):
        return [
            ("seq_replay", _craft_network_pdu(seq=0, payload=b"\x01\x02\x03")),
            ("seq_replay", _craft_network_pdu(seq=0, payload=b"\x01\x02\x03")),
        ]


def _print_fuzz_results(results: list[MeshFuzzResult]):
    from rich.table import Table
    from rich import box
    from rich.console import Console
    console = Console(emoji=False)

    crashes = [r for r in results if r.crashed]
    t = Table(title=f"Mesh Fuzz Results — {len(results)} payloads, {len(crashes)} crashes",
              box=box.SIMPLE, show_header=True)
    t.add_column("Strategy", style="white",    width=16)
    t.add_column("Size",     style="dim",       width=5)
    t.add_column("Crash",    style="bold red",  width=6)
    t.add_column("ms",       style="dim",       width=8)
    t.add_column("Note",     style="dim",       width=40)

    for r in results:
        crash_str = "[bold red]CRASH[/]" if r.crashed else "—"
        t.add_row(r.strategy, str(len(r.payload)), crash_str,
                  f"{r.elapsed_ms:.1f}", r.note[:40])
    console.print(t)
