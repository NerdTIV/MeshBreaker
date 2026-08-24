from dataclasses import dataclass, field

from src.utils import logger
from src.utils.capture_io import (frame_bytes, load_capture,
                                  profile_capture, warn_if_mesh_blind)


@dataclass
class MeshNode:
    mac:      str
    name:     str
    rssi_min: int = 0
    rssi_max: int = 0
    rssi_avg: float = 0.0
    packets:  int = 0
    protocol: str | None = None
    roles:    list[str] = field(default_factory=list)
    raw_samples: list[bytes] = field(default_factory=list)


@dataclass
class MeshTopology:
    nodes:     dict[str, MeshNode] = field(default_factory=dict)
    protocol:  str | None = None
    relay_candidates: list[str] = field(default_factory=list)
    proxy_candidates: list[str] = field(default_factory=list)


_MSG_AD_TYPE   = 0x2A
_BEACON_AD_TYPE = 0x2B

_UNPROVISIONED = 0x00
_SECURE_NETWORK = 0x01


class MeshFrameParser:
    def __init__(self):
        self._topology = MeshTopology()

    def parse_file(self, path: str):
        entries = load_capture(path)
        if entries is None:
            return self._topology
        logger.info(f"Parsing {len(entries)} beacons from {path}")
        warn_if_mesh_blind(profile_capture(entries), "mesh beacons")
        for entry in entries:
            self._process_entry(entry)
        self._infer_roles()
        _print_topology(self._topology)
        return self._topology

    def parse_beacon(self, entry: dict):
        self._process_entry(entry)
        return self._topology.nodes.get(entry.get("mac", ""))

    def topology(self):
        return self._topology

    def _process_entry(self, entry: dict):
        mac      = entry.get("mac", "??:??:??:??:??:??")
        name     = entry.get("name", "")
        rssi     = entry.get("rssi", 0)
        mesh_hint = entry.get("mesh")
        raw      = frame_bytes(entry) or b""

        node = self._topology.nodes.get(mac)
        if node is None:
            node = MeshNode(mac=mac, name=name, rssi_min=rssi, rssi_max=rssi,
                            rssi_avg=rssi, packets=0, protocol=mesh_hint)
            self._topology.nodes[mac] = node

        node.packets += 1
        node.rssi_min = min(node.rssi_min, rssi)
        node.rssi_max = max(node.rssi_max, rssi)
        node.rssi_avg = (node.rssi_avg * (node.packets - 1) + rssi) / node.packets

        if raw:
            node.raw_samples.append(raw)
            self._parse_sig_mesh(node, raw)

        if self._topology.protocol is None and mesh_hint:
            self._topology.protocol = mesh_hint

    def _parse_sig_mesh(self, node: MeshNode, raw: bytes):
        if len(raw) < 2:
            return
        ad_type = raw[0]

        if ad_type == _BEACON_AD_TYPE and len(raw) >= 2:
            beacon_type = raw[1]
            if beacon_type == _UNPROVISIONED:
                if "unprovisioned" not in node.roles:
                    node.roles.append("unprovisioned")
            elif beacon_type == _SECURE_NETWORK:
                if "provisioned" not in node.roles:
                    node.roles.append("provisioned")
                if len(raw) >= 3:
                    flags = raw[2]
                    if flags & 0x02:
                        node.roles.append("key_refresh")

        elif ad_type == _MSG_AD_TYPE:
            if "active" not in node.roles:
                node.roles.append("active")

    def _infer_roles(self):
        for mac, node in self._topology.nodes.items():
            if node.packets > 10 and node.rssi_avg > -70:
                self._topology.relay_candidates.append(mac)
            if "provisioned" in node.roles:
                self._topology.proxy_candidates.append(mac)


def _print_topology(topo: MeshTopology):
    from rich.table import Table
    from rich import box
    from rich.console import Console
    console = Console()

    t = Table(title=f"Mesh Topology ({topo.protocol or 'unknown protocol'})",
              box=box.ROUNDED, border_style="magenta")
    t.add_column("MAC",      style="bold magenta", width=18)
    t.add_column("Name",     style="white",        width=20)
    t.add_column("RSSI avg", style="cyan",         width=9)
    t.add_column("Pkts",     style="dim",          width=5)
    t.add_column("Protocol", style="yellow",       width=12)
    t.add_column("Roles",    style="green",        width=30)

    for mac, n in sorted(topo.nodes.items(), key=lambda x: -x[1].packets):
        rssi_color = "green" if n.rssi_avg > -60 else "yellow" if n.rssi_avg > -80 else "red"
        t.add_row(mac, n.name[:20], f"[{rssi_color}]{n.rssi_avg:.0f}[/]",
                  str(n.packets), n.protocol or "?", ", ".join(n.roles))

    console.print(t)
    logger.info(f"Relay candidates: {topo.relay_candidates}")
    logger.info(f"Proxy candidates: {topo.proxy_candidates}")
