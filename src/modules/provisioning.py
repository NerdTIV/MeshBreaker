"""
BLE Mesh provisioning analysis.

Provisioning is how a blank node joins a mesh network. The provisioner and
the new node run an ECDH exchange and the node receives the NetKey. Get in
the middle of that exchange and you own the network, so it is the single
most interesting phase to watch.

The useful detail: **the early provisioning PDUs are not encrypted**. Invite,
Capabilities, Start and Public Key all travel in the clear, because there is
no shared key yet — that is the whole point of the exchange. Only
Confirmation/Random (hashes) and Data (encrypted with the session key) are
protected. So a passive capture of a provisioning session tells you exactly
which authentication method was negotiated, without attacking anything.

What we look for:

    AuthenticationMethod = No OOB   ->  nothing authenticates the peer, so a
                                        machine-in-the-middle can sit between
                                        provisioner and node and end up with
                                        the NetKey.
    Static OOB not supported        ->  the node cannot do the strong method.
    Output/Input OOB size small     ->  the AuthValue space is tiny and can be
                                        brute-forced offline from Confirmation.

Two bearers carry provisioning:

    PB-ADV   AD type 0x29, broadcast, no connection. Sniffable passively.
    PB-GATT  GATT service 0x1827, connection-based. A device still exposing
             0x1827 after deployment can usually be re-provisioned.

Relevant CVEs (published 2021, SIG Mesh provisioning):
    CVE-2020-26556  malleable commitment
    CVE-2020-26557  predictable AuthValue
    CVE-2020-26559  AuthValue leak
    CVE-2020-26560  impersonation during provisioning

Spec reference: Mesh Profile 1.0.1 section 5.4, Mesh Protocol 1.1 section 5.4.
"""

import struct
from dataclasses import dataclass, field

from src.utils import logger
from src.utils.capture_io import (decode_frames, load_capture,
                                  profile_capture, warn_if_mesh_blind)

PB_ADV_AD_TYPE = 0x29
MESH_PROVISIONING_SERVICE = "1827"
MESH_PROV_DATA_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROV_DATA_OUT = "00002adc-0000-1000-8000-00805f9b34fb"

GPCF_START = 0b00
GPCF_ACK = 0b01
GPCF_CONTINUATION = 0b10
GPCF_BEARER_CONTROL = 0b11

BEARER_OPCODES = {0x00: "Link Open", 0x01: "Link ACK", 0x02: "Link Close"}

PROV_PDU_TYPES = {
    0x00: "Provisioning Invite",
    0x01: "Provisioning Capabilities",
    0x02: "Provisioning Start",
    0x03: "Provisioning Public Key",
    0x04: "Provisioning Input Complete",
    0x05: "Provisioning Confirmation",
    0x06: "Provisioning Random",
    0x07: "Provisioning Data",
    0x08: "Provisioning Complete",
    0x09: "Provisioning Failed",
}

AUTH_METHODS = {
    0x00: "No OOB",
    0x01: "Static OOB",
    0x02: "Output OOB",
    0x03: "Input OOB",
}

ALGORITHMS = {
    0: "FIPS P-256 Elliptic Curve (CMAC-AES128)",
    1: "FIPS P-256 Elliptic Curve (HMAC-SHA256)",
}

OUTPUT_OOB_ACTIONS = {
    0: "Blink", 1: "Beep", 2: "Vibrate",
    3: "Output Numeric", 4: "Output Alphanumeric",
}
INPUT_OOB_ACTIONS = {
    0: "Push", 1: "Twist", 2: "Input Numeric", 3: "Input Alphanumeric",
}


@dataclass
class ProvisioningCapabilities:
    """Decoded Provisioning Capabilities PDU — what the node says it can do."""

    num_elements: int = 0
    algorithms: int = 0
    public_key_type: int = 0
    static_oob_type: int = 0
    output_oob_size: int = 0
    output_oob_action: int = 0
    input_oob_size: int = 0
    input_oob_action: int = 0

    @property
    def supports_static_oob(self) -> bool:
        return bool(self.static_oob_type & 0x01)

    @property
    def supports_oob_public_key(self) -> bool:
        return bool(self.public_key_type & 0x01)

    @property
    def algorithm_names(self) -> list[str]:
        return [name for bit, name in ALGORITHMS.items() if self.algorithms & (1 << bit)]

    @property
    def output_actions(self) -> list[str]:
        return [n for b, n in OUTPUT_OOB_ACTIONS.items() if self.output_oob_action & (1 << b)]

    @property
    def input_actions(self) -> list[str]:
        return [n for b, n in INPUT_OOB_ACTIONS.items() if self.input_oob_action & (1 << b)]


@dataclass
class ProvisioningFinding:
    severity: str
    title: str
    detail: str
    cve: str = ""


@dataclass
class ProvisioningSession:
    """One observed provisioning exchange, keyed by its PB-ADV link ID."""

    link_id: int = 0
    device_uuid: str = ""
    source_mac: str = ""
    pdus_seen: list[str] = field(default_factory=list)
    capabilities: ProvisioningCapabilities | None = None
    chosen_method: str | None = None
    chosen_algorithm: str | None = None
    auth_size: int = 0
    completed: bool = False


def parse_capabilities(data: bytes) -> ProvisioningCapabilities | None:
    """Parse the 11 parameter bytes of a Provisioning Capabilities PDU."""
    if len(data) < 11:
        logger.warning(f"Capabilities PDU too short: {len(data)} bytes, need 11")
        return None
    return ProvisioningCapabilities(
        num_elements=data[0],
        algorithms=struct.unpack(">H", data[1:3])[0],
        public_key_type=data[3],
        static_oob_type=data[4],
        output_oob_size=data[5],
        output_oob_action=struct.unpack(">H", data[6:8])[0],
        input_oob_size=data[8],
        input_oob_action=struct.unpack(">H", data[9:11])[0],
    )


def parse_start(data: bytes) -> dict | None:
    """Parse the 5 parameter bytes of a Provisioning Start PDU.

    This is the PDU that actually decides the security of the whole exchange:
    it names the authentication method both sides will use.
    """
    if len(data) < 5:
        logger.warning(f"Start PDU too short: {len(data)} bytes, need 5")
        return None
    return {
        "algorithm": data[0],
        "public_key": data[1],
        "auth_method": data[2],
        "auth_action": data[3],
        "auth_size": data[4],
    }


def _pb_adv_payload(entry: dict, raw: bytes) -> bytes | None:
    """Return the PB-ADV payload of a frame, or None if it is not PB-ADV.

    Everything that is not PB-ADV has to be dropped here. Feeding an
    arbitrary advert to parse_pb_adv() always succeeds — it reads the first
    four bytes as a Link ID — so an Apple manufacturer-data frame gets
    reported as a provisioning session with link ID 0xFF4C0002. A false
    "provisioning traffic observed" is worse than silence in an audit tool.

    `ad_type` is authoritative when the capture carries it. Only a capture
    without it falls back to reading the type off the payload.
    """
    ad_type = entry.get("ad_type")
    if ad_type is not None:
        if ad_type != PB_ADV_AD_TYPE:
            return None
        payload = raw[1:] if raw[:1] == bytes([PB_ADV_AD_TYPE]) else raw
    else:
        if raw[:1] != bytes([PB_ADV_AD_TYPE]):
            return None
        payload = raw[1:]

    return payload if len(payload) >= 6 else None


def parse_pb_adv(raw: bytes) -> dict | None:
    """Parse one PB-ADV payload.

    Layout:
        Link ID             4 bytes
        Transaction Number  1 byte
        Generic Prov PDU    variable

    The Generic Provisioning layer segments long provisioning PDUs, so a
    single advert may only carry a fragment. We decode the header and, when
    the fragment is a Transaction Start, the provisioning PDU inside it.
    """
    if len(raw) < 6:
        return None

    link_id = struct.unpack(">I", raw[0:4])[0]
    transaction = raw[4]
    gp = raw[5:]
    gpcf = gp[0] & 0x03

    out = {"link_id": link_id, "transaction": transaction, "gpcf": gpcf}

    if gpcf == GPCF_BEARER_CONTROL:
        opcode = gp[0] >> 2
        out["type"] = "bearer_control"
        out["opcode"] = opcode
        out["opcode_name"] = BEARER_OPCODES.get(opcode, f"Unknown 0x{opcode:02X}")
        if opcode == 0x00 and len(gp) >= 17:
            out["device_uuid"] = gp[1:17].hex()
        return out

    if gpcf == GPCF_ACK:
        out["type"] = "ack"
        return out

    if gpcf == GPCF_CONTINUATION:
        out["type"] = "continuation"
        out["segment_index"] = gp[0] >> 2
        out["data"] = gp[1:].hex()
        return out

    if len(gp) < 5:
        return None
    out["type"] = "start"
    out["seg_n"] = gp[0] >> 2
    out["total_length"] = struct.unpack(">H", gp[1:3])[0]
    out["fcs"] = gp[3]

    prov_pdu = gp[4:]
    if prov_pdu:
        pdu_type = prov_pdu[0] & 0x3F
        out["pdu_type"] = pdu_type
        out["pdu_name"] = PROV_PDU_TYPES.get(pdu_type, f"Unknown 0x{pdu_type:02X}")
        out["pdu_data"] = prov_pdu[1:].hex()
    return out


class ProvisioningAnalyzer:
    """Walk a capture file, rebuild provisioning sessions, score the risk."""

    def __init__(self):
        self.sessions: dict[int, ProvisioningSession] = {}
        self.findings: list[ProvisioningFinding] = []
        self.mesh_blind = False

    def parse_file(self, path: str) -> list[ProvisioningSession]:
        entries = load_capture(path)
        if entries is None:
            return []

        logger.info(f"Scanning {len(entries)} captured frames for provisioning traffic")

        profile = profile_capture(entries)
        self.mesh_blind = warn_if_mesh_blind(profile, "PB-ADV provisioning traffic")

        frames, _ = decode_frames(entries)

        for entry, raw in frames:
            payload = _pb_adv_payload(entry, raw)
            if payload is None:
                continue
            self._process(payload, entry.get("mac", ""))

        if not self.sessions and not self.mesh_blind:
            logger.info("No PB-ADV provisioning traffic in this capture")
        self._audit()
        return list(self.sessions.values())

    def _process(self, raw: bytes, mac: str):
        parsed = parse_pb_adv(raw)
        if not parsed:
            return

        link_id = parsed["link_id"]
        session = self.sessions.get(link_id)
        if session is None:
            session = ProvisioningSession(link_id=link_id, source_mac=mac)
            self.sessions[link_id] = session
            logger.warning(f"Provisioning session observed — link ID 0x{link_id:08X} from {mac}")

        if parsed["type"] == "bearer_control":
            session.pdus_seen.append(parsed["opcode_name"])
            if "device_uuid" in parsed:
                session.device_uuid = parsed["device_uuid"]
            return

        if parsed["type"] != "start" or "pdu_type" not in parsed:
            return

        session.pdus_seen.append(parsed["pdu_name"])
        pdu_data = bytes.fromhex(parsed.get("pdu_data", ""))

        if parsed["pdu_type"] == 0x01:
            caps = parse_capabilities(pdu_data)
            if caps:
                session.capabilities = caps
                logger.info(
                    f"  Capabilities: {caps.num_elements} elements, "
                    f"static OOB={'yes' if caps.supports_static_oob else 'no'}"
                )

        elif parsed["pdu_type"] == 0x02:
            start = parse_start(pdu_data)
            if start:
                session.chosen_method = AUTH_METHODS.get(
                    start["auth_method"], f"Unknown 0x{start['auth_method']:02X}")
                session.chosen_algorithm = ALGORITHMS.get(
                    start["algorithm"], f"Unknown 0x{start['algorithm']:02X}")
                session.auth_size = start["auth_size"]
                logger.warning(f"  Auth method negotiated: {session.chosen_method}")

        elif parsed["pdu_type"] == 0x08:
            session.completed = True

    def _audit(self):
        """Turn what we saw into findings a report can print."""
        for session in self.sessions.values():
            if session.chosen_method == "No OOB":
                self.findings.append(ProvisioningFinding(
                    severity="CRITICAL",
                    title="Provisioning negotiated with No OOB authentication",
                    detail=(
                        f"Link 0x{session.link_id:08X} used the 'No OOB' method. Nothing "
                        "authenticates either peer during the ECDH exchange, so an attacker "
                        "in range can act as machine-in-the-middle, complete provisioning "
                        "with both sides, and obtain the NetKey."
                    ),
                    cve="CVE-2020-26560",
                ))

            caps = session.capabilities
            if caps and not caps.supports_static_oob:
                self.findings.append(ProvisioningFinding(
                    severity="HIGH",
                    title="Device does not support Static OOB",
                    detail=(
                        f"Link 0x{session.link_id:08X}: the node advertises no Static OOB "
                        "support, so the strongest authentication method is unavailable and "
                        "the deployment is forced onto a weaker one."
                    ),
                ))

            if caps and 0 < caps.output_oob_size <= 4:
                self.findings.append(ProvisioningFinding(
                    severity="HIGH",
                    title=f"Output OOB size is only {caps.output_oob_size} digits",
                    detail=(
                        "The AuthValue is drawn from a small space. An attacker who captures "
                        "the Confirmation PDU can brute-force the AuthValue offline and then "
                        "replay a valid Confirmation."
                    ),
                    cve="CVE-2020-26557",
                ))

            if caps and caps.algorithms & 0x01 and not caps.algorithms & 0x02:
                self.findings.append(ProvisioningFinding(
                    severity="LOW",
                    title="Only the Mesh 1.0 provisioning algorithm is offered",
                    detail=(
                        "The node supports CMAC-AES128 but not the HMAC-SHA256 algorithm "
                        "added in Mesh Protocol 1.1, which suggests a 1.0 stack that will "
                        "not carry the 1.1 hardening fixes."
                    ),
                ))


async def probe_pb_gatt(target: str, adapter: str = "hci0") -> dict:
    """Check whether a target still exposes the PB-GATT provisioning service.

    A deployed node should already be provisioned, and a provisioned node
    normally swaps the Provisioning Service (0x1827) for the Proxy Service
    (0x1828). Still finding 0x1827 on a live device means it can be dragged
    into a new network by anyone in range.
    """
    try:
        from bleak import BleakClient
    except ImportError:
        logger.error("bleak not installed")
        return {"error": "bleak not installed"}

    result = {
        "target": target,
        "provisioning_service": False,
        "proxy_service": False,
        "data_in_writable": False,
        "findings": [],
    }

    logger.info(f"PB-GATT probe → {target}")
    try:
        async with BleakClient(target, adapter=adapter) as client:
            for svc in client.services:
                uuid = str(svc.uuid).lower()
                if "1827" in uuid:
                    result["provisioning_service"] = True
                if "1828" in uuid:
                    result["proxy_service"] = True
                for char in svc.characteristics:
                    if str(char.uuid).lower() == MESH_PROV_DATA_IN:
                        props = [str(p).upper() for p in char.properties]
                        if any("WRITE" in p for p in props):
                            result["data_in_writable"] = True
    except Exception as e:
        logger.error(f"PB-GATT probe failed: {e}")
        result["error"] = str(e)
        return result

    if result["provisioning_service"]:
        logger.warning("Mesh Provisioning Service (0x1827) is exposed")
        result["findings"].append({
            "severity": "HIGH",
            "title": "PB-GATT provisioning service exposed on a live device",
            "detail": (
                "The device advertises the Mesh Provisioning Service. A provisioned node "
                "should expose the Proxy Service (0x1828) instead. Anyone in range can "
                "start a provisioning session against it."
            ),
        })
    else:
        logger.info("Provisioning service not exposed (expected for a provisioned node)")

    if result["proxy_service"]:
        logger.info("Mesh Proxy Service (0x1828) present — node is provisioned")

    return result


def print_sessions(sessions: list[ProvisioningSession], findings: list[ProvisioningFinding]):
    from rich.table import Table
    from rich import box
    from rich.console import Console

    console = Console(emoji=False)

    if sessions:
        t = Table(title="Provisioning Sessions Observed", box=box.ROUNDED,
                  border_style="yellow")
        t.add_column("Link ID", style="bold magenta", width=12)
        t.add_column("Source", style="white", width=18)
        t.add_column("Device UUID", style="dim", width=34)
        t.add_column("Auth method", style="bold yellow", width=14)
        t.add_column("Done", style="cyan", width=5)
        for s in sessions:
            t.add_row(f"0x{s.link_id:08X}", s.source_mac or "?",
                      s.device_uuid[:32] or "—",
                      s.chosen_method or "not seen",
                      "yes" if s.completed else "no")
        console.print(t)

    if findings:
        t = Table(title="Provisioning Findings", box=box.ROUNDED, border_style="red")
        t.add_column("Severity", style="bold", width=10)
        t.add_column("Finding", style="white", width=46)
        t.add_column("CVE", style="dim", width=16)
        colors = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "green"}
        for f in findings:
            color = colors.get(f.severity, "white")
            t.add_row(f"[{color}]{f.severity}[/]", f.title, f.cve or "—")
        console.print(t)
        for f in findings:
            logger.warning(f"{f.severity}: {f.title}")
            logger.info(f"  {f.detail}")


MESH_PROV_SERVICE_UUID = "1827"
MESH_PROXY_SERVICE_UUID = "1828"

PROXY_ID_NETWORK = 0x00
PROXY_ID_NODE = 0x01

OOB_INFO_BITS = {
    0: "Other",
    1: "Electronic / URI",
    2: "2D machine-readable code",
    3: "Bar code",
    4: "NFC",
    5: "Number",
    6: "String",
    7: "Certificate-based provisioning",
    8: "Provisioning records",
    10: "On box",
    11: "Inside box",
    12: "On piece of paper",
    13: "Inside manual",
    14: "On device",
}


@dataclass
class UnprovisionedDevice:
    """A node advertising that it is ready to be provisioned."""

    mac: str = ""
    device_uuid: str = ""
    oob_info: int = 0
    rssi: int = 0

    @property
    def oob_sources(self) -> list[str]:
        return [name for bit, name in OOB_INFO_BITS.items() if self.oob_info & (1 << bit)]

    @property
    def has_oob(self) -> bool:
        return self.oob_info != 0


@dataclass
class ProxyNode:
    """A provisioned node reachable over the proxy service."""

    mac: str = ""
    identity_type: int = PROXY_ID_NETWORK
    network_id: str = ""
    node_identity: str = ""
    rssi: int = 0


def _service_uuid_matches(uuid: str, short: str) -> bool:
    """Match a service UUID against its 16-bit short form.

    bleak reports the full 128-bit form, so 0x1827 arrives as
    00001827-0000-1000-8000-00805f9b34fb.
    """
    return short.lower() in str(uuid).lower().replace("-", "")


def parse_prov_service_data(payload: bytes) -> tuple[str, int] | None:
    """Parse Mesh Provisioning service data: Device UUID + OOB Information."""
    if len(payload) < 18:
        return None
    return payload[0:16].hex(), struct.unpack(">H", payload[16:18])[0]


def parse_proxy_service_data(payload: bytes) -> dict | None:
    """Parse Mesh Proxy service data: Network ID or Node Identity."""
    if len(payload) < 9:
        return None
    identity_type = payload[0]
    if identity_type == PROXY_ID_NETWORK:
        return {"type": PROXY_ID_NETWORK, "network_id": payload[1:9].hex()}
    if identity_type == PROXY_ID_NODE and len(payload) >= 17:
        return {"type": PROXY_ID_NODE, "hash": payload[1:9].hex(),
                "random": payload[9:17].hex()}
    return None


class MeshServiceDataAnalyzer:
    """Recover mesh state from service data — the standard-adapter path."""

    def __init__(self, net_key: bytes | None = None):
        self.net_key = net_key
        self.unprovisioned: dict[str, UnprovisionedDevice] = {}
        self.proxies: dict[str, ProxyNode] = {}
        self.findings: list[ProvisioningFinding] = []

    def parse_file(self, path: str):
        entries = load_capture(path)
        if entries is None:
            return [], []
        return self.parse_entries(entries)

    def parse_entries(self, entries: list[dict]):
        for entry in entries:
            service_data = entry.get("service_data") or {}
            if not isinstance(service_data, dict):
                continue
            mac = entry.get("mac", "")
            rssi = entry.get("rssi", 0)

            for uuid, payload_hex in service_data.items():
                try:
                    payload = bytes.fromhex(payload_hex)
                except (ValueError, AttributeError, TypeError):
                    continue

                if _service_uuid_matches(uuid, MESH_PROV_SERVICE_UUID):
                    parsed = parse_prov_service_data(payload)
                    if parsed:
                        device_uuid, oob = parsed
                        self.unprovisioned[mac] = UnprovisionedDevice(
                            mac=mac, device_uuid=device_uuid, oob_info=oob, rssi=rssi)

                elif _service_uuid_matches(uuid, MESH_PROXY_SERVICE_UUID):
                    parsed = parse_proxy_service_data(payload)
                    if parsed:
                        self.proxies[mac] = ProxyNode(
                            mac=mac, identity_type=parsed["type"],
                            network_id=parsed.get("network_id", ""),
                            node_identity=parsed.get("hash", ""), rssi=rssi)

        self._audit()
        return list(self.unprovisioned.values()), list(self.proxies.values())

    def _audit(self):
        for device in self.unprovisioned.values():
            self.findings.append(ProvisioningFinding(
                severity="HIGH" if not device.has_oob else "MEDIUM",
                title=f"Unprovisioned node advertising on {device.mac}",
                detail=(
                    f"Device UUID {device.device_uuid} is beaconing the Mesh Provisioning "
                    "Service, which means it is unprovisioned and will accept a "
                    "provisioning session from anyone in range. "
                    + ("It advertises no OOB information, so provisioning it can only "
                       "use the No OOB method and nothing would authenticate the "
                       "provisioner."
                       if not device.has_oob else
                       f"OOB available via: {', '.join(device.oob_sources)}.")
                ),
                cve="CVE-2020-26560" if not device.has_oob else "",
            ))

        for node in self.proxies.values():
            if node.identity_type == PROXY_ID_NODE:
                self.findings.append(ProvisioningFinding(
                    severity="LOW",
                    title=f"Proxy node advertising Node Identity on {node.mac}",
                    detail=(
                        "The node advertises Node Identity rather than only a Network ID. "
                        "That is intended for reconnection by a known phone, but while it "
                        "is on, the node is individually addressable to observers and "
                        "easier to track across time and place."
                    ),
                ))

        networks = {n.network_id for n in self.proxies.values() if n.network_id}
        if len(networks) > 1:
            logger.info(f"{len(networks)} distinct mesh networks in range")

        if self.net_key:
            from src.modules.mesh_crypto import k3
            expected = k3(self.net_key).hex()
            ours = [n.mac for n in self.proxies.values() if n.network_id == expected]
            if ours:
                logger.success(f"Network ID matches the supplied NetKey on: {', '.join(ours)}")
            elif networks:
                logger.warning("No node in range matches the supplied NetKey "
                               f"(expected Network ID {expected})")


def print_service_data(unprovisioned: list, proxies: list):
    from rich.table import Table
    from rich import box
    from rich.console import Console

    console = Console(emoji=False)

    if unprovisioned:
        t = Table(title="Unprovisioned Nodes (Mesh Provisioning Service 0x1827)",
                  box=box.ROUNDED, border_style="red")
        t.add_column("MAC", style="bold magenta", width=18)
        t.add_column("Device UUID", style="dim", width=34)
        t.add_column("RSSI", style="cyan", width=6)
        t.add_column("OOB available", style="yellow", width=30)
        for d in unprovisioned:
            t.add_row(d.mac, d.device_uuid, str(d.rssi),
                      ", ".join(d.oob_sources) or "[red]none[/]")
        console.print(t)

    if proxies:
        t = Table(title="Proxy Nodes (Mesh Proxy Service 0x1828)",
                  box=box.ROUNDED, border_style="cyan")
        t.add_column("MAC", style="bold magenta", width=18)
        t.add_column("Advertising", style="yellow", width=14)
        t.add_column("Network ID / Hash", style="dim", width=20)
        t.add_column("RSSI", style="cyan", width=6)
        for n in proxies:
            kind = "Network ID" if n.identity_type == PROXY_ID_NETWORK else "Node Identity"
            value = n.network_id or n.node_identity
            t.add_row(n.mac, kind, value, str(n.rssi))
        console.print(t)

    if not unprovisioned and not proxies:
        logger.info("No mesh service data in this capture")
