"""
Directed Forwarding audit (Bluetooth Mesh Protocol 1.1).

Classic Bluetooth Mesh routes by "managed flooding": every relay rebroadcasts
every message. Crude, but there is no routing state for an attacker to lie
about. Mesh Protocol 1.1 added **Directed Forwarding**, which builds real
routes:

    Path Origin (PO)  --PATH_REQUEST-->  ...relays...  --> Path Target (PT)
                      <--PATH_REPLY----
    then only the nodes on that path forward traffic for it.

That saves bandwidth and battery, and it introduces a routing control plane —
which is new attack surface. Nodes now accept messages that change who
forwards what. Feed them wrong path information and traffic for a chosen
destination gets routed into a hole and dropped.

This is the surface studied in:

    "Tous les chemins mènent à DROP : une évaluation de la sécurité d'un
     mécanisme de routage du Bluetooth Mesh"
    Elies Tali, Romain Cayre, Vincent Nicomette, Guillaume Auriol
    LAAS-CNRS, SSTIC 2025
    https://www.sstic.org/2025/presentation/

Be clear about what a passive listener can and cannot do here. Directed
Forwarding control messages travel inside encrypted Network PDUs, so **you
cannot read PATH_REQUEST opcodes off the air without the NetKey.** Anyone who
tells you otherwise is selling something.

So this module audits *exposure* rather than decoding path traffic:

    - is Directed Forwarding present at all (model IDs, firmware strings)
    - is the Directed Forwarding Configuration Server reachable
    - which 1.1 hardening features are missing alongside it

and, when you legitimately hold the NetKey for a network you are testing, it
decodes the control opcodes for you.
"""

import struct
from dataclasses import dataclass, field
from pathlib import Path

from src.utils import logger
from src.utils.capture_io import (decode_frames, load_capture,
                                  profile_capture, warn_if_mesh_blind)

MESH_11_MODELS = {
    0x0007: "Directed Forwarding Configuration Server",
    0x0008: "Directed Forwarding Configuration Client",
    0x0009: "Bridge Configuration Server",
    0x000A: "Bridge Configuration Client",
    0x000B: "Private Beacon Server",
    0x000C: "Private Beacon Client",
    0x000D: "On-Demand Private Proxy Server",
    0x000E: "On-Demand Private Proxy Client",
    0x000F: "SAR Configuration Server",
    0x0010: "SAR Configuration Client",
    0x0011: "Opcodes Aggregator Server",
    0x0012: "Opcodes Aggregator Client",
    0x0013: "Large Composition Data Server",
    0x0014: "Large Composition Data Client",
    0x0015: "Solicitation PDU RPL Configuration Server",
    0x0016: "Solicitation PDU RPL Configuration Client",
}

DF_MODELS = (0x0007, 0x0008)

DF_CONTROL_OPCODES = {
    0x01: "PATH_REQUEST",
    0x02: "PATH_REPLY",
    0x03: "PATH_CONFIRMATION",
    0x04: "PATH_ECHO_REQUEST",
    0x05: "PATH_ECHO_REPLY",
    0x06: "DEPENDENT_NODE_UPDATE",
    0x07: "PATH_REQUEST_SOLICITATION",
}

DF_FIRMWARE_STRINGS = (
    "directed_forwarding", "bt_mesh_df", "bt_mesh_dfw", "df_srv", "df_cli",
    "path_origin", "path_target", "path_request", "path_reply",
    "forwarding_table", "directed_publish", "CONFIG_BT_MESH_DF_SRV",
)

MESH_11_FIRMWARE_STRINGS = (
    "private_beacon", "on_demand_proxy", "sar_config", "opcodes_aggregator",
    "large_comp_data", "solicitation_pdu",
)


@dataclass
class DFFinding:
    severity: str
    title: str
    detail: str
    reference: str = ""


@dataclass
class DFAudit:
    """What we managed to establish about Directed Forwarding on this target."""

    df_present: bool = False
    df_confidence: int = 0
    evidence: list[str] = field(default_factory=list)
    models_found: dict[int, str] = field(default_factory=dict)
    mesh_11_features: list[str] = field(default_factory=list)
    findings: list[DFFinding] = field(default_factory=list)


def detect_from_firmware(firmware_info) -> DFAudit:
    """Look for Directed Forwarding in an analysed firmware binary.

    Takes the FirmwareInfo produced by FirmwareAnalyzer. Cheap and reliable:
    if the stack was compiled with DF, the symbols are usually in there.
    """
    audit = DFAudit()
    strings = [s.lower() for s in getattr(firmware_info, "strings", [])]
    if not strings:
        logger.warning("Firmware has no extracted strings — run 'firmware' first")
        return audit

    for needle in DF_FIRMWARE_STRINGS:
        hits = [s for s in strings if needle.lower() in s]
        if hits:
            audit.df_confidence = min(100, audit.df_confidence + 20)
            audit.evidence.append(f"firmware string '{needle}'")

    for needle in MESH_11_FIRMWARE_STRINGS:
        if any(needle.lower() in s for s in strings):
            audit.mesh_11_features.append(needle)

    audit.df_present = audit.df_confidence >= 40
    if audit.df_present:
        logger.warning(f"Directed Forwarding found in firmware ({audit.df_confidence}% confidence)")
        for e in audit.evidence:
            logger.info(f"  {e}")
    else:
        logger.info("No Directed Forwarding symbols in firmware")

    _audit_exposure(audit)
    return audit


def detect_from_composition_data(composition_hex: str) -> DFAudit:
    """Look for the Directed Forwarding models in a Composition Data Page 0 blob.

    Composition Data is what a node returns when asked what models it runs.
    Reading it normally needs the DevKey, so this path is for when you already
    have it (your own test network, or a node you provisioned yourself).

    Page 0 layout after the 10-byte header, per element:
        Loc (2) NumS (1) NumV (1) then NumS SIG model IDs (2 bytes each)
        then NumV vendor model IDs (4 bytes each).
    """
    audit = DFAudit()
    try:
        data = bytes.fromhex(composition_hex.replace(" ", ""))
    except ValueError:
        logger.error("Composition data is not valid hex")
        return audit

    if len(data) < 10:
        logger.error("Composition data too short for a Page 0 header")
        return audit

    offset = 10
    element = 0
    while offset + 4 <= len(data):
        num_sig = data[offset + 2]
        num_vendor = data[offset + 3]
        offset += 4

        for _ in range(num_sig):
            if offset + 2 > len(data):
                break
            model_id = struct.unpack("<H", data[offset:offset + 2])[0]
            offset += 2
            if model_id in MESH_11_MODELS:
                audit.models_found[model_id] = MESH_11_MODELS[model_id]
                if model_id in DF_MODELS:
                    audit.df_present = True
                    audit.df_confidence = 100
                    audit.evidence.append(
                        f"element {element} runs {MESH_11_MODELS[model_id]} "
                        f"(model 0x{model_id:04X})")
                else:
                    audit.mesh_11_features.append(MESH_11_MODELS[model_id])

        offset += num_vendor * 4
        element += 1

    if audit.df_present:
        logger.warning("Directed Forwarding Configuration model present — DF is in use")
        for e in audit.evidence:
            logger.info(f"  {e}")
    else:
        logger.info("No Directed Forwarding models in composition data")

    _audit_exposure(audit)
    return audit


def detect_from_capture(path: str) -> DFAudit:
    """Heuristic pass over a passive capture.

    We cannot read control opcodes without the NetKey, so this only looks for
    the coarse signal: Mesh 1.1 nodes and the traffic shape that route
    maintenance produces (steady low-rate control chatter between a small
    set of nodes rather than uniform flooding).
    """
    audit = DFAudit()
    entries = load_capture(path)
    if entries is None:
        return audit

    profile = profile_capture(entries)
    if warn_if_mesh_blind(profile, "mesh network PDUs"):
        return audit

    frames, _ = decode_frames(entries)

    ctl_frames = 0
    mesh_frames = 0
    for _entry, raw in frames:
        if len(raw) < 3 or raw[0] != 0x2A:
            continue
        mesh_frames += 1
        if raw[2] & 0x80:
            ctl_frames += 1

    if mesh_frames == 0:
        logger.info("No mesh network PDUs in this capture")
        return audit

    ratio = ctl_frames / mesh_frames
    logger.info(f"Mesh frames: {mesh_frames}, control frames: {ctl_frames} ({ratio:.0%})")

    if ctl_frames and ratio > 0.15:
        audit.df_confidence = 40
        audit.evidence.append(
            f"{ratio:.0%} of mesh frames are control PDUs — consistent with "
            "path maintenance traffic")
        logger.warning("Elevated control-PDU ratio — Directed Forwarding may be active")

    logger.info("Opcode-level decode needs the NetKey (control PDUs are encrypted)")
    _audit_exposure(audit)
    return audit


def decode_control_pdu(plaintext: bytes) -> dict | None:
    """Decode a *decrypted* network control PDU.

    Only usable once you hold the NetKey for the network you are testing and
    have decrypted the Network PDU yourself. Input is the plaintext transport
    PDU: first byte carries the 7-bit control opcode.
    """
    if not plaintext:
        return None
    opcode = plaintext[0] & 0x7F
    name = DF_CONTROL_OPCODES.get(opcode)
    if name is None:
        return {"opcode": opcode, "name": f"Unknown/other control 0x{opcode:02X}",
                "is_df": False, "params": plaintext[1:].hex()}

    out = {"opcode": opcode, "name": name, "is_df": True,
           "params": plaintext[1:].hex()}

    body = plaintext[1:]
    if name == "PATH_REQUEST" and len(body) >= 5:
        out["path_origin"] = struct.unpack(">H", body[3:5])[0]
    elif name == "PATH_REPLY" and len(body) >= 3:
        out["path_origin"] = struct.unpack(">H", body[1:3])[0]
    return out


def _audit_exposure(audit: DFAudit):
    """Attach findings based on what the detection turned up."""
    if audit.df_present:
        audit.findings.append(DFFinding(
            severity="MEDIUM",
            title="Directed Forwarding is enabled",
            detail=(
                "The node participates in Mesh 1.1 Directed Forwarding, so it maintains "
                "routing state that other nodes can influence through path discovery. "
                "A node holding a valid NetKey — including a compromised or salvaged "
                "device — can inject path control messages to make itself the forwarder "
                "for a chosen destination and then drop that traffic. Managed flooding "
                "has no equivalent state to poison."
            ),
            reference="SSTIC 2025 — Tali, Cayre, Nicomette, Auriol",
        ))

        if 0x0007 in audit.models_found:
            audit.findings.append(DFFinding(
                severity="HIGH",
                title="Directed Forwarding Configuration Server is reachable",
                detail=(
                    "This model accepts configuration of the forwarding table. Anyone "
                    "who obtains the DevKey for this node can change which paths it "
                    "honours, including removing them. Confirm the DevKey has never "
                    "been shipped in firmware or reused across the fleet."
                ),
            ))

        if "private_beacon" not in " ".join(audit.mesh_11_features).lower():
            audit.findings.append(DFFinding(
                severity="LOW",
                title="Directed Forwarding without Private Beacons",
                detail=(
                    "The stack runs 1.1 routing but does not appear to use Private "
                    "Beacons, so the network still leaks a stable identifier that lets "
                    "an observer track nodes and map the topology before attacking a "
                    "path. Enable Private Beacons alongside Directed Forwarding."
                ),
            ))


def print_audit(audit: DFAudit):
    from rich.table import Table
    from rich import box
    from rich.console import Console

    console = Console()

    t = Table(title="Directed Forwarding Audit", box=box.ROUNDED, border_style="cyan")
    t.add_column("Field", style="bold white", width=22)
    t.add_column("Value", style="cyan")
    t.add_row("Directed Forwarding", "[bold red]present[/]" if audit.df_present else "not detected")
    t.add_row("Confidence", f"{audit.df_confidence}%")
    t.add_row("Mesh 1.1 models", str(len(audit.models_found)))
    console.print(t)

    if audit.models_found:
        t = Table(title="Mesh 1.1 Models Found", box=box.SIMPLE, border_style="magenta")
        t.add_column("Model ID", style="bold magenta", width=10)
        t.add_column("Name", style="white")
        for mid, name in sorted(audit.models_found.items()):
            t.add_row(f"0x{mid:04X}", name)
        console.print(t)

    for e in audit.evidence:
        logger.info(f"Evidence: {e}")

    if audit.findings:
        colors = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "green"}
        for f in audit.findings:
            color = colors.get(f.severity, "white")
            console.print(f"\n[{color}][{f.severity}][/] [bold]{f.title}[/]")
            console.print(f"  {f.detail}")
            if f.reference:
                console.print(f"  [dim]Reference: {f.reference}[/]")
