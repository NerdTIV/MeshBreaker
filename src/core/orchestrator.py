"""
Phase orchestrator — run the whole assessment in one command.

Running seven commands by hand and remembering which order they go in is a
chore, and the order matters: fingerprinting the protocol before you fuzz
means you fuzz the right thing, and analysing firmware before the CVE check
means the versions get filled in for you.

So this chains them, carries the session state from one phase into the next,
and keeps going when a phase fails instead of dropping everything.

Phases are split into two groups:

    PASSIVE  scan, capture, enumerate, provisioning audit, DF audit,
             firmware analysis, CVE matching, report
             — nothing is written to the target

    ACTIVE   fuzzing
             — sends malformed traffic and can crash the device

Passive is the default. Active only runs when you pass --active, because a
tool that silently starts crashing a customer's lighting controller is a tool
nobody should ship.
"""

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from src.utils import logger


@dataclass
class PhaseResult:
    phase_id: int
    name: str
    status: str = "pending"
    detail: str = ""
    elapsed: float = 0.0


@dataclass
class Phase:
    phase_id: int
    name: str
    description: str
    handler: Callable
    active: bool = False
    needs_target: bool = False
    needs_capture: bool = False
    needs_firmware: bool = False


class Orchestrator:
    """Runs the phases in order against one session."""

    def __init__(self, session, adapter: str = "hci0", output_dir: str = "./output"):
        self.session = session
        self.adapter = adapter
        self.output_dir = output_dir
        self.results: list[PhaseResult] = []
        self.phases: list[Phase] = self._build_phases()

    def _build_phases(self) -> list[Phase]:
        return [
            Phase(1, "recon", "BLE scan and protocol fingerprint",
                  self._phase_recon),
            Phase(2, "capture", "Passive capture and mesh topology decode",
                  self._phase_capture),
            Phase(3, "enumerate", "GATT service enumeration",
                  self._phase_enumerate, needs_target=True),
            Phase(4, "provisioning", "Provisioning security audit (PB-ADV and PB-GATT)",
                  self._phase_provisioning),
            Phase(5, "directed-forwarding", "Mesh 1.1 Directed Forwarding exposure audit",
                  self._phase_df),
            Phase(6, "firmware", "Firmware static analysis",
                  self._phase_firmware, needs_firmware=True),
            Phase(7, "fuzz", "Protocol fuzzing",
                  self._phase_fuzz, active=True, needs_target=True),
            Phase(8, "cve-check", "CVE matching against detected versions and tags",
                  self._phase_cve),
            Phase(9, "report", "Generate Markdown, HTML and JSON reports",
                  self._phase_report),
        ]

    async def run(self, include_active: bool = False,
                  start: int = 1, stop: int = 99,
                  skip: set[str] | None = None,
                  scan_time: float = 15.0,
                  capture_duration: float = 30.0) -> list[PhaseResult]:
        skip = skip or set()
        self._scan_time = scan_time
        self._capture_duration = capture_duration

        logger.info(f"Chain start — phases {start} to {min(stop, len(self.phases))}, "
                    f"{'active included' if include_active else 'passive only'}")

        for phase in self.phases:
            if phase.phase_id < start or phase.phase_id > stop:
                continue

            result = PhaseResult(phase.phase_id, phase.name)

            if phase.name in skip:
                result.status = "skipped"
                result.detail = "skipped by user"
                self.results.append(result)
                continue

            if phase.active and not include_active:
                result.status = "skipped"
                result.detail = "active phase — rerun with --active to include"
                logger.info(f"[{phase.phase_id}] {phase.name} — skipped (active phase)")
                self.results.append(result)
                continue

            if phase.needs_target and not self.session.target_mac:
                result.status = "skipped"
                result.detail = "no target MAC set"
                logger.warning(f"[{phase.phase_id}] {phase.name} — skipped, no target")
                self.results.append(result)
                continue

            if phase.needs_firmware and not self.session.firmware_path:
                result.status = "skipped"
                result.detail = "no firmware path set"
                logger.info(f"[{phase.phase_id}] {phase.name} — skipped, no firmware")
                self.results.append(result)
                continue

            logger.banner(f"── Phase {phase.phase_id}: {phase.description} ──")
            started = time.time()
            try:
                detail = await phase.handler()
                result.status = "ok"
                result.detail = detail or ""
            except Exception as e:
                from src.core.adapter_manager import explain_ble_error

                result.status = "failed"
                hint = explain_ble_error(e)
                if hint:
                    result.detail = "Bluetooth unavailable"
                    logger.error(f"Phase {phase.phase_id} ({phase.name}): {e}")
                    for line in hint.splitlines():
                        logger.info(f"  {line}")
                else:
                    result.detail = str(e)
                    logger.error(f"Phase {phase.phase_id} ({phase.name}) failed: {e}")
            result.elapsed = time.time() - started
            self.results.append(result)

        _print_chain_summary(self.results)
        return self.results


    async def _phase_recon(self):
        from src.core.scanner import BLEScanner
        from src.modules.protocol_identifier import ProtocolIdentifier

        scanner = BLEScanner(adapter=self.adapter, timeout=self._scan_time)
        devices = await scanner.scan()
        self.session.devices = [
            {"mac": d.mac, "name": d.name, "rssi": d.rssi,
             "uuids": d.uuids, "manufacturer_data": {}}
            for d in devices
        ]

        if not devices:
            return "no devices found"

        matches = ProtocolIdentifier().from_devices(self.session.devices)
        self.session.store("protocol_id", [
            {"protocol_id": m.protocol_id, "name": m.name, "confidence": m.confidence,
             "evidence": m.evidence, "cve_tags": m.cve_tags}
            for m in matches
        ])
        if matches:
            self.session.mesh_protocol = matches[0].protocol_id

        if not self.session.target_mac and matches and matches[0].confidence >= 60:
            mesh_devices = [d for d in devices if d.uuids]
            if mesh_devices:
                self.session.set_target(mesh_devices[0].mac)
                logger.warning(f"Auto-selected target: {self.session.target_mac} "
                               f"(protocol {matches[0].name}, {matches[0].confidence}%)")

        return f"{len(devices)} devices, protocol {self.session.mesh_protocol or 'unknown'}"

    async def _phase_capture(self):
        from src.modules.passive_capture import PassiveCapture
        from src.modules.mesh_frame_parser import MeshFrameParser

        cap = PassiveCapture(adapter=self.adapter, output_dir=self.output_dir)
        result = await cap.capture(duration=self._capture_duration, save_json=True)
        self.session.store("capture", {
            "file": result.pcap_file, "beacons": result.device_count,
            "duration": result.duration,
        })
        if not result.pcap_file:
            return "capture produced no file"

        self.session.results["capture_file"] = result.pcap_file
        topo = MeshFrameParser().parse_file(result.pcap_file)
        self.session.store("topology", {
            "nodes": len(topo.nodes), "protocol": topo.protocol,
            "relays": topo.relay_candidates, "proxies": topo.proxy_candidates,
        })
        return f"{len(topo.nodes)} nodes mapped"

    async def _phase_enumerate(self):
        from src.core.enumerator import GATTEnumerator

        enumerator = GATTEnumerator(target=self.session.target_mac, adapter=self.adapter)
        gatt = await enumerator.enumerate()
        self.session.store("gatt", gatt)
        surface = gatt.get("attack_surface", [])
        return f"{len(gatt.get('services', []))} services, {len(surface)} writable chars"

    async def _phase_provisioning(self):
        from src.modules.provisioning import (
            MeshServiceDataAnalyzer, ProvisioningAnalyzer, print_service_data,
            print_sessions, probe_pb_gatt,
        )

        detail_parts = []

        capture_file = self.session.results.get("capture_file")
        if capture_file and Path(capture_file).exists():
            analyzer = ProvisioningAnalyzer()
            sessions = analyzer.parse_file(capture_file)
            print_sessions(sessions, analyzer.findings)

            service = MeshServiceDataAnalyzer()
            unprovisioned, proxies = service.parse_file(capture_file)
            print_service_data(unprovisioned, proxies)
            for f in service.findings:
                logger.warning(f"{f.severity}: {f.title}")

            self.session.store("provisioning_capture", {
                "sessions": len(sessions),
                "pb_adv_visible": not analyzer.mesh_blind,
                "unprovisioned_nodes": [
                    {"mac": d.mac, "device_uuid": d.device_uuid,
                     "oob_info": d.oob_info, "oob_sources": d.oob_sources}
                    for d in unprovisioned
                ],
                "proxy_nodes": [
                    {"mac": n.mac, "network_id": n.network_id,
                     "node_identity": n.node_identity} for n in proxies
                ],
                "findings": [
                    {"severity": f.severity, "title": f.title,
                     "detail": f.detail, "cve": f.cve}
                    for f in analyzer.findings + service.findings
                ],
            })
            if sessions:
                detail_parts.append(f"{len(sessions)} PB-ADV sessions")
            if unprovisioned:
                detail_parts.append(f"{len(unprovisioned)} unprovisioned")
            if proxies:
                detail_parts.append(f"{len(proxies)} proxies")
        else:
            logger.info("No capture file — skipping capture analysis")

        if self.session.target_mac:
            probe = await probe_pb_gatt(self.session.target_mac, self.adapter)
            self.session.store("provisioning_gatt", probe)
            if probe.get("provisioning_service"):
                detail_parts.append("PB-GATT exposed")

        return ", ".join(detail_parts) or "nothing to analyse"

    async def _phase_df(self):
        from src.modules.directed_forwarding import (
            DFAudit, detect_from_capture, detect_from_firmware, print_audit,
        )

        audit = DFAudit()

        firmware_info = getattr(self, "_firmware_info", None)
        if firmware_info is not None:
            audit = detect_from_firmware(firmware_info)

        capture_file = self.session.results.get("capture_file")
        if not audit.df_present and capture_file and Path(capture_file).exists():
            audit = detect_from_capture(capture_file)

        print_audit(audit)
        self.session.store("directed_forwarding", {
            "present": audit.df_present,
            "confidence": audit.df_confidence,
            "evidence": audit.evidence,
            "models": {f"0x{k:04X}": v for k, v in audit.models_found.items()},
            "findings": [
                {"severity": f.severity, "title": f.title,
                 "detail": f.detail, "reference": f.reference}
                for f in audit.findings
            ],
        })
        return "present" if audit.df_present else "not detected"

    async def _phase_firmware(self):
        from src.firmware_analysis.firmware_analyzer import FirmwareAnalyzer
        from src.modules.protocol_identifier import ProtocolIdentifier

        analyzer = FirmwareAnalyzer(self.session.firmware_path)
        info = analyzer.analyze()
        analyzer.print_report()
        analyzer.export(self.output_dir)

        self._firmware_info = info

        self.session.store("firmware", {
            "path": str(info.path), "size": info.size, "arch": info.arch,
            "rtos": info.rtos, "soc": info.soc,
            "kernel_version": info.kernel_version,
            "bluez_version": info.bluez_version,
            "is_encrypted": info.is_encrypted, "is_compressed": info.is_compressed,
            "urls": info.urls, "credentials": info.credentials,
            "aes_keys": len(info.crypto_keys.get("aes_keys", [])),
            "ble_mesh_keys": len(info.crypto_keys.get("ble_mesh_keys", [])),
        })

        matches = ProtocolIdentifier().from_firmware(info)
        existing = self.session.get("protocol_id", [])
        for m in matches:
            existing.append({"protocol_id": m.protocol_id, "name": m.name,
                             "confidence": m.confidence, "evidence": m.evidence,
                             "cve_tags": m.cve_tags, "source": "firmware"})
        self.session.store("protocol_id", existing)
        return f"{info.arch or 'unknown arch'}, {info.rtos or 'unknown RTOS'}"

    async def _phase_fuzz(self):
        from src.modules.mesh_fuzzer import MeshFuzzer

        fuzzer = MeshFuzzer(target=self.session.target_mac, adapter=self.adapter)
        results = await fuzzer.fuzz_gatt_proxy(strategy="all")
        crashes = [r for r in results if r.crashed]
        self.session.store("mesh_fuzz", [
            {"strategy": r.strategy, "payload": r.payload.hex(),
             "crashed": r.crashed, "note": r.note}
            for r in results
        ])
        return f"{len(results)} payloads, {len(crashes)} crashes"

    async def _phase_cve(self):
        from src.modules.cve_checker import CVEChecker

        ctx: dict = {}
        tags: list[str] = []
        for entry in self.session.get("protocol_id", []):
            tags.extend(entry.get("cve_tags", []) if isinstance(entry, dict) else entry.cve_tags)

        prov = self.session.get("provisioning_capture", {})
        if prov.get("findings"):
            tags.append("mesh_provisioning")
        if self.session.get("directed_forwarding", {}).get("present"):
            tags.append("mesh_df")

        ctx["protocol_tags"] = tags

        firmware = self.session.get("firmware", {})
        if firmware.get("kernel_version"):
            ctx["kernel_version"] = firmware["kernel_version"]
            logger.info(f"Kernel from firmware: {firmware['kernel_version']}")
        if firmware.get("bluez_version"):
            ctx["bluez_version"] = firmware["bluez_version"]
            logger.info(f"BlueZ from firmware: {firmware['bluez_version']}")

        matches = CVEChecker().check_all(ctx)
        self.session.store("cve_check", [
            {"cve_id": m.cve_id, "name": m.name, "severity": m.severity,
             "cvss": m.cvss, "description": m.description,
             "matched_on": m.matched_on, "attack_vector": m.attack_vector}
            for m in matches
        ])
        return f"{len(matches)} CVE matches"

    async def _phase_report(self):
        from src.modules.report_generator import ReportGenerator

        paths = ReportGenerator(self.session).generate_all(self.output_dir)
        return f"{len(paths)} reports written"


def _print_chain_summary(results: list[PhaseResult]):
    from rich.table import Table
    from rich import box
    from rich.console import Console

    console = Console()
    colors = {"ok": "green", "failed": "red", "skipped": "dim", "pending": "dim"}

    t = Table(title="Chain Summary", box=box.ROUNDED, border_style="cyan")
    t.add_column("#", style="dim", width=3)
    t.add_column("Phase", style="bold white", width=22)
    t.add_column("Status", width=9)
    t.add_column("Time", style="dim", width=8)
    t.add_column("Detail", style="cyan", width=44)

    for r in results:
        color = colors.get(r.status, "white")
        t.add_row(str(r.phase_id), r.name,
                  f"[{color}]{r.status}[/]",
                  f"{r.elapsed:.1f}s" if r.elapsed else "—",
                  r.detail[:44])
    console.print(t)

    ok = len([r for r in results if r.status == "ok"])
    failed = [r for r in results if r.status == "failed"]
    logger.success(f"{ok}/{len(results)} phases completed")
    for r in failed:
        logger.error(f"  {r.name}: {r.detail}")
