#!/usr/bin/env python3
import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

sys.path.insert(0, str(Path(__file__).parent))

from src.core.session            import SessionState
from src.core.plugin_registry    import PluginRegistry
from src.core.scanner            import BLEScanner, ClassicScanner, BTDevice
from src.core.enumerator         import GATTEnumerator, SDPEnumerator
from src.modules.gatt_fuzzer         import GATTFuzzer
from src.modules.sdp_enum            import SDPProbe
from src.modules.l2cap_fuzzer        import L2CAPFuzzer
from src.modules.passive_capture     import PassiveCapture
from src.modules.protocol_identifier import ProtocolIdentifier
from src.modules.mesh_frame_parser   import MeshFrameParser
from src.modules.mesh_fuzzer         import MeshFuzzer
from src.modules.cve_checker         import CVEChecker
from src.modules.report_generator    import ReportGenerator
from src.firmware_analysis.firmware_analyzer import FirmwareAnalyzer
from src.utils import logger

console = Console()

BANNER = """\
███╗   ███╗███████╗███████╗██╗  ██╗██████╗ ██████╗ ███████╗ █████╗ ██╗  ██╗███████╗██████╗
████╗ ████║██╔════╝██╔════╝██║  ██║██╔══██╗██╔══██╗██╔════╝██╔══██╗██║ ██╔╝██╔════╝██╔══██╗
██╔████╔██║█████╗  ███████╗███████║██████╔╝██████╔╝█████╗  ███████║█████╔╝ █████╗  ██████╔╝
██║╚██╔╝██║██╔══╝  ╚════██║██╔══██║██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗
██║ ╚═╝ ██║███████╗███████║██║  ██║██████╔╝██║  ██║███████╗██║  ██║██║  ██╗███████╗██║  ██║
╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝"""


def _load_session(output_dir: str) -> SessionState:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    sf = Path(output_dir) / "session.json"
    if sf.exists():
        try:
            data = json.loads(sf.read_text())
            s = SessionState(
                target_mac=data.get("target_mac"),
                adapter=data.get("adapter", "hci0"),
                scan_time=data.get("scan_time", 10.0),
                output_dir=output_dir,
            )
            s.results = data.get("results", {})
            s.mesh_protocol = data.get("mesh_protocol")
            s.firmware_path = data.get("firmware_path")
            if hasattr(s, "target_ip"):
                s.target_ip = data.get("target_ip")
            return s
        except Exception:
            pass
    return SessionState(adapter="hci0", scan_time=10.0, output_dir=output_dir)


def _save_session(session: SessionState, output_dir: str):
    sf = Path(output_dir) / "session.json"
    data = {
        "target_mac":    session.target_mac,
        "adapter":       session.adapter,
        "scan_time":     session.scan_time,
        "mesh_protocol": session.mesh_protocol,
        "firmware_path": session.firmware_path,
        "results":       session.results,
    }
    if hasattr(session, "target_ip"):
        data["target_ip"] = session.target_ip
    sf.write_text(json.dumps(data, indent=2, default=str))


def _banner():
    console.print(f"[bold cyan]{BANNER}[/]\n", highlight=False)


def _print_devices(devices: list, title: str = "Devices"):
    if not devices:
        logger.warning("No devices found")
        return
    t = Table(title=title, box=box.ROUNDED, border_style="cyan")
    t.add_column("#",     style="dim",          width=3)
    t.add_column("MAC",   style="bold magenta", width=18)
    t.add_column("Name",  style="bold white",   width=24)
    t.add_column("RSSI",  style="cyan",         width=6)
    t.add_column("Type",  style="dim",          width=8)
    t.add_column("UUIDs", style="dim",          width=40)
    for i, d in enumerate(devices, 1):
        color = "green" if d.rssi > -60 else "yellow" if d.rssi > -80 else "red"
        t.add_row(str(i), d.mac, d.name[:24],
                  f"[{color}]{d.rssi}[/]",
                  "BLE" if d.is_ble else "Classic",
                  ", ".join(d.uuids[:3])[:40])
    console.print(t)


# CLI

@click.group()
@click.option("--output",  "-o", default="./output", show_default=True,
              help="Output directory", envvar="MB_OUTPUT")
@click.option("--adapter", "-a", default="hci0", show_default=True,
              help="Bluetooth adapter", envvar="MB_ADAPTER")
@click.pass_context
def cli(ctx, output, adapter):
    """MeshBreaker v3.0 — BLE Mesh security research tool."""
    ctx.ensure_object(dict)
    ctx.obj["output"]  = output
    ctx.obj["adapter"] = adapter


# commands

@cli.command()
@click.option("--time",    "-t", "scan_time", default=10.0, show_default=True,
              help="Scan duration (seconds)")
@click.option("--classic", is_flag=True, help="Also run Bluetooth Classic scan")
@click.option("--target",  default=None, metavar="MAC",
              help="Pre-set target MAC (saves to session)")
@click.pass_context
def recon(ctx, scan_time, classic, target):
    """BLE scan + protocol fingerprint."""
    _banner()
    output  = ctx.obj["output"]
    adapter = ctx.obj["adapter"]
    session = _load_session(output)
    if target:
        session.set_target(target)

    async def _run():
        scanner = BLEScanner(adapter=adapter, timeout=scan_time)
        devices = await scanner.scan()
        _print_devices(devices, "BLE Devices")

        session.devices = [{"mac": d.mac, "name": d.name, "rssi": d.rssi,
                             "uuids": d.uuids, "manufacturer_data": {}} for d in devices]

        if classic:
            cs = ClassicScanner(timeout=scan_time)
            cdevs = cs.scan()
            _print_devices(cdevs, "Classic Devices")
            session.devices += [{"mac": d.mac, "name": d.name, "rssi": d.rssi,
                                  "uuids": d.uuids, "manufacturer_data": {}} for d in cdevs]

        if session.devices:
            ident   = ProtocolIdentifier()
            matches = ident.from_devices(session.devices)
            session.store("protocol_id", [
                {"protocol_id": m.protocol_id, "name": m.name,
                 "confidence": m.confidence, "evidence": m.evidence,
                 "cve_tags": m.cve_tags} for m in matches
            ])
            if matches:
                session.mesh_protocol = matches[0].protocol_id
                logger.info(f"Protocol: {session.mesh_protocol}")

        if devices and not session.target_mac:
            console.print("\n[dim]Hint: set target with[/]  meshbreaker set-target <MAC>")

    asyncio.run(_run())
    _save_session(session, output)


@cli.command()
@click.option("--duration", "-d", default=30.0, show_default=True,
              help="Capture duration (seconds)")
@click.option("--no-parse", is_flag=True, help="Skip topology decode after capture")
@click.pass_context
def capture(ctx, duration, no_parse):
    """Passive BLE capture + mesh beacon decode."""
    _banner()
    output  = ctx.obj["output"]
    adapter = ctx.obj["adapter"]
    session = _load_session(output)

    async def _run():
        cap = PassiveCapture(adapter=adapter, output_dir=output)
        try:
            s = await cap.capture(duration=duration, save_json=True)
        except Exception as e:
            if "No Bluetooth" in str(e) or "adapter" in str(e).lower():
                logger.error("No Bluetooth adapter found. Plug in a USB dongle.")
                return
            raise

        session.store("capture", {"file": s.pcap_file, "beacons": s.device_count,
                                   "duration": s.duration})
        if s.pcap_file:
            session.results["capture_file"] = s.pcap_file

        if s.pcap_file and not no_parse:
            topo = MeshFrameParser().parse_file(s.pcap_file)
            session.store("topology", {"nodes": len(topo.nodes), "protocol": topo.protocol,
                                        "relays": topo.relay_candidates,
                                        "proxies": topo.proxy_candidates})
            logger.info(f"Topology: {len(topo.nodes)} nodes, protocol={topo.protocol}")

    asyncio.run(_run())
    _save_session(session, output)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--no-protocol-id", is_flag=True, help="Skip protocol fingerprint from strings")
@click.pass_context
def firmware(ctx, path, no_protocol_id):
    """Analyze a firmware binary.

    PATH — path to the firmware binary (ELF, raw, or squashfs image).
    """
    _banner()
    output  = ctx.obj["output"]
    session = _load_session(output)
    session.firmware_path = path

    analyzer = FirmwareAnalyzer(path)
    info     = analyzer.analyze()
    analyzer.print_report()
    analyzer.export(output)

    session.store("firmware", {
        "path": str(info.path), "size": info.size, "arch": info.arch,
        "is_encrypted": info.is_encrypted, "is_compressed": info.is_compressed,
        "urls": info.urls, "credentials": info.credentials,
        "aes_keys":      len(info.crypto_keys.get("aes_keys", [])),
        "ble_mesh_keys": len(info.crypto_keys.get("ble_mesh_keys", [])),
    })

    if not no_protocol_id:
        ident    = ProtocolIdentifier()
        matches  = ident.from_firmware(info)
        existing = session.get("protocol_id", [])
        for m in matches:
            existing.append({"protocol_id": m.protocol_id, "name": m.name,
                              "confidence": m.confidence, "evidence": m.evidence,
                              "cve_tags": m.cve_tags, "source": "firmware"})
        session.store("protocol_id", existing)

    _save_session(session, output)


@cli.command()
@click.option("--target", "-t", default=None, metavar="MAC",
              help="Target BT MAC address")
@click.option("--no-sdp", is_flag=True, help="Skip Bluetooth Classic SDP browse")
@click.pass_context
def enumerate(ctx, target, no_sdp):
    """GATT service enumeration + SDP browse."""
    _banner()
    output  = ctx.obj["output"]
    adapter = ctx.obj["adapter"]
    session = _load_session(output)
    if target:
        session.set_target(target)
    if not session.target_mac:
        logger.error("No target MAC. Use: meshbreaker set-target AA:BB:CC:DD:EE:FF")
        sys.exit(1)

    async def _run():
        logger.info(f"GATT enumeration → {session.target_mac}")
        enum_g = GATTEnumerator(target=session.target_mac, adapter=adapter)
        try:
            gatt = await enum_g.enumerate()
        except Exception as e:
            if any(k in str(e).lower() for k in ("no bluetooth", "adapter", "connect")):
                logger.error(f"BLE error: {e}")
                return
            raise

        session.store("gatt", gatt)
        for item in gatt.get("attack_surface", []):
            logger.warning(f"  WRITE [{item['handle']:#06x}] {item['uuid']}")

        if not no_sdp:
            sdp      = SDPProbe(target=session.target_mac)
            services = sdp.browse()
            session.store("sdp", [s.__dict__ for s in services])

    asyncio.run(_run())
    _save_session(session, output)


@cli.command()
@click.option("--target",   "-t", default=None, metavar="MAC",
              help="Target BT MAC address")
@click.option("--methods",  "-m", default="mesh",
              help="Comma-separated: mesh,gatt,l2cap,sdp,all", show_default=True)
@click.option("--strategy", "-s", default="all",
              help="Mesh fuzz strategy: all|net_pdu|proxy_cfg|oversized", show_default=True)
@click.pass_context
def fuzz(ctx, target, methods, strategy):
    """Protocol-aware fuzzing (mesh/GATT/L2CAP/SDP)."""
    _banner()
    output  = ctx.obj["output"]
    adapter = ctx.obj["adapter"]
    session = _load_session(output)
    if target:
        session.set_target(target)
    if not session.target_mac:
        logger.error("No target MAC. Use: meshbreaker set-target AA:BB:CC:DD:EE:FF")
        sys.exit(1)

    method_set = {m.strip() for m in methods.split(",")}
    if "all" in method_set:
        method_set = {"mesh", "gatt", "l2cap", "sdp"}

    logger.warning(f"Fuzzing {session.target_mac} — {', '.join(method_set)}")

    async def _run():
        if "mesh" in method_set:
            fuzzer  = MeshFuzzer(target=session.target_mac, adapter=adapter)
            results = await fuzzer.fuzz_gatt_proxy(strategy=strategy)
            session.store("mesh_fuzz", [{"strategy": r.strategy, "payload": r.payload.hex(),
                                          "crashed": r.crashed, "note": r.note} for r in results])

        if "gatt" in method_set:
            gf      = GATTFuzzer(target=session.target_mac, adapter=adapter)
            results = await gf.run()
            session.store("gatt_fuzz", [{"uuid": r.uuid, "len": len(r.payload),
                                          "crashed": r.crashed} for r in results])

        if "l2cap" in method_set:
            lf      = L2CAPFuzzer(target=session.target_mac)
            results = lf.run()
            session.store("l2cap_fuzz", [{"psm": r.psm, "crashed": r.crashed,
                                           "note": r.note} for r in results])

        if "sdp" in method_set:
            probe   = SDPProbe(target=session.target_mac)
            crashed = probe.probe_sdp_bof()
            session.store("sdp_bof", {"crashed": crashed})

    asyncio.run(_run())
    _save_session(session, output)


@cli.command()
@click.option("--target", "-t", default=None, metavar="MAC",
              help="Target BT MAC address")
@click.option("--method", "-m", default="a2mp",
              type=click.Choice(["a2mp", "sdp-bof", "plugin"], case_sensitive=False),
              show_default=True)
@click.option("--plugin-name", default=None,
              help="Plugin name when using --method plugin")
@click.pass_context
def exploit(ctx, target, method, plugin_name):
    """Exploit probes: BleedingTooth A2MP check, SDP BOF, or custom plugin."""
    _banner()
    output  = ctx.obj["output"]
    adapter = ctx.obj["adapter"]
    session = _load_session(output)
    if target:
        session.set_target(target)
    if not session.target_mac:
        logger.error("No target MAC. Use: meshbreaker set-target AA:BB:CC:DD:EE:FF")
        sys.exit(1)

    registry = PluginRegistry()
    registry.load_directory(Path(__file__).parent / "src" / "plugins")

    if method == "a2mp":
        probe     = SDPProbe(target=session.target_mac)
        reachable = probe.probe_a2mp()
        session.store("a2mp", {"reachable": reachable})
        if reachable:
            logger.warning("A2MP CID 3 reachable — BleedingTooth surface (CVE-2020-12351)")
        else:
            logger.info("A2MP not reachable")

    elif method == "sdp-bof":
        probe   = SDPProbe(target=session.target_mac)
        crashed = probe.probe_sdp_bof()
        session.store("sdp_bof", {"crashed": crashed})

    elif method == "plugin":
        plugins = registry.by_category("exploit")
        if not plugins:
            logger.error("No exploit plugins in src/plugins/")
            sys.exit(1)
        if not plugin_name:
            logger.info("Available: " + ", ".join(plugins.keys()))
            logger.error("Specify with --plugin-name NAME")
            sys.exit(1)
        if plugin_name not in plugins:
            logger.error(f"Unknown plugin: {plugin_name}  (available: {', '.join(plugins.keys())})")
            sys.exit(1)
        p = plugins[plugin_name](target=session.target_mac, adapter=adapter, session=session)
        session.store(f"exploit_{plugin_name}", p.run())

    _save_session(session, output)


@cli.command("cve-check")
@click.option("--kernel", default=None, help="Kernel version, e.g. 5.4.47")
@click.option("--bluez",  default=None, help="BlueZ version, e.g. 5.72")
@click.option("--runc",   default=None, help="runc version")
@click.option("--tags",   default=None, help="Extra tags, comma-separated (wirepas,kura,mqtt…)")
@click.pass_context
def cve_check(ctx, kernel, bluez, runc, tags):
    """Match CVE database against stack versions and protocol tags."""
    _banner()
    output  = ctx.obj["output"]
    session = _load_session(output)

    checker  = CVEChecker()
    ctx_data: dict = {}

    all_tags: list = []
    for p in session.get("protocol_id", []):
        cvt = p.get("cve_tags", []) if isinstance(p, dict) else p.cve_tags
        all_tags.extend(cvt)
    ctx_data["protocol_tags"] = all_tags

    # auto-pull versions from firmware analysis if available in session
    fw = session.get("firmware", {})
    auto_kernel = fw.get("kernel_version")
    auto_bluez  = fw.get("bluez_version")
    if auto_kernel and not kernel:
        logger.info(f"Kernel version from firmware analysis: {auto_kernel}")
        ctx_data["kernel_version"] = auto_kernel
    if auto_bluez and not bluez:
        logger.info(f"BlueZ version from firmware analysis: {auto_bluez}")
        ctx_data["bluez_version"] = auto_bluez

    if kernel: ctx_data["kernel_version"] = kernel
    if bluez:  ctx_data["bluez_version"]  = bluez
    if runc:   ctx_data["runc_version"]   = runc
    if tags:
        ctx_data["custom_tags"] = [t.strip() for t in tags.split(",") if t.strip()]

    matches = checker.check_all(ctx_data)
    session.store("cve_check", [
        {"cve_id": m.cve_id, "name": m.name, "severity": m.severity,
         "cvss": m.cvss, "description": m.description,
         "matched_on": m.matched_on, "attack_vector": m.attack_vector}
        for m in matches
    ])
    _save_session(session, output)


@cli.command()
@click.option("--format", "-f", "fmt",
              type=click.Choice(["md", "html", "json", "all"], case_sensitive=False),
              default="all", show_default=True)
@click.pass_context
def report(ctx, fmt):
    """Generate Markdown, HTML, or JSON report from session data."""
    _banner()
    output  = ctx.obj["output"]
    session = _load_session(output)

    gen   = ReportGenerator(session)
    paths = gen.generate_all() if fmt == "all" else {fmt: gen.generate(fmt)}

    console.print("\n[bold green]Reports written:[/]")
    for f, p in paths.items():
        console.print(f"  [dim]{f.upper():8}[/] {p}")


@cli.command("parse-capture")
@click.argument("path", type=click.Path(exists=True))
@click.pass_context
def parse_capture(ctx, path):
    """Load an existing capture JSON file and decode topology."""
    _banner()
    output  = ctx.obj["output"]
    session = _load_session(output)

    topo = MeshFrameParser().parse_file(path)
    session.store("topology", {"nodes": len(topo.nodes), "protocol": topo.protocol,
                                "relays": topo.relay_candidates,
                                "proxies": topo.proxy_candidates})
    if topo.protocol and not session.mesh_protocol:
        session.mesh_protocol = topo.protocol

    matches = ProtocolIdentifier().from_capture_file(path)
    if matches:
        session.mesh_protocol = session.mesh_protocol or matches[0].protocol_id
        logger.info(f"Protocol: {session.mesh_protocol}")

    _save_session(session, output)


@cli.command("set-target")
@click.argument("mac")
@click.pass_context
def set_target(ctx, mac):
    """Save a target MAC to the session (persists across commands)."""
    output  = ctx.obj["output"]
    session = _load_session(output)
    session.set_target(mac)
    _save_session(session, output)
    logger.success(f"Target → {session.target_mac}")


@cli.command("set-ip")
@click.argument("ip")
@click.pass_context
def set_ip(ctx, ip):
    """Save a target IP to the session (persists across commands)."""
    output  = ctx.obj["output"]
    session = _load_session(output)
    session.target_ip = ip.strip()
    _save_session(session, output)
    logger.success(f"IP → {ip}")


@cli.command("session")
@click.option("--reset", is_flag=True, help="Clear all session state")
@click.pass_context
def show_session(ctx, reset):
    """Show current session state (target, protocol, results)."""
    output = ctx.obj["output"]
    sf     = Path(output) / "session.json"
    if reset:
        if sf.exists():
            sf.unlink()
        logger.info("Session cleared")
        return
    s = _load_session(output)
    console.print(Panel(
        f"Target MAC : [bold magenta]{s.target_mac or 'not set'}[/]\n"
        f"Target IP  : [bold]{getattr(s, 'target_ip', None) or 'not set'}[/]\n"
        f"Protocol   : [yellow]{s.mesh_protocol or 'unknown'}[/]\n"
        f"Firmware   : [dim]{s.firmware_path or 'not set'}[/]\n"
        f"Results    : {', '.join(s.results.keys()) if s.results else 'none'}",
        title="[bold cyan]Session[/]",
        border_style="cyan",
        expand=False,
    ))


if __name__ == "__main__":
    cli()
