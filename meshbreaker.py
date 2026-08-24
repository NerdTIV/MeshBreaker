#!/usr/bin/env python3
import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

sys.path.insert(0, str(Path(__file__).parent))

from src.core.session            import SessionState
from src.core.plugin_registry    import PluginRegistry
from src.core.scanner            import BLEScanner, ClassicScanner
from src.core.enumerator         import GATTEnumerator
from src.core.adapter_manager    import scan_hardware, list_adapters, report_ble_error
from src.core.orchestrator       import Orchestrator
from src.modules.gatt_fuzzer         import GATTFuzzer
from src.modules.sdp_enum            import SDPProbe
from src.modules.l2cap_fuzzer        import L2CAPFuzzer
from src.modules.passive_capture     import PassiveCapture
from src.modules.protocol_identifier import ProtocolIdentifier
from src.modules.mesh_frame_parser   import MeshFrameParser
from src.modules.mesh_fuzzer         import MeshFuzzer
from src.modules.cve_checker         import CVEChecker
from src.modules.report_generator    import ReportGenerator
from src.modules import channel_map
from src.modules import provisioning as prov
from src.modules import directed_forwarding as df_mod
from src.modules import sniffer as sniffer_mod
from src.firmware_analysis.firmware_analyzer import FirmwareAnalyzer
from src.utils import logger

console = Console(emoji=False)

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
            s.devices = data.get("devices", [])
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
        "devices":       session.devices,
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


@cli.command()
@click.option("--time",    "-t", "scan_time", default=10.0, show_default=True,
              help="Scan duration (seconds)")
@click.option("--classic", is_flag=True, help="Also run Bluetooth Classic scan")
@click.option("--target",  default=None, metavar="MAC",
              help="Pre-set target MAC (saves to session)")
@click.option("--fuzzable", default=None, metavar="MAC[,MAC...]",
              help="After the scan, connect to these devices and report what "
                   "a fuzzer could write to. Use 'scanned' for every device "
                   "the scan found.")
@click.pass_context
def recon(ctx, scan_time, classic, target, fuzzable):
    """BLE scan + protocol fingerprint.

    \b
    --fuzzable connects to the devices you name and counts their writable
    characteristics, which no scan can tell you: nothing in an advertisement
    says whether a device accepts connections, and characteristics only exist
    once service discovery has run.

    \b
    It never picks targets on its own. Everything in range belongs to
    someone, and connecting to a stranger's device is not reconnaissance.

    \b
    Examples:
      meshbreaker recon --fuzzable 72:12:E9:5E:DD:88
      meshbreaker recon --fuzzable scanned      (only in a lab you own)
    """
    _banner()
    output  = ctx.obj["output"]
    adapter = ctx.obj["adapter"]
    session = _load_session(output)
    if target:
        session.set_target(target)

    async def _run():
        scanner = BLEScanner(adapter=adapter, timeout=scan_time)
        try:
            devices = await scanner.scan()
        except Exception as e:
            if not report_ble_error(e):
                raise
            return
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

        if fuzzable:
            await _probe_fuzzable(fuzzable, devices, adapter, session)

        if devices and not session.target_mac:
            console.print("\n[dim]Hint: set target with[/]  meshbreaker set-target <MAC>")

    asyncio.run(_run())
    _save_session(session, output)


async def _probe_fuzzable(selector: str, devices, adapter: str, session):
    """Connect to the named devices and report their writable surface."""
    from src.core.enumerator import probe_writable

    if selector.strip().lower() == "scanned":
        macs = [d.mac for d in devices]
        logger.warning(f"Probing all {len(macs)} scanned device(s) — only do "
                       f"this on hardware you are authorised to touch")
    else:
        macs = [m.strip().upper() for m in selector.split(",") if m.strip()]

    if not macs:
        logger.error("--fuzzable needs at least one MAC, or the word 'scanned'")
        return

    results = []
    for mac in macs:
        logger.info(f"Probing {mac}…")
        result = await probe_writable(mac, adapter=adapter)
        results.append(result)
        if not result.connected:
            logger.warning(f"  not connectable — {result.error}")
        elif result.writable:
            logger.success(f"  {len(result.writable)} writable characteristic(s), "
                           f"MTU {result.mtu}")
        else:
            logger.info(f"  connected, {result.services} service(s), "
                        f"nothing writable")

    _print_probe_results(results)
    session.store("fuzzable", [
        {"mac": r.mac, "connected": r.connected, "mtu": r.mtu,
         "services": r.services, "characteristics": r.characteristics,
         "writable": r.writable, "error": r.error}
        for r in results
    ])

    best = [r for r in results if r.fuzzable]
    if best:
        logger.info(f"Fuzz one with:  meshbreaker fuzz -m gatt -t {best[0].mac}")


def _print_probe_results(results):
    t = Table(title="Fuzzable Surface", box=box.ROUNDED, border_style="magenta")
    t.add_column("MAC", style="bold white", width=19)
    t.add_column("Connect", width=9)
    t.add_column("MTU", style="cyan", width=5)
    t.add_column("Services", style="dim", width=9)
    t.add_column("Writable", width=9)
    t.add_column("Note", style="dim", width=28)
    for r in results:
        if not r.connected:
            t.add_row(r.mac, "[red]no[/]", "—", "—", "—", r.error[:28])
            continue
        writable = f"[yellow]{len(r.writable)}[/]" if r.writable else "0"
        note = "fuzz target" if r.writable else "no write surface"
        t.add_row(r.mac, "[green]yes[/]", str(r.mtu), str(r.services),
                  writable, note)
    console.print(t)


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
            if not report_ble_error(e):
                raise
            return

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


@cli.command("enumerate")
@click.option("--target", "-t", default=None, metavar="MAC",
              help="Target BT MAC address")
@click.option("--no-sdp", is_flag=True, help="Skip Bluetooth Classic SDP browse")
@click.pass_context
def enumerate_cmd(ctx, target, no_sdp):
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
            if not report_ble_error(e):
                if "connect" in str(e).lower():
                    logger.error(f"Could not connect to {session.target_mac}: {e}")
                    return
                raise
            return

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
@click.option("--type", "type_alias", default=None,
              help="Alias for --methods (kept so older docs and scripts keep working)")
@click.option("--strategy", "-s", default="all",
              help="Mesh fuzz strategy: all|net_pdu|proxy_cfg|oversized", show_default=True)
@click.option("--psm", default=None,
              help="Comma-separated L2CAP PSMs to fuzz (default: common ones)")
@click.pass_context
def fuzz(ctx, target, methods, type_alias, strategy, psm):
    """Protocol-aware fuzzing (mesh/GATT/L2CAP/SDP).

    \b
    Examples:
      meshbreaker fuzz -m gatt
      meshbreaker fuzz -m l2cap --psm 1,3,5,7
      meshbreaker fuzz -m all -t AA:BB:CC:DD:EE:FF
    """
    _banner()
    output  = ctx.obj["output"]
    adapter = ctx.obj["adapter"]
    session = _load_session(output)
    if target:
        session.set_target(target)
    if not session.target_mac:
        logger.error("No target MAC. Use: meshbreaker set-target AA:BB:CC:DD:EE:FF")
        sys.exit(1)

    if type_alias:
        methods = type_alias

    psm_list = None
    if psm:
        try:
            psm_list = [int(p.strip()) for p in psm.split(",") if p.strip()]
        except ValueError:
            logger.error(f"Invalid --psm value: {psm} (expected numbers, e.g. 1,3,5,7)")
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
            results = lf.run(psms=psm_list)
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
@click.option("--netkey", default=None, metavar="HEX",
              help="16-byte mesh NetKey (hex) for plugins that need one")
@click.option("--iv-index", default=None, metavar="N",
              help="Mesh IV index, e.g. 0x12345678")
@click.option("--opt", "opts", multiple=True, metavar="KEY=VALUE",
              help="Extra plugin option, repeatable (e.g. --opt mode=path_request)")
@click.option("--list-plugins", is_flag=True, help="List loaded plugins and exit")
@click.pass_context
def exploit(ctx, target, method, plugin_name, netkey, iv_index, opts, list_plugins):
    """Exploit probes: BleedingTooth A2MP check, SDP BOF, or custom plugin.

    \b
    Examples:
      meshbreaker exploit --list-plugins
      meshbreaker exploit -m a2mp -t AA:BB:CC:DD:EE:FF
      meshbreaker exploit -m plugin --plugin-name df_path_inject \\
          --netkey 7dd7364cd842ad18c17c2b820c84c3d6 \\
          --iv-index 0x12345678 --opt mode=path_request --opt dry_run=true
    """
    _banner()
    output  = ctx.obj["output"]
    adapter = ctx.obj["adapter"]
    session = _load_session(output)
    if target:
        session.set_target(target)

    registry = PluginRegistry()
    registry.load_directory(Path(__file__).parent / "src" / "plugins")

    if list_plugins:
        loaded = registry.all()
        if not loaded:
            logger.error("No plugins loaded from src/plugins/")
            return
        t = Table(title=f"Plugins ({len(loaded)})", box=box.ROUNDED, border_style="cyan")
        t.add_column("Name",        style="bold white", width=22)
        t.add_column("Category",    style="yellow",     width=10)
        t.add_column("Ver",         style="dim",        width=5)
        t.add_column("Description", style="cyan",       width=48)
        for name, cls in sorted(loaded.items()):
            t.add_row(name, cls.meta.category, cls.meta.version, cls.meta.description)
        console.print(t)
        return

    if method != "plugin" and not session.target_mac:
        logger.error("No target MAC. Use: meshbreaker set-target AA:BB:CC:DD:EE:FF")
        sys.exit(1)

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

        config: dict = {}
        if netkey:
            config["netkey"] = netkey
        if iv_index:
            config["iv_index"] = iv_index
        for item in opts:
            if "=" not in item:
                logger.error(f"--opt must be KEY=VALUE, got: {item}")
                sys.exit(1)
            key, value = item.split("=", 1)
            config[key.strip()] = value.strip()

        p = plugins[plugin_name](target=session.target_mac, adapter=adapter,
                                 session=session, config=config)
        try:
            session.store(f"exploit_{plugin_name}", p.run())
        except ValueError as e:
            logger.error(str(e))
            sys.exit(1)

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


@cli.command()
@click.option("--target",   "-t", default=None, metavar="MAC", help="Target BT MAC address")
@click.option("--firmware", "fw_path", default=None, type=click.Path(exists=True),
              help="Firmware binary to analyze as part of the chain")
@click.option("--active",   is_flag=True,
              help="Include active phases (fuzzing). Off by default — fuzzing can crash the target.")
@click.option("--from",     "start", default=1, show_default=True, help="First phase to run")
@click.option("--to",       "stop",  default=99, help="Last phase to run")
@click.option("--skip",     default=None, help="Comma-separated phase names to skip")
@click.option("--time",     "-s", "scan_time", default=15.0, show_default=True,
              help="Recon scan duration (seconds)")
@click.option("--duration", "-d", default=30.0, show_default=True,
              help="Passive capture duration (seconds)")
@click.pass_context
def auto(ctx, target, fw_path, active, start, stop, skip, scan_time, duration):
    """Run the whole assessment chain in one go.

    \b
    Phases:
      1 recon               BLE scan + protocol fingerprint
      2 capture             passive capture + topology
      3 enumerate           GATT services
      4 provisioning        PB-ADV / PB-GATT security audit
      5 directed-forwarding Mesh 1.1 routing exposure
      6 firmware            static analysis (needs --firmware)
      7 fuzz                ACTIVE — only with --active
      8 cve-check           CVE matching
      9 report              md + html + json

    \b
    Examples:
      meshbreaker auto
      meshbreaker auto -t AA:BB:CC:DD:EE:FF --firmware fw.bin
      meshbreaker auto --active --skip capture,fuzz
      meshbreaker auto --from 4 --to 5
    """
    _banner()
    output  = ctx.obj["output"]
    adapter = ctx.obj["adapter"]
    session = _load_session(output)

    if target:
        session.set_target(target)
    if fw_path:
        session.firmware_path = fw_path

    if active:
        logger.warning("Active phases enabled — fuzzing may crash or reset the target")
        logger.warning("Only continue if you are authorized to test this device")

    skip_set = {s.strip() for s in skip.split(",")} if skip else set()
    orch = Orchestrator(session, adapter=adapter, output_dir=output)

    asyncio.run(orch.run(
        include_active=active, start=start, stop=stop, skip=skip_set,
        scan_time=scan_time, capture_duration=duration,
    ))
    _save_session(session, output)


@cli.command()
@click.pass_context
def setup(ctx):
    """Show BLE adapters, sniffer hardware, and which tools are installed."""
    _banner()
    report = scan_hardware()
    from src.core.adapter_manager import print_report
    print_report(report)


@cli.command()
@click.option("--connect-ind", default=None, metavar="HEX",
              help="Parse a captured CONNECT_IND payload (hex) and predict the hop sequence")
@click.option("--events", default=20, show_default=True,
              help="How many future connection events to predict")
@click.option("--algorithm", type=click.Choice(["1", "2"]), default="1", show_default=True,
              help="Hop algorithm: 1 = legacy, 2 = Bluetooth 5.0+")
@click.pass_context
def channels(ctx, connect_ind, events, algorithm):
    """BLE channel reference, and hop prediction from a CONNECT_IND.

    \b
    BLE has 40 channels of 2 MHz each (40 x 2 = 80 MHz of spectrum — that is
    where the "80" comes from, it is not a channel count). 37 carry data,
    3 carry advertising.

    \b
    Examples:
      meshbreaker channels
      meshbreaker channels --connect-ind <68 hex chars> --events 30
      meshbreaker channels --connect-ind <hex> --algorithm 2
    """
    _banner()
    if not connect_ind:
        channel_map.print_channel_table()
        logger.info("Pass --connect-ind <hex> to predict a connection's hop sequence")
        return

    output  = ctx.obj["output"]
    session = _load_session(output)
    result = sniffer_mod.follow_from_connect_ind(
        connect_ind, events=events, algorithm=int(algorithm))
    if "error" not in result:
        session.store("connection_follow", result)
        _save_session(session, output)


@cli.command()
@click.option("--adapters", default=None,
              help="Comma-separated adapters, e.g. hci0,hci1 (default: all that are up)")
@click.option("--duration", "-d", default=30.0, show_default=True, help="Sniff duration (seconds)")
@click.option("--backend", type=click.Choice(["hci", "sniffle", "ubertooth"]),
              default="hci", show_default=True,
              help="hci = parallel adapters; sniffle/ubertooth = real channel-level sniffing")
@click.option("--channel", "-c", default=37, show_default=True,
              help="Advertising channel for the sniffle backend (37, 38 or 39)")
@click.option("--serial", default="/dev/ttyACM0", show_default=True,
              help="Serial port of the Sniffle dongle")
@click.option("--target", "-t", default=None, metavar="MAC", help="Filter on this MAC")
@click.pass_context
def sniff(ctx, adapters, duration, backend, channel, serial, target):
    """Multi-adapter sniffing, or drive an external channel-level sniffer.

    \b
    A plain HCI dongle cannot be pinned to one channel — BlueZ hops it for you.
    Running several in parallel still buys you coverage, and that is what the
    default 'hci' backend does. To actually catch a CONNECT_IND on a chosen
    channel and follow a connection you need Sniffle or an Ubertooth.

    \b
    Examples:
      meshbreaker sniff --adapters hci0,hci1 -d 60
      meshbreaker sniff --backend sniffle --channel 38
      meshbreaker sniff --backend ubertooth -d 120
    """
    _banner()
    output  = ctx.obj["output"]
    session = _load_session(output)
    if target:
        session.set_target(target)

    if backend == "sniffle":
        result = sniffer_mod.SniffleBackend(serial_port=serial, output_dir=output).run(
            channel=channel, duration=duration, target_mac=session.target_mac)
        session.store("sniff", result)
        _save_session(session, output)
        return

    if backend == "ubertooth":
        result = sniffer_mod.UbertoothBackend(output_dir=output).run(
            duration=duration, target_mac=session.target_mac)
        session.store("sniff", result)
        _save_session(session, output)
        return

    if adapters:
        adapter_list = [a.strip() for a in adapters.split(",") if a.strip()]
    else:
        adapter_list = [a.name for a in list_adapters() if a.is_up]
        if not adapter_list:
            adapter_list = [ctx.obj["adapter"]]
        logger.info(f"Using adapters that are up: {', '.join(adapter_list)}")

    sniffer_mod.print_channel_plan(adapter_list)

    async def _run():
        s = sniffer_mod.MultiAdapterSniffer(adapter_list, output_dir=output)
        result = await s.run(duration=duration, save=True)
        session.store("sniff", {
            "adapters": result.adapters_used,
            "adverts": len(result.hits),
            "unique_devices": result.unique_devices,
            "file": result.output_file,
        })
        if result.output_file:
            session.results["capture_file"] = result.output_file

    asyncio.run(_run())
    _save_session(session, output)


@cli.command("hci-capture")
@click.option("--duration", "-d", default=30.0, show_default=True,
              help="Capture duration (seconds)")
@click.option("--no-scan", is_flag=True,
              help="Do not start a scan — use when something else is already scanning")
@click.pass_context
def hci_capture(ctx, duration, no_scan):
    """Capture complete advertising payloads, including mesh AD types (Linux, root).

    \b
    BlueZ only hands bleak names, UUIDs, service data and manufacturer data.
    Mesh lives in AD types 0x29 (PB-ADV), 0x2A and 0x2B, which never make it
    through — so an ordinary capture cannot contain provisioning traffic no
    matter how much is in the air.

    \b
    This reads the HCI monitor socket instead, the same interface btmon uses,
    and parses the AD structures itself. It needs Linux and root, but it works
    with any standard adapter — no sniffer hardware.

    \b
    Examples:
      sudo meshbreaker hci-capture -d 60
      meshbreaker provisioning --capture output/hci_capture_123.json
    """
    _banner()
    output  = ctx.obj["output"]
    adapter = ctx.obj["adapter"]
    session = _load_session(output)

    from src.modules.hci_capture import HCIMonitorCapture

    cap = HCIMonitorCapture(adapter=adapter, output_dir=output)
    result = asyncio.run(cap.capture(duration=duration, save=True,
                                     drive_scan=not no_scan))

    session.store("hci_capture", {
        "frames": len(result.frames),
        "mesh_frames": result.mesh_frames,
        "duration": result.duration,
        "file": result.output_file,
        "ad_types": {f"0x{t:02X}": c for t, c in result.ad_types.items()},
    })
    if result.output_file:
        session.results["capture_file"] = result.output_file
    _save_session(session, output)


@cli.command()
@click.option("--capture", "capture_file", default=None, type=click.Path(exists=True),
              help="Capture JSON to scan for PB-ADV traffic (default: last one in session)")
@click.option("--target", "-t", default=None, metavar="MAC",
              help="Also probe this target for an exposed PB-GATT service")
@click.option("--no-gatt", is_flag=True, help="Skip the PB-GATT probe")
@click.option("--netkey", default=None, metavar="HEX",
              help="NetKey (hex) — matches proxy Network IDs against your network")
@click.pass_context
def provisioning(ctx, capture_file, target, no_gatt, netkey):
    """Audit BLE Mesh provisioning security.

    \b
    Provisioning is where a node receives the NetKey. The early PDUs travel
    unencrypted — there is no shared key yet — so a passive capture tells you
    exactly which authentication method was negotiated. 'No OOB' means nothing
    authenticates either peer and a machine-in-the-middle can take the NetKey.

    \b
    Examples:
      meshbreaker provisioning
      meshbreaker provisioning --capture output/capture_123.json
      meshbreaker provisioning -t AA:BB:CC:DD:EE:FF
    """
    _banner()
    output  = ctx.obj["output"]
    adapter = ctx.obj["adapter"]
    session = _load_session(output)
    if target:
        session.set_target(target)

    net_key = None
    if netkey:
        from src.modules.mesh_crypto import parse_key
        try:
            net_key = parse_key(netkey, "NetKey")
        except ValueError as e:
            logger.error(str(e))
            sys.exit(1)

    path = capture_file or session.results.get("capture_file")
    if path and Path(path).exists():
        analyzer = prov.ProvisioningAnalyzer()
        sessions = analyzer.parse_file(path)
        prov.print_sessions(sessions, analyzer.findings)

        service = prov.MeshServiceDataAnalyzer(net_key=net_key)
        unprovisioned, proxies = service.parse_file(path)
        prov.print_service_data(unprovisioned, proxies)
        for f in service.findings:
            logger.warning(f"{f.severity}: {f.title}")
            logger.info(f"  {f.detail}")

        session.store("provisioning_capture", {
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
            "findings": [{"severity": f.severity, "title": f.title,
                          "detail": f.detail, "cve": f.cve}
                         for f in analyzer.findings + service.findings],
        })
    else:
        logger.info("No capture file — run 'meshbreaker capture' first")

    if not no_gatt and session.target_mac:
        result = asyncio.run(prov.probe_pb_gatt(session.target_mac, adapter))
        session.store("provisioning_gatt", result)
    elif not no_gatt:
        logger.info("No target set — skipping PB-GATT probe")

    _save_session(session, output)


@cli.command("df")
@click.option("--capture", "capture_file", default=None, type=click.Path(exists=True),
              help="Capture JSON to inspect (default: last one in session)")
@click.option("--firmware", "fw_path", default=None, type=click.Path(exists=True),
              help="Firmware binary to search for Directed Forwarding symbols")
@click.option("--composition", default=None, metavar="HEX",
              help="Composition Data Page 0 blob (hex) — needs the DevKey to obtain")
@click.pass_context
def directed_forwarding(ctx, capture_file, fw_path, composition):
    """Audit Mesh 1.1 Directed Forwarding exposure.

    \b
    Mesh 1.1 replaced managed flooding with real routing. Routing means routing
    state, and routing state is something an attacker can lie about. This checks
    whether Directed Forwarding is present and what that exposes.

    \b
    Control messages ride inside encrypted Network PDUs, so opcode-level decode
    needs the NetKey. Without it we audit exposure, not traffic.

    \b
    Reference: "Tous les chemins mènent à DROP", Tali/Cayre/Nicomette/Auriol,
    LAAS-CNRS, SSTIC 2025.

    \b
    Examples:
      meshbreaker df --firmware fw.bin
      meshbreaker df --capture output/capture_123.json
      meshbreaker df --composition 0a00...
    """
    _banner()
    output  = ctx.obj["output"]
    session = _load_session(output)

    session_capture = session.results.get("capture_file")

    if composition:
        audit = df_mod.detect_from_composition_data(composition)

    elif fw_path:
        logger.info(f"Searching firmware for Directed Forwarding symbols: {fw_path}")
        audit = df_mod.detect_from_firmware(FirmwareAnalyzer(fw_path).analyze())

    elif capture_file:
        audit = df_mod.detect_from_capture(capture_file)

    elif session.firmware_path and Path(session.firmware_path).exists():
        logger.info(f"Using firmware from session: {session.firmware_path}")
        audit = df_mod.detect_from_firmware(
            FirmwareAnalyzer(session.firmware_path).analyze())

    elif session_capture and Path(session_capture).exists():
        logger.info(f"Using capture from session: {session_capture}")
        audit = df_mod.detect_from_capture(session_capture)

    else:
        logger.error("Nothing to analyze — pass --firmware, --capture or --composition")
        return

    df_mod.print_audit(audit)
    session.store("directed_forwarding", {
        "present": audit.df_present,
        "confidence": audit.df_confidence,
        "evidence": audit.evidence,
        "models": {f"0x{k:04X}": v for k, v in audit.models_found.items()},
        "findings": [{"severity": f.severity, "title": f.title,
                      "detail": f.detail, "reference": f.reference}
                     for f in audit.findings],
    })
    _save_session(session, output)


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
