import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.modules.mesh_frame_parser import MeshFrameParser, MeshNode
from src.modules.protocol_identifier import ProtocolIdentifier
from src.core.session import SessionState


def test_session_defaults():
    s = SessionState()
    assert s.target_mac is None
    assert s.adapter == "hci0"
    assert isinstance(s.results, dict)


def test_mesh_frame_parser_empty():
    parser = MeshFrameParser()
    topo = parser.topology()
    assert topo.nodes == {}
    assert topo.relay_candidates == []


def test_mesh_frame_parser_beacon():
    parser = MeshFrameParser()
    entry = {
        "mac": "AA:BB:CC:DD:EE:FF",
        "name": "TestNode",
        "rssi": -65,
        "raw": "2b01",
    }
    node = parser.parse_beacon(entry)
    assert node is not None
    assert node.mac == "AA:BB:CC:DD:EE:FF"
    assert "provisioned" in node.roles


def test_protocol_identifier_no_crash():
    pi = ProtocolIdentifier()
    results = pi.from_devices([])
    assert isinstance(results, list)


def test_protocol_identifier_uuid_match():
    pi = ProtocolIdentifier()
    devices = [{"uuids": ["1827"], "manufacturer_data": {}, "name": "", "service_data": {}}]
    results = pi.from_devices(devices)
    assert isinstance(results, list)


import struct

from src.modules import channel_map as cm


def _fake_connect_ind(hop=11, channel_map_bits=0x1FFFFFFFFF, aa=0x8E89BED6):
    """Build a valid 34-byte CONNECT_IND payload for tests."""
    init = bytes.fromhex("112233445566")
    adv = bytes.fromhex("AABBCCDDEEFF")
    ll = (struct.pack("<I", aa)
          + (0x555555).to_bytes(3, "little")
          + bytes([3])
          + struct.pack("<HHHH", 5, 6, 0, 500)
          + channel_map_bits.to_bytes(5, "little")
          + bytes([(2 << 5) | hop]))
    return init + adv + ll


def test_channel_frequencies():
    assert cm.channel_to_freq(37) == 2402
    assert cm.channel_to_freq(38) == 2426
    assert cm.channel_to_freq(39) == 2480
    freqs = sorted(cm.channel_to_freq(c) for c in range(cm.NUM_CHANNELS))
    assert len(set(freqs)) == 40
    assert freqs[0] == 2402 and freqs[-1] == 2480


def test_freq_to_channel_roundtrip():
    for ch in range(cm.NUM_CHANNELS):
        assert cm.freq_to_channel(cm.channel_to_freq(ch)) == ch
    assert cm.freq_to_channel(2403) is None


def test_channel_39_is_clear_of_common_wifi():
    assert cm.wifi_overlap(39) is None
    assert cm.wifi_overlap(37) == "WiFi-1"


def test_parse_connect_ind():
    params = cm.parse_connect_ind(_fake_connect_ind())
    assert params.access_address == 0x8E89BED6
    assert params.hop_increment == 11
    assert params.crc_init == 0x555555
    assert params.adv_addr == "FF:EE:DD:CC:BB:AA"
    assert params.interval_ms == 7.5
    assert len(params.used_channels) == 37


def test_parse_connect_ind_too_short():
    import pytest
    with pytest.raises(ValueError):
        cm.parse_connect_ind(b"\x00" * 10)


def test_hop_algo1_is_a_fixed_step():
    params = cm.parse_connect_ind(_fake_connect_ind(hop=11))
    sequence = cm.hop_algo1(params, events=10)
    assert sequence == [(11 * (i + 1)) % 37 for i in range(10)]


def test_hop_algo2_is_deterministic():
    params = cm.parse_connect_ind(_fake_connect_ind())
    first = cm.hop_algo2(params, events=15)
    second = cm.hop_algo2(params, events=15)
    assert first == second
    assert all(0 <= c < 37 for c in first)
    assert first != cm.hop_algo1(params, events=15)


def test_hop_remapping_stays_inside_used_channels():
    params = cm.parse_connect_ind(_fake_connect_ind(channel_map_bits=0b11111))
    assert params.used_channels == [0, 1, 2, 3, 4]
    for sequence in (cm.hop_algo1(params, events=40), cm.hop_algo2(params, events=40)):
        assert all(c in params.used_channels for c in sequence)


def test_channel_identifier_matches_spec_formula():
    params = cm.parse_connect_ind(_fake_connect_ind(aa=0x12345678))
    assert params.channel_identifier == (0x1234 ^ 0x5678)


from src.modules import provisioning as prov


def _pb_adv(link_id: int, transaction: int, gp: bytes) -> str:
    return (b"\x29" + struct.pack(">I", link_id) + bytes([transaction]) + gp).hex()


def _transaction_start(pdu: bytes) -> bytes:
    return bytes([0x00]) + struct.pack(">H", len(pdu)) + bytes([0xAB]) + pdu


def test_parse_capabilities():
    raw = (bytes([0x02]) + struct.pack(">H", 0x0003) + bytes([0x01, 0x01, 0x04])
           + struct.pack(">H", 0x0008) + bytes([0x00]) + struct.pack(">H", 0x0000))
    caps = prov.parse_capabilities(raw)
    assert caps.num_elements == 2
    assert caps.supports_static_oob is True
    assert caps.supports_oob_public_key is True
    assert caps.output_oob_size == 4
    assert len(caps.algorithm_names) == 2


def test_parse_capabilities_too_short():
    assert prov.parse_capabilities(b"\x01\x02") is None


def test_parse_start_reads_auth_method():
    start = prov.parse_start(bytes([0x00, 0x00, 0x00, 0x00, 0x00]))
    assert prov.AUTH_METHODS[start["auth_method"]] == "No OOB"
    start = prov.parse_start(bytes([0x00, 0x00, 0x01, 0x00, 0x10]))
    assert prov.AUTH_METHODS[start["auth_method"]] == "Static OOB"


def test_parse_pb_adv_link_open():
    uuid = bytes(range(16))
    gp = bytes([(0x00 << 2) | 0b11]) + uuid
    parsed = prov.parse_pb_adv(bytes.fromhex(_pb_adv(0xAABBCCDD, 0, gp))[1:])
    assert parsed["type"] == "bearer_control"
    assert parsed["opcode_name"] == "Link Open"
    assert parsed["device_uuid"] == uuid.hex()


def test_no_oob_provisioning_is_critical(tmp_path):
    import json
    caps = (bytes([0x01]) + struct.pack(">H", 0x0001) + bytes([0x00, 0x00, 0x00])
            + struct.pack(">H", 0) + bytes([0x00]) + struct.pack(">H", 0))
    frames = [
        {"mac": "AA:BB:CC:DD:EE:01", "rssi": -50,
         "raw": _pb_adv(0x1234, 1, _transaction_start(bytes([0x01]) + caps))},
        {"mac": "AA:BB:CC:DD:EE:01", "rssi": -50,
         "raw": _pb_adv(0x1234, 2,
                        _transaction_start(bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x00])))},
    ]
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(frames))

    analyzer = prov.ProvisioningAnalyzer()
    sessions = analyzer.parse_file(str(path))
    assert len(sessions) == 1
    assert sessions[0].chosen_method == "No OOB"
    assert any(f.severity == "CRITICAL" for f in analyzer.findings)


def test_capture_without_provisioning_is_quiet(tmp_path):
    import json
    path = tmp_path / "empty.json"
    path.write_text(json.dumps([{"mac": "AA:BB", "rssi": -50, "raw": ""}]))
    analyzer = prov.ProvisioningAnalyzer()
    assert analyzer.parse_file(str(path)) == []
    assert analyzer.findings == []


from src.modules import directed_forwarding as df


def test_composition_data_finds_df_model():
    header = struct.pack("<HHHHH", 0x0059, 1, 1, 100, 0x000B)
    element = struct.pack("<HBB", 0, 2, 0) + struct.pack("<HH", 0x0000, 0x0007)
    audit = df.detect_from_composition_data((header + element).hex())
    assert audit.df_present is True
    assert audit.df_confidence == 100
    assert 0x0007 in audit.models_found
    assert any(f.severity == "HIGH" for f in audit.findings)


def test_composition_data_without_df():
    header = struct.pack("<HHHHH", 0x0059, 1, 1, 100, 0x0003)
    element = struct.pack("<HBB", 0, 1, 0) + struct.pack("<H", 0x0000)
    audit = df.detect_from_composition_data((header + element).hex())
    assert audit.df_present is False
    assert audit.findings == []


def test_composition_data_bad_hex_does_not_crash():
    assert df.detect_from_composition_data("nothex").df_present is False


def test_firmware_strings_detect_df():
    class FakeFirmware:
        strings = ["bt_mesh_df_srv", "path_request_handler", "forwarding_table"]
    audit = df.detect_from_firmware(FakeFirmware())
    assert audit.df_present is True
    assert audit.evidence


def test_private_beacon_suppresses_the_low_finding():
    class WithBeacons:
        strings = ["bt_mesh_df", "path_origin", "path_reply", "private_beacon_set"]

    class WithoutBeacons:
        strings = ["bt_mesh_df", "path_origin", "path_reply"]

    titles = [f.title for f in df.detect_from_firmware(WithBeacons()).findings]
    assert not any("Private Beacon" in t for t in titles)
    titles = [f.title for f in df.detect_from_firmware(WithoutBeacons()).findings]
    assert any("Private Beacon" in t for t in titles)


def test_decode_control_pdu():
    assert df.decode_control_pdu(bytes([0x01]))["name"] == "PATH_REQUEST"
    assert df.decode_control_pdu(bytes([0x02]))["is_df"] is True
    assert df.decode_control_pdu(bytes([0x7F]))["is_df"] is False
    assert df.decode_control_pdu(b"") is None


from src.core import adapter_manager as am


def test_adapter_scoring_prefers_usb_that_is_up():
    internal = am.Adapter(name="hci0", bus="UART", is_up=True)
    dongle = am.Adapter(name="hci1", bus="USB", is_up=True)
    down = am.Adapter(name="hci2", bus="USB", is_up=False)
    for a in (internal, dongle, down):
        a.score = am._score_adapter(a)
    assert am.best_of([internal, dongle, down]) == "hci1"


def test_best_of_falls_back_when_no_adapters():
    assert am.best_of([]) == "hci0"


def test_serial_device_on_known_id_is_reported_as_sniffer(monkeypatch):
    """A board we know by VID:PID, reported with the port you have to type."""
    dongle = am.SerialDevice(port="/dev/ttyACM0", usb_id="2fe3:0004",
                             manufacturer="Zephyr Project",
                             product="CDC ACM serial backend", writable=True)
    monkeypatch.setattr(am, "_run", lambda *a, **k: "")
    found = am.detect_sniffer_hardware([dongle])
    assert len(found) == 1
    assert found[0].usb_id == "2fe3:0004"
    assert found[0].port == "/dev/ttyACM0"


def test_unknown_product_id_on_known_vendor_is_still_reported(monkeypatch):
    """Flashing firmware changes the product ID, so the table always lags.

    A Nordic VID on a serial port is worth surfacing even when we have never
    seen that PID — otherwise the user is told they have no sniffer while
    holding one.
    """
    dongle = am.SerialDevice(port="/dev/ttyACM0", usb_id="1915:ffff",
                             manufacturer="Nordic", product="Custom",
                             writable=True)
    monkeypatch.setattr(am, "_run", lambda *a, **k: "")
    found = am.detect_sniffer_hardware([dongle])
    assert len(found) == 1
    assert "unrecognised product ID" in found[0].description
    assert found[0].port == "/dev/ttyACM0"


def test_unrelated_serial_device_is_ignored(monkeypatch):
    """A USB modem or an Arduino is not a sniffer."""
    modem = am.SerialDevice(port="/dev/ttyUSB0", usb_id="1a86:7523",
                            product="USB Serial", writable=True)
    monkeypatch.setattr(am, "_run", lambda *a, **k: "")
    assert am.detect_sniffer_hardware([modem]) == []


def test_lsusb_and_serial_do_not_double_report(monkeypatch):
    """Same board seen twice must collapse to one row, keeping the port."""
    dongle = am.SerialDevice(port="/dev/ttyACM0", usb_id="1d50:6002",
                             product="Ubertooth One", writable=True)
    monkeypatch.setattr(am, "_run",
                        lambda *a, **k: "Bus 002 Device 005: ID 1d50:6002 ubertooth")
    found = am.detect_sniffer_hardware([dongle])
    assert len(found) == 1
    assert found[0].port == "/dev/ttyACM0"


def test_board_with_no_serial_port_still_reported(monkeypatch):
    """A dongle in DFU mode exposes no port — lsusb is the only witness."""
    monkeypatch.setattr(am, "_run",
                        lambda *a, **k: "Bus 002 Device 005: ID 1915:521f nordic")
    found = am.detect_sniffer_hardware([])
    assert len(found) == 1
    assert found[0].port == ""


def test_non_pb_adv_frames_are_not_read_as_provisioning():
    """parse_pb_adv() succeeds on any 6+ byte buffer, so filtering matters.

    An Apple manufacturer-data advert was reported as a provisioning session
    with link ID 0xFF4C0002 — the company ID read as a Link ID. In an audit
    tool a false "provisioning traffic observed" is worse than silence.
    """
    from src.modules.provisioning import _pb_adv_payload

    apple = bytes.fromhex("ff4c000212020003")
    assert _pb_adv_payload({"ad_type": 0xFF}, apple) is None
    assert _pb_adv_payload({}, apple) is None

    pb_adv = bytes([0x29]) + bytes.fromhex("11223344") + b"\x00\x03\x00"
    assert _pb_adv_payload({"ad_type": 0x29}, pb_adv) == pb_adv[1:]
    assert _pb_adv_payload({}, pb_adv) == pb_adv[1:]

    assert _pb_adv_payload({"ad_type": 0x29}, bytes([0x29, 0x01])) is None


def test_extended_advertising_reports_are_decoded():
    """A Bluetooth 5 controller reports through subevent 0x0D, not 0x02.

    BlueZ switches to extended scanning on its own when the controller
    supports it, and an Intel AX200 does. Decoding only the legacy event
    yielded an empty capture there, which reads as "nothing is advertising".
    """
    from src.modules.hci_capture import (parse_le_ext_advertising_report,
                                         _parse_monitor_packet)

    payload = bytes.fromhex("020106")
    event_type = bytes.fromhex("0100")
    address_type = b"\x01"
    address = bytes.fromhex("112233445566")
    phys_sid_txpower = b"\x01\x01\x00\x7f"
    rssi_minus_64 = bytes([0xC0])
    periodic_interval = b"\x00\x00"
    direct_address = b"\x00" + bytes(6)

    report = (event_type + address_type + address + phys_sid_txpower
              + rssi_minus_64 + periodic_interval + direct_address
              + bytes([len(payload)]) + payload)
    body = b"\x3e" + bytes([len(report) + 2]) + b"\x0d\x01" + report
    from src.modules import hci_capture as hci
    packet = struct.pack("<HHH", hci.MON_EVENT_PKT, 0, len(body)) + body

    parsed = parse_le_ext_advertising_report(b"\x01" + report)
    assert len(parsed) == 1
    assert parsed[0]["mac"] == "66:55:44:33:22:11"
    assert parsed[0]["rssi"] == -64
    assert parsed[0]["payload"] == payload

    assert _parse_monitor_packet(packet) == parsed


def test_mac_addresses_survive_rich_rendering():
    """Rich turns :cd: into a CD emoji, which eats a byte of a MAC address.

    64:01:60:CD:9A:1C rendered as 64:01:60(disc)9A:1C, so the address on
    screen was not the address on the air. Any byte matching an emoji name
    hits this.
    """
    from src.utils import logger

    with logger.console.capture() as cap:
        logger.info("64:01:60:CD:9A:1C")
    out = cap.get()
    assert "64:01:60:CD:9A:1C" in out
    assert "\U0001F4BF" not in out


def test_no_console_renders_emoji_shortcodes():
    """Every Console must be built with emoji=False, not just the logger's."""
    import re
    from pathlib import Path

    offenders = []
    root = Path(__file__).resolve().parent.parent
    for f in sorted(root.rglob("*.py")):
        if "__pycache__" in str(f):
            continue
        for i, line in enumerate(f.read_text().splitlines(), 1):
            if re.search(r"\bConsole\(", line) and "emoji=False" not in line:
                offenders.append(f"{f.relative_to(root)}:{i}")
    assert not offenders, f"Console without emoji=False: {offenders}"


def test_session_round_trip_keeps_devices(tmp_path):
    """recon filled session.devices but the saver dropped the field.

    Every later command reloaded a session with an empty list, so every
    report said "Devices found: 0" no matter how large the scan was.
    """
    import meshbreaker
    from src.core.session import SessionState

    session = SessionState(output_dir=str(tmp_path))
    session.devices = [{"mac": "AA:BB:CC:DD:EE:FF", "name": "x", "rssi": -60}]
    meshbreaker._save_session(session, str(tmp_path))

    reloaded = meshbreaker._load_session(str(tmp_path))
    assert reloaded.devices == session.devices


def test_report_skips_gatt_section_with_nothing_to_show(tmp_path):
    """A failed enumeration left a bare heading with no content under it."""
    from src.core.session import SessionState
    from src.modules.report_generator import ReportGenerator

    session = SessionState(output_dir=str(tmp_path))
    session.results = {"gatt": {}}
    path = ReportGenerator(session).generate("md", str(tmp_path))
    assert "## GATT Enumeration" not in Path(path).read_text()

    session.results = {"gatt": {"services": [{"uuid": "1800"}], "attack_surface": []}}
    path = ReportGenerator(session).generate("md", str(tmp_path))
    body = Path(path).read_text()
    assert "## GATT Enumeration" in body
    assert "No writable characteristics found" in body


def test_cli_commands_do_not_shadow_builtins():
    """A click command named like a builtin shadows it for the whole module.

    `def enumerate(...)` at module level in meshbreaker.py did exactly that,
    and _print_devices() calls the builtin enumerate — so listing scan results
    crashed. It only showed up once a real adapter found a device, because
    with an empty result list the loop never runs.
    """
    import builtins
    import meshbreaker

    risky = ("enumerate", "list", "filter", "type", "id", "hash", "input",
             "print", "range", "map", "set", "dict", "next", "open", "format")
    for name in risky:
        shadow = getattr(meshbreaker, name, None)
        assert shadow is None or shadow is getattr(builtins, name), (
            f"meshbreaker.{name} shadows the builtin — "
            f"use @cli.command(\"{name}\") with a differently named function")


from src.core.orchestrator import Orchestrator


def test_fuzz_is_the_only_active_phase():
    orch = Orchestrator(SessionState())
    active = [p.name for p in orch.phases if p.active]
    assert active == ["fuzz"]


def test_chain_skips_active_phases_by_default():
    import asyncio
    session = SessionState()
    orch = Orchestrator(session)
    results = asyncio.run(orch.run(start=7, stop=7, scan_time=0.1, capture_duration=0.1))
    assert len(results) == 1
    assert results[0].name == "fuzz"
    assert results[0].status == "skipped"


def test_chain_skips_phases_needing_a_target():
    import asyncio
    orch = Orchestrator(SessionState())
    results = asyncio.run(orch.run(start=3, stop=3))
    assert results[0].status == "skipped"
    assert "target" in results[0].detail


from src.modules.report_generator import ReportGenerator


def test_generate_single_format(tmp_path):
    session = SessionState(target_mac="AA:BB:CC:DD:EE:FF", output_dir=str(tmp_path))
    gen = ReportGenerator(session)
    for fmt, extension in [("md", ".md"), ("html", ".html"), ("json", ".json"),
                           ("markdown", ".md")]:
        path = gen.generate(fmt)
        assert path.endswith(extension)
        assert Path(path).exists()


def test_generate_rejects_unknown_format(tmp_path):
    import pytest
    gen = ReportGenerator(SessionState(output_dir=str(tmp_path)))
    with pytest.raises(ValueError):
        gen.generate("pdf")


def test_report_includes_the_new_sections(tmp_path):
    session = SessionState(target_mac="AA:BB:CC:DD:EE:FF", output_dir=str(tmp_path))
    session.store("provisioning_capture", {
        "sessions": 1,
        "findings": [{"severity": "CRITICAL", "title": "No OOB",
                      "detail": "MITM possible", "cve": "CVE-2020-26560"}],
    })
    session.store("directed_forwarding", {
        "present": True, "confidence": 100, "evidence": ["model 0x0007"],
        "models": {"0x0007": "Directed Forwarding Configuration Server"},
        "findings": [{"severity": "HIGH", "title": "DF config server reachable",
                      "detail": "forwarding table is configurable", "reference": "SSTIC 2025"}],
    })
    session.store("connection_follow", {
        "access_address": "0x8E89BED6", "crc_init": "0x555555",
        "hop_increment": 11, "algorithm": 1, "interval_ms": 7.5,
        "channels_used": 37, "predicted_channels": [11, 22, 33],
    })

    text = Path(ReportGenerator(session).generate("md")).read_text()
    assert "## Provisioning Security" in text
    assert "CVE-2020-26560" in text
    assert "## Directed Forwarding (Mesh 1.1)" in text
    assert "SSTIC 2025" in text
    assert "## Connection Following" in text
    assert "0x8E89BED6" in text


import json

from src.modules.cve_checker import CVEChecker


def _cve_db():
    root = Path(__file__).parent.parent
    return json.loads((root / "data" / "cve_db.json").read_text())


def test_cve_ids_are_unique():
    ids = [e["cve_id"] for e in _cve_db()["entries"]]
    duplicates = {i for i in ids if ids.count(i) > 1}
    assert not duplicates, f"duplicate CVE entries: {duplicates}"


def test_every_cve_has_the_fields_the_checker_reads():
    for entry in _cve_db()["entries"]:
        for field_name in ("cve_id", "name", "severity", "description", "tags"):
            assert field_name in entry, f"{entry.get('cve_id')} is missing {field_name}"
        float(entry.get("cvss") or 0)


def test_mesh_provisioning_cves_are_present():
    ids = {e["cve_id"] for e in _cve_db()["entries"]}
    for cve in ("CVE-2020-26556", "CVE-2020-26557", "CVE-2020-26559", "CVE-2020-26560"):
        assert cve in ids


def test_sig_mesh_tag_matches_the_provisioning_cves():
    matches = CVEChecker().check_all({"protocol_tags": ["ble_mesh_sig"]})
    ids = {m.cve_id for m in matches}
    assert "CVE-2020-26560" in ids
    assert "BT-MESH-DF-2025" in ids


def test_unknown_tag_matches_nothing():
    assert CVEChecker().check_all({"protocol_tags": ["not_a_real_protocol"]}) == []


from src.modules import mesh_crypto as mc

SAMPLE_NETKEY = bytes.fromhex("7dd7364cd842ad18c17c2b820c84c3d6")
SAMPLE_IV_INDEX = 0x12345678


def test_s1_matches_spec_vector():
    assert mc.s1(b"test").hex() == "b73cefbd641ef2ea598c2b6efb62f79c"


def test_k2_matches_spec_vector():
    nid, encryption_key, privacy_key = mc.k2(SAMPLE_NETKEY)
    assert nid == 0x68
    assert encryption_key.hex() == "0953fa93e7caac9638f58820220a398e"
    assert privacy_key.hex() == "8b84eedec100067d670971dd2aa700cf"


def test_k3_matches_spec_vector():
    assert mc.k3(SAMPLE_NETKEY).hex() == "3ecaff672f673370"


def test_k4_matches_spec_vector():
    assert mc.k4(bytes.fromhex("3216d1509884b533248541792b877f98")) == 0x38


def test_network_pdu_matches_spec_sample_message():
    pdu = mc.build_network_pdu(
        net_key=SAMPLE_NETKEY, iv_index=SAMPLE_IV_INDEX,
        transport_pdu=bytes.fromhex("034b50057e400000010000"),
        src=0x1201, dst=0xFFFD, ctl=1, ttl=0, seq=1,
    )
    assert pdu.hex() == "68eca487516765b5e5bfdacbaf6cb7fb6bff871f035444ce83a670df"


def test_network_pdu_round_trip():
    transport = bytes.fromhex("0108000000050001")
    pdu = mc.build_network_pdu(SAMPLE_NETKEY, SAMPLE_IV_INDEX, transport,
                               src=0x0001, dst=0xFFFF, ctl=1, ttl=127, seq=42)
    parsed = mc.parse_network_pdu(SAMPLE_NETKEY, SAMPLE_IV_INDEX, pdu)
    assert parsed is not None
    assert parsed["src"] == 0x0001
    assert parsed["dst"] == 0xFFFF
    assert parsed["seq"] == 42
    assert parsed["ctl"] == 1
    assert parsed["transport_pdu"] == transport


def test_wrong_netkey_is_rejected_not_misparsed():
    pdu = mc.build_network_pdu(SAMPLE_NETKEY, SAMPLE_IV_INDEX, b"\x01\x02",
                               src=1, dst=2)
    assert mc.parse_network_pdu(bytes(16), SAMPLE_IV_INDEX, pdu) is None


def test_control_messages_use_a_64_bit_mic():
    control = mc.build_network_pdu(SAMPLE_NETKEY, SAMPLE_IV_INDEX, b"\x01",
                                   src=1, dst=2, ctl=1)
    access = mc.build_network_pdu(SAMPLE_NETKEY, SAMPLE_IV_INDEX, b"\x01",
                                  src=1, dst=2, ctl=0)
    assert len(control) - len(access) == 4


def test_obfuscation_is_its_own_inverse():
    _, _, privacy_key = mc.k2(SAMPLE_NETKEY)
    header = bytes.fromhex("800000011201")
    encrypted = bytes(range(21))
    once = mc.obfuscate_header(privacy_key, SAMPLE_IV_INDEX, header, encrypted)
    twice = mc.deobfuscate_header(privacy_key, SAMPLE_IV_INDEX, once, encrypted)
    assert once != header
    assert twice == header


def test_build_network_pdu_rejects_bad_input():
    import pytest
    with pytest.raises(ValueError):
        mc.build_network_pdu(b"\x00" * 15, 0, b"\x01", src=1, dst=2)
    with pytest.raises(ValueError):
        mc.build_network_pdu(SAMPLE_NETKEY, 0, b"\x01", src=1, dst=2, seq=0x1000000)


def test_proxy_pdu_segmentation():
    single = mc.wrap_proxy_pdu(b"\x01" * 10, att_mtu=23)
    assert len(single) == 1
    assert single[0][0] == (mc.SAR_COMPLETE << 6) | mc.PROXY_NETWORK_PDU

    chunks = mc.wrap_proxy_pdu(b"\x01" * 50, att_mtu=23)
    assert len(chunks) == 3
    assert chunks[0][0] >> 6 == mc.SAR_FIRST
    assert chunks[1][0] >> 6 == mc.SAR_CONTINUATION
    assert chunks[2][0] >> 6 == mc.SAR_LAST
    assert b"".join(c[1:] for c in chunks) == b"\x01" * 50


def test_parse_key_validation():
    import pytest
    assert mc.parse_key("7dd7364cd842ad18c17c2b820c84c3d6") == SAMPLE_NETKEY
    assert mc.parse_key("7d:d7:36:4c:d8:42:ad:18:c1:7c:2b:82:0c:84:c3:d6") == SAMPLE_NETKEY
    with pytest.raises(ValueError):
        mc.parse_key("tooshort")
    with pytest.raises(ValueError):
        mc.parse_key("zz" * 16)


from src.plugins.df_path_inject import DFPathInjectPlugin, build_path_request


def test_plugin_requires_a_netkey():
    import pytest
    plugin = DFPathInjectPlugin(target=None, config={})
    result = plugin.run()
    assert "error" in result
    assert "netkey" in result["error"].lower()


def test_plugin_dry_run_builds_a_decryptable_pdu():
    plugin = DFPathInjectPlugin(target=None, config={
        "netkey": SAMPLE_NETKEY.hex(),
        "iv_index": "0x12345678",
        "mode": "path_request",
        "src": "0x0001",
        "path_target": "0x0005",
        "dry_run": "true",
    })
    result = plugin.run()
    assert result["transmitted"] is False
    assert result["opcode_name"] == "PATH_REQUEST"

    parsed = mc.parse_network_pdu(SAMPLE_NETKEY, SAMPLE_IV_INDEX,
                                  bytes.fromhex(result["network_pdu"]))
    assert parsed is not None
    assert parsed["ctl"] == 1
    assert parsed["src"] == 0x0001
    assert parsed["transport_pdu"][0] == 0x01


def test_plugin_raw_params_passthrough():
    plugin = DFPathInjectPlugin(target=None, config={
        "netkey": SAMPLE_NETKEY.hex(),
        "opcode": "0x02",
        "params": "deadbeef",
        "dry_run": "true",
    })
    result = plugin.run()
    assert result["transport_pdu"] == "02deadbeef"


def test_plugin_rejects_unknown_mode():
    plugin = DFPathInjectPlugin(target=None, config={
        "netkey": SAMPLE_NETKEY.hex(), "mode": "nonsense", "dry_run": "true",
    })
    assert "error" in plugin.run()


def test_plugin_does_not_transmit_without_a_target():
    plugin = DFPathInjectPlugin(target=None, config={
        "netkey": SAMPLE_NETKEY.hex(), "dry_run": "false",
    })
    result = plugin.run()
    assert result["transmitted"] is False
    assert result["error"] == "no target"


def test_path_request_parameter_layout():
    params = build_path_request(path_origin=0x0001, destination=0x0005, lifetime=2)
    assert params.hex() == "0800000005" + "0001"


def test_plugins_still_load_without_a_config():
    from src.plugins.example_plugin import ExamplePlugin
    plugin = ExamplePlugin(target="AA:BB:CC:DD:EE:FF", adapter="hci0")
    assert plugin.config == {}
    assert plugin.option("anything") is None


from src.utils.capture_io import decode_frames, frame_bytes, load_capture


def test_load_capture_accepts_all_three_shapes(tmp_path):
    import json
    frames = [{"mac": "AA", "raw": "2b01"}]
    for payload in (frames, {"beacons": frames}, {"devices": frames}):
        path = tmp_path / "c.json"
        path.write_text(json.dumps(payload))
        assert load_capture(str(path)) == frames


def test_load_capture_survives_bad_files(tmp_path):
    cases = {
        "notjson.json": "this is not json",
        "empty.json": "",
        "scalar.json": "42",
        "badlist.json": '{"beacons": "not a list"}',
    }
    for name, content in cases.items():
        path = tmp_path / name
        path.write_text(content)
        assert load_capture(str(path)) is None, f"{name} should be rejected cleanly"

    assert load_capture(str(tmp_path / "does_not_exist.json")) is None


def test_load_capture_drops_non_dict_entries(tmp_path):
    import json
    path = tmp_path / "mixed.json"
    path.write_text(json.dumps([{"mac": "AA"}, "garbage", 42, {"mac": "BB"}]))
    frames = load_capture(str(path))
    assert frames == [{"mac": "AA"}, {"mac": "BB"}]


def test_frame_bytes_handles_bad_hex():
    assert frame_bytes({"raw": "2b01"}) == b"\x2b\x01"
    assert frame_bytes({"raw": "zzzz"}) is None
    assert frame_bytes({"raw": "abc"}) is None
    assert frame_bytes({"raw": ""}) is None
    assert frame_bytes({}) is None


def test_decode_frames_counts_bad_ones():
    entries = [{"raw": "2b01"}, {"raw": "zzzz"}, {"raw": ""}, {"raw": "2a00"}]
    good, bad = decode_frames(entries)
    assert len(good) == 2
    assert bad == 1


def test_parsers_do_not_crash_on_a_corrupt_capture(tmp_path):
    """Every capture consumer must survive a file it cannot read."""
    import json
    from src.modules.mesh_frame_parser import MeshFrameParser
    from src.modules.protocol_identifier import ProtocolIdentifier
    from src.modules import directed_forwarding as df
    from src.modules import provisioning as prov

    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{ this is not json")
    bad_hex = tmp_path / "badhex.json"
    bad_hex.write_text(json.dumps([{"mac": "AA", "raw": "zzz"}]))

    for path in (corrupt, bad_hex):
        topo = MeshFrameParser().parse_file(str(path))
        assert topo is not None
        assert ProtocolIdentifier().from_capture_file(str(path)) == []
        assert df.detect_from_capture(str(path)).df_present is False
        assert prov.ProvisioningAnalyzer().parse_file(str(path)) == []


from src.core.adapter_manager import explain_ble_error


def test_bluez_not_running_gets_an_actionable_hint():
    exc = Exception("[org.freedesktop.systemd1.NoSuchUnit] "
                    "Unit dbus-org.bluez.service not found.")
    hint = explain_ble_error(exc)
    assert "systemctl start bluetooth" in hint


def test_missing_adapter_and_permissions_are_recognised():
    assert "hciconfig" in explain_ble_error(RuntimeError("No Bluetooth adapter found"))
    assert "sudo" in explain_ble_error(PermissionError("Permission denied"))


def test_unrecognised_errors_return_empty_so_callers_reraise():
    assert explain_ble_error(ValueError("something else entirely")) == ""


def test_proxy_payload_size_accounts_for_att_and_proxy_headers():
    assert mc.proxy_payload_size(23) == 19
    assert mc.proxy_payload_size(247) == 243
    assert mc.proxy_payload_size(4) == 1


def test_higher_mtu_means_fewer_writes():
    """The reason segmentation waits for the connection."""
    payload = b"\x01" * 40
    at_default = mc.wrap_proxy_pdu(payload, att_mtu=23)
    at_negotiated = mc.wrap_proxy_pdu(payload, att_mtu=247)
    assert len(at_default) == 3
    assert len(at_negotiated) == 1
    assert b"".join(c[1:] for c in at_default) == payload
    assert at_negotiated[0][1:] == payload


def test_negotiated_mtu_reads_the_client():
    from src.plugins.df_path_inject import _negotiated_mtu

    class Client:
        mtu_size = 247
    assert _negotiated_mtu(Client()) == 247


def test_negotiated_mtu_falls_back_on_a_useless_value():
    from src.plugins.df_path_inject import _negotiated_mtu

    class Zero:
        mtu_size = 0

    class Missing:
        pass

    class Nonsense:
        mtu_size = "?"

    for client in (Zero(), Missing(), Nonsense()):
        assert _negotiated_mtu(client) == mc.DEFAULT_ATT_MTU


def test_forced_mtu_overrides_the_client_but_not_below_the_minimum():
    from src.plugins.df_path_inject import _negotiated_mtu

    class Client:
        mtu_size = 23
    assert _negotiated_mtu(Client(), forced="185") == 185
    assert _negotiated_mtu(Client(), forced="8") == mc.DEFAULT_ATT_MTU


def test_dry_run_reports_the_mtu_it_assumed():
    plugin = DFPathInjectPlugin(target=None, config={
        "netkey": SAMPLE_NETKEY.hex(), "dry_run": "true",
    })
    result = plugin.run()
    assert result["att_mtu"] == mc.DEFAULT_ATT_MTU
    assert result["proxy_pdus"]


from src.utils.capture_io import (MESH_AD_TYPES, profile_capture,
                                  warn_if_mesh_blind)


def test_bleak_capture_is_recognised_as_mesh_blind():
    entries = [{"mac": "AA", "ad_type": 0xFF, "raw": "7700abcd"} for _ in range(5)]
    profile = profile_capture(entries)
    assert profile.source == "bleak"
    assert profile.carries_mesh_ad_types is False
    assert warn_if_mesh_blind(profile, "PB-ADV") is True


def test_sniffer_capture_is_recognised_as_mesh_capable():
    entries = [{"mac": "AA", "ad_type": 0x2B, "raw": "2b01"},
               {"mac": "AA", "ad_type": 0x29, "raw": "29aabb"}]
    profile = profile_capture(entries)
    assert profile.source == "sniffer"
    assert profile.carries_mesh_ad_types is True
    assert profile.mesh_frames == 2
    assert warn_if_mesh_blind(profile, "PB-ADV") is False


def test_ad_type_field_wins_over_raw_first_byte():
    """In a bleak capture raw[0] is a company ID byte, not an AD type.

    Reading raw[0] as the AD type would misclassify manufacturer data whose
    company ID happens to start with 0x29, 0x2A or 0x2B.
    """
    entries = [{"mac": "AA", "ad_type": 0xFF, "raw": "2a00deadbeef"}]
    profile = profile_capture(entries)
    assert profile.carries_mesh_ad_types is False
    assert profile.ad_types == {0xFF: 1}


def test_provisioning_flags_a_blind_capture(tmp_path):
    import json
    path = tmp_path / "bleak.json"
    path.write_text(json.dumps([{"mac": "AA", "ad_type": 0xFF, "raw": "7700ab"}]))
    analyzer = prov.ProvisioningAnalyzer()
    assert analyzer.parse_file(str(path)) == []
    assert analyzer.mesh_blind is True


def _service_entry(mac, uuid_short, payload_hex, rssi=-60):
    return {"mac": mac, "rssi": rssi,
            "service_data": {f"0000{uuid_short}-0000-1000-8000-00805f9b34fb": payload_hex}}


def test_unprovisioned_node_without_oob_is_high():
    device_uuid = bytes(range(16)).hex()
    entries = [_service_entry("AA:BB:CC:00:00:01", "1827", device_uuid + "0000")]
    analyzer = prov.MeshServiceDataAnalyzer()
    unprovisioned, _ = analyzer.parse_entries(entries)
    assert len(unprovisioned) == 1
    assert unprovisioned[0].device_uuid == device_uuid
    assert unprovisioned[0].has_oob is False
    assert any(f.severity == "HIGH" for f in analyzer.findings)


def test_unprovisioned_node_with_oob_is_only_medium():
    device_uuid = bytes(range(16)).hex()
    entries = [_service_entry("AA:BB:CC:00:00:02", "1827", device_uuid + "4020")]
    analyzer = prov.MeshServiceDataAnalyzer()
    unprovisioned, _ = analyzer.parse_entries(entries)
    assert unprovisioned[0].has_oob is True
    assert "Number" in unprovisioned[0].oob_sources
    assert "On device" in unprovisioned[0].oob_sources
    assert all(f.severity != "HIGH" for f in analyzer.findings)


def test_proxy_network_id_matches_the_supplied_netkey(capsys):
    from src.modules.mesh_crypto import k3
    network_id = k3(SAMPLE_NETKEY).hex()
    entries = [_service_entry("AA:BB:CC:00:00:03", "1828", "00" + network_id)]
    analyzer = prov.MeshServiceDataAnalyzer(net_key=SAMPLE_NETKEY)
    _, proxies = analyzer.parse_entries(entries)
    assert len(proxies) == 1
    assert proxies[0].network_id == network_id


def test_node_identity_advertising_is_flagged():
    entries = [_service_entry("AA:BB:CC:00:00:04", "1828", "01" + "aa" * 8 + "bb" * 8)]
    analyzer = prov.MeshServiceDataAnalyzer()
    _, proxies = analyzer.parse_entries(entries)
    assert proxies[0].identity_type == prov.PROXY_ID_NODE
    assert any("Node Identity" in f.title for f in analyzer.findings)


def test_service_data_parsers_reject_short_payloads():
    assert prov.parse_prov_service_data(b"\x00" * 10) is None
    assert prov.parse_proxy_service_data(b"\x00") is None
    assert prov.parse_proxy_service_data(b"\x01" + b"\x00" * 4) is None


def test_service_data_analyzer_survives_junk():
    entries = [
        {"mac": "AA", "service_data": "not a dict"},
        {"mac": "BB", "service_data": {"00001827-0000-1000-8000-00805f9b34fb": "zzz"}},
        {"mac": "CC"},
    ]
    analyzer = prov.MeshServiceDataAnalyzer()
    unprovisioned, proxies = analyzer.parse_entries(entries)
    assert unprovisioned == [] and proxies == []


from src.modules import hci_capture as hci


def test_ad_structures_are_split_correctly():
    payload = (bytes([2, 0x01, 0x06])
               + bytes([3, 0x2B, 0x01, 0xFF])
               + bytes([7, 0x29, 0x11, 0x22, 0x33, 0x44, 0x00, 0x03]))
    ads = hci.parse_ad_structures(payload)
    assert [a.ad_type for a in ads] == [0x01, 0x2B, 0x29]
    assert ads[1].is_mesh and ads[2].is_mesh
    assert ads[0].is_mesh is False
    assert ads[2].data.hex() == "112233440003"


def test_ad_parsing_survives_truncation_and_padding():
    assert hci.parse_ad_structures(b"") == []
    assert hci.parse_ad_structures(bytes([5, 0x2B, 0x01])) == []
    assert len(hci.parse_ad_structures(bytes([2, 0x01, 0x06, 0, 0, 0]))) == 1


def test_le_advertising_report_parsing():
    payload = bytes([2, 0x01, 0x06])
    report = (bytes([1]) + bytes([0x03, 0x00]) + bytes.fromhex("665544332211")
              + bytes([len(payload)]) + payload + struct.pack("b", -55))
    parsed = hci.parse_le_advertising_report(report)
    assert len(parsed) == 1
    assert parsed[0]["mac"] == "11:22:33:44:55:66"
    assert parsed[0]["rssi"] == -55


def test_le_advertising_report_survives_truncation():
    assert hci.parse_le_advertising_report(b"") == []
    assert hci.parse_le_advertising_report(bytes([5])) == []
    assert hci.parse_le_advertising_report(bytes([1, 0x03])) == []


def test_monitor_packet_extraction():
    payload = bytes([3, 0x2B, 0x01, 0xFF])
    report = (bytes([1]) + bytes([0x03, 0x00]) + bytes.fromhex("665544332211")
              + bytes([len(payload)]) + payload + struct.pack("b", -60))
    event = bytes([hci.HCI_EV_LE_META, 1 + len(report),
                   hci.LE_ADVERTISING_REPORT]) + report
    packet = struct.pack("<HHH", hci.MON_EVENT_PKT, 0, len(event)) + event

    parsed = hci._parse_monitor_packet(packet)
    assert len(parsed) == 1
    assert parsed[0]["mac"] == "11:22:33:44:55:66"


def test_monitor_ignores_non_event_packets():
    assert hci._parse_monitor_packet(b"") == []
    assert hci._parse_monitor_packet(b"\x00\x00") == []
    assert hci._parse_monitor_packet(struct.pack("<HHH", hci.MON_COMMAND_PKT, 0, 0)) == []


def test_hci_capture_records_one_frame_per_ad_structure():
    """The output must be readable by the mesh parsers, so raw starts with the
    AD type — unlike a bleak capture."""
    capture = hci.HCIMonitorCapture()
    payload = bytes([2, 0x01, 0x06]) + bytes([3, 0x2B, 0x01, 0xFF])
    capture._record({"mac": "AA:BB:CC:DD:EE:FF", "rssi": -50, "payload": payload}, 1.0)

    assert len(capture.session.frames) == 2
    mesh_frame = [f for f in capture.session.frames if f["ad_type"] == 0x2B][0]
    assert mesh_frame["raw"].startswith("2b")
    assert mesh_frame["mesh"] == "sig_mesh"
    assert capture.session.mesh_frames == 1

    profile = profile_capture(capture.session.frames)
    assert profile.carries_mesh_ad_types is True
    assert profile.source == "sniffer"


def test_hci_capture_reports_why_it_cannot_run():
    ok, reason = hci.HCIMonitorCapture.available()
    assert ok or reason


def _monitor_packet(mac_hex: str, ad_payload: bytes, rssi: int = -55) -> bytes:
    """Build a real monitor-format packet: monitor header + HCI LE Meta event."""
    report = (bytes([1]) + bytes([0x03, 0x00]) + bytes.fromhex(mac_hex)
              + bytes([len(ad_payload)]) + ad_payload + struct.pack("b", rssi))
    event = (bytes([hci.HCI_EV_LE_META, 1 + len(report), hci.LE_ADVERTISING_REPORT])
             + report)
    return struct.pack("<HHH", hci.MON_EVENT_PKT, 0, len(event)) + event


def test_read_loop_decodes_mesh_over_a_socketpair():
    """Exercise the whole decode path without a radio.

    Opening the monitor channel needs root and a real controller, but
    everything after it is ordinary socket reading. Feeding one end of a
    socketpair leaves only the privileged bind() untested.
    """
    import asyncio
    import socket as sockmod

    flags = bytes([2, 0x01, 0x06])
    mesh_beacon = bytes([3, 0x2B, 0x01, 0xFF])
    pb_adv = bytes([9, 0x29, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x03])
    mesh_message = bytes([5, 0x2A, 0x68, 0x80, 0x00, 0x01])
    local_name = bytes([5, 0x09]) + b"Node"

    packets = [
        _monitor_packet("665544332211", flags + mesh_beacon),
        _monitor_packet("665544332211", flags + pb_adv),
        _monitor_packet("aabbccddeeff", local_name + mesh_message, rssi=-70),
        struct.pack("<HHH", hci.MON_COMMAND_PKT, 0, 0),
        b"\x00\x00",
    ]

    async def run():
        rx, tx = sockmod.socketpair(sockmod.AF_UNIX, sockmod.SOCK_DGRAM)
        rx.setblocking(False)
        capture = hci.HCIMonitorCapture()

        async def feed():
            await asyncio.sleep(0.05)
            for packet in packets:
                tx.send(packet)
                await asyncio.sleep(0.02)

        await asyncio.gather(capture.read_loop(rx, duration=1.0), feed())
        rx.close()
        tx.close()
        return capture.session

    session = asyncio.run(run())

    assert len(session.frames) == 6
    assert session.mesh_frames == 3
    assert session.ad_types[0x2B] == 1
    assert session.ad_types[0x29] == 1
    assert session.ad_types[0x2A] == 1

    named = [f for f in session.frames if f["mac"] == "FF:EE:DD:CC:BB:AA"]
    assert named and all(f["name"] == "Node" for f in named)

    profile = profile_capture(session.frames)
    assert profile.carries_mesh_ad_types is True
    assert profile.source == "sniffer"


def test_read_loop_stops_on_a_closed_socket():
    import asyncio
    import socket as sockmod

    async def run():
        rx, tx = sockmod.socketpair(sockmod.AF_UNIX, sockmod.SOCK_DGRAM)
        rx.setblocking(False)
        tx.close()
        capture = hci.HCIMonitorCapture()
        await capture.read_loop(rx, duration=0.6)
        rx.close()
        return capture.session

    assert asyncio.run(run()).frames == []
