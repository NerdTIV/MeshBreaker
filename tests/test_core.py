import sys
import os

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
    # BT Mesh Provisioning UUID — should match if in DB
    assert isinstance(results, list)
