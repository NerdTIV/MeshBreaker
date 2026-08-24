"""
Template — BLE Mesh attack plugin
===================================
Copy this, rename it (e.g. proxy_cfg_inject.py), and fill in your logic.
Don't keep the "template_" prefix — those files are skipped at load time.

Use this for any active attack against a BLE Mesh device:
- Write a crafted packet to a GATT characteristic
- Send a malformed mesh PDU through the Proxy Service
- Inject a rogue provisioning request
- Replay a captured mesh message

How BLE Mesh Proxy works (quick version):
    The device exposes a "Mesh Proxy Service" over GATT.
    You connect via BLE and write raw mesh packets to the "Proxy In" characteristic.
    The device processes them as if they came from the mesh network itself.

    Proxy In  UUID: 00002add-0000-1000-8000-00805f9b34fb   ← you write here
    Proxy Out UUID: 00002ade-0000-1000-8000-00805f9b34fb   ← responses come here
"""

import asyncio
from src.core.plugin_base import PluginBase, PluginMeta

PROXY_IN  = "00002add-0000-1000-8000-00805f9b34fb"
PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"


class MyMeshAttackPlugin(PluginBase):

    meta = PluginMeta(
        name          = "my_mesh_attack",
        version       = "1.0",
        description   = "Short description shown in the menu",
        author      = "T.I.V.",
        category      = "exploit",
        requires_bt   = True,
        requires_root = True,
    )

    def run(self) -> dict:
        return asyncio.run(self.async_run())

    async def async_run(self) -> dict:
        """
        What you have:
            self.target   → target MAC address
            self.adapter  → BT adapter, e.g. "hci0"
        """
        from src.utils import logger

        if not self.target:
            return {"error": "No target. Press T to set a MAC address."}

        try:
            from bleak import BleakClient
        except ImportError:
            return {"error": "bleak not installed. Run: pip install bleak"}

        logger.info(f"Connecting to {self.target}...")

        try:
            async with BleakClient(self.target, adapter=self.adapter) as client:
                logger.success(f"Connected to {self.target}")

                my_payload = bytes([0x00] * 20)

                await client.write_gatt_char(PROXY_IN, my_payload, response=True)
                logger.info(f"Sent {len(my_payload)} bytes")


        except Exception as e:
            logger.error(f"Attack failed: {e}")
            return {"error": str(e)}

        return {
            "target":  self.target,
            "payload": my_payload.hex(),
            "status":  "sent",
        }
