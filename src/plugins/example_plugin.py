"""
Example plugin — reads the device name from a BLE target
=========================================================
This is a working example, not just a skeleton.
It connects to the target, reads the Device Name GATT characteristic,
and returns whatever the device reports as its name.

The Device Name char (0x2A00) exists on almost every BLE device,
so this is a safe first thing to try on an unknown target.
"""

import asyncio
from src.core.plugin_base import PluginBase, PluginMeta
from src.utils import logger


class ExamplePlugin(PluginBase):

    meta = PluginMeta(
        name        = "example",
        version     = "1.0",
        description = "Read device name from target (GATT 0x2A00)",
        author      = "T.I.V.",
        category    = "recon",
        requires_bt = True,
    )

    def run(self) -> dict:
        if not self.target:
            return {"error": "No target set — press T in the menu"}
        return asyncio.run(self._read_name())

    async def _read_name(self) -> dict:
        try:
            from bleak import BleakClient
        except ImportError:
            return {"error": "bleak not installed — pip install bleak"}

        # Standard "Device Name" characteristic, part of the Generic Access service
        DEVICE_NAME = "00002a00-0000-1000-8000-00805f9b34fb"

        logger.info(f"Connecting to {self.target}...")

        try:
            async with BleakClient(self.target, adapter=self.adapter) as client:
                raw = await client.read_gatt_char(DEVICE_NAME)
                name = raw.decode("utf-8", errors="replace")
                logger.success(f"Device name: {name}")
        except Exception as e:
            logger.error(f"Failed: {e}")
            return {"error": str(e)}

        return {
            "target":      self.target,
            "device_name": name,
            "raw_hex":     raw.hex(),
        }
