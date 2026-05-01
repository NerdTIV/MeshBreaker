"""
Template — Firmware analysis plugin
=====================================
Copy this, rename it (e.g. find_hardcoded_keys.py), and fill in your logic.
Don't keep the "template_" prefix — those files are skipped at load time.

Use this type of plugin when you want to dig into a firmware binary:
- Search for specific byte patterns or strings
- Extract a custom key format
- Detect a particular RTOS or bootloader version
- Find hardcoded IPs, credentials, or API endpoints

The firmware path is set during Phase 3 (Firmware Analysis).
If the user hasn't done that yet, you can ask for a path manually.
"""

from pathlib import Path
from src.core.plugin_base import PluginBase, PluginMeta


class MyFirmwarePlugin(PluginBase):

    meta = PluginMeta(
        name              = "my_firmware",
        version           = "1.0",
        description       = "Short description shown in the menu",
        author      = "T.I.V.",
        category          = "recon",
        requires_bt       = False,
        requires_firmware = True,
    )

    def run(self) -> dict:
        """
        What you have:
            self.session.firmware_path          → path to the binary set in Phase 3
                                                  None if Phase 3 hasn't run yet.
            self.session.get("firmware")        → dict with what Phase 3 already found:
                                                  arch, rtos, soc, urls, credentials, etc.
        """
        from src.utils import logger

        # Get the firmware path
        firmware_path = None
        if self.session:
            firmware_path = self.session.firmware_path

        if not firmware_path or not Path(firmware_path).exists():
            logger.error("No firmware loaded. Run Phase 3 first, or press W in the menu.")
            return {"error": "No firmware path"}

        data = Path(firmware_path).read_bytes()
        logger.info(f"Loaded {len(data):,} bytes from {firmware_path}")

        # Your analysis logic goes here.
        # This example searches for a 4-byte magic value.
        MAGIC = b"\xDE\xAD\xBE\xEF"
        hits = []
        for i in range(len(data) - 4):
            if data[i:i+4] == MAGIC:
                hits.append(hex(i))

        logger.success(f"Found magic bytes at {len(hits)} offset(s)")

        return {
            "firmware":   firmware_path,
            "magic_hits": hits,
        }
