"""
Template — Recon plugin
========================
Copy this file, give it a proper name (like gatt_scan.py), and fill in your logic.
Don't keep the "template_" prefix — files starting with template_ aren't loaded.

A recon plugin is anything that collects info without actively attacking:
- Read GATT characteristics
- Parse advertisement data
- Map nearby nodes
- Probe open services

The target MAC and BT adapter come from the MeshBreaker session (set with T in the menu).
You just write the logic and return a dict with your findings.
"""

from src.core.plugin_base import PluginBase, PluginMeta


class MyReconPlugin(PluginBase):

    meta = PluginMeta(
        name        = "my_recon",
        version     = "1.0",
        description = "Short description that shows up in the menu",
        author      = "T.I.V.",
        category    = "recon",
    )

    def run(self) -> dict:
        """
        MeshBreaker calls this when you pick your plugin from the menu.

        What you have:
            self.target   → MAC address, e.g. "AA:BB:CC:DD:EE:FF"
                            Will be None if the user hasn't set a target yet.
            self.adapter  → BT adapter name, e.g. "hci0"
            self.session  → Results from earlier phases. Examples:
                              self.session.get("gatt")        → GATT services/chars
                              self.session.get("capture_file") → path to a .json capture
                              self.session.mesh_protocol       → "sig_mesh", "wirepas", etc.

        What you return:
            A plain dict with whatever you found. Any keys, any values.
            The dict gets saved in the session and included in the final report.
        """

        if not self.target:
            return {"error": "No target set. Press T in the menu to set a MAC address."}

        from src.utils import logger

        logger.info(f"Scanning {self.target} on adapter {self.adapter}...")

        result = {
            "target":  self.target,
            "adapter": self.adapter,
            "note":    "Replace this with your actual recon logic",
        }

        logger.success("Done!")
        return result
