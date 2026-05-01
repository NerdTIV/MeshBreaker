import time
from dataclasses import dataclass, field


@dataclass
class SessionState:
    target_mac: str | None = None
    target_ip: str | None = None
    adapter: str = "hci0"
    scan_time: float = 10.0
    devices: list[dict] = field(default_factory=list)
    mesh_protocol: str | None = None
    mesh_keys: dict = field(default_factory=dict)
    pcap_file: str | None = None
    firmware_path: str | None = None
    results: dict = field(default_factory=dict)
    session_id: str = field(default_factory=lambda: str(int(time.time())))
    output_dir: str = "./output"

    def set_target(self, mac):
        self.target_mac = mac.upper().strip()

    def store(self, phase, data):
        self.results[phase] = data

    def get(self, phase, default=None):
        return self.results.get(phase, default)
