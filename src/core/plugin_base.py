from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class PluginMeta:
    name:             str
    version:          str
    description:      str
    author:           str
    category:         str   # recon | capture | firmware | fuzz | exploit | post
    phase:            int = 0
    requires_bt:      bool = True
    requires_root:    bool = False
    requires_pcap:    bool = False
    requires_firmware: bool = False
    tags:             list[str] = field(default_factory=list)


class PluginBase(ABC):
    meta: PluginMeta

    def __init__(self, target=None, adapter="hci0", session=None, config=None):
        self.target  = target
        self.adapter = adapter
        self.session = session
        # Extra options from the command line, e.g. --netkey or --opt key=value.
        # Optional so plugins written before this existed keep working.
        self.config  = config or {}
        self.results = {}

    @abstractmethod
    def run(self):
        ...

    def set_target(self, mac):
        self.target = mac

    def option(self, name, default=None):
        """Read a command-line option passed to this plugin."""
        return self.config.get(name, default)

    def require(self, name):
        """Read an option that the plugin cannot run without."""
        value = self.config.get(name)
        if value in (None, ""):
            raise ValueError(f"{self.meta.name} requires --{name.replace('_', '-')}")
        return value
