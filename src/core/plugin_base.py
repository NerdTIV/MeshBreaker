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

    def __init__(self, target=None, adapter="hci0", session=None):
        self.target  = target
        self.adapter = adapter
        self.session = session
        self.results = {}

    @abstractmethod
    def run(self):
        ...

    def set_target(self, mac):
        self.target = mac
