from dataclasses import dataclass
from enum import StrEnum, auto


@dataclass
class PortsScheme:
    start: int
    end: int


class PolicyTypes(StrEnum):
    ips=auto()
    protocols=auto()
    ports=auto()
    ip_and_port=auto()


class RolesVerdicts(StrEnum):
    CLEAN='CLEAN'
    SUSPICIOUS='SUSPICIOUS'
