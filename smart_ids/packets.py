"""A tiny packet record used everywhere, so detection logic never depends on Scapy.

Keeping detection separate from packet capture means we can unit-test it and
evaluate it on recorded or synthetic traffic without sniffing a real network.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Pkt:
    ts: float          # seconds (epoch or simulated)
    src: str           # source IP
    dst: str           # destination IP
    proto: str         # "TCP", "UDP" or "ICMP"
    dport: int = 0     # destination port (0 for ICMP)
    flags: str = ""    # TCP flags as letters, e.g. "S" (SYN), "SA", "A"
    length: int = 0    # packet size in bytes
