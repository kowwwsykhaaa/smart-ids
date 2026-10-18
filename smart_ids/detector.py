"""Rule-based detection: three simple, explainable rules with time windows.

Rule                 Fires when one source IP ...
-------------------  ----------------------------------------------------------
SSH Brute Force      sends >= 6 TCP SYN packets to port 22 within 60 s
Port Scan            sends SYNs to >= 15 different ports within 30 s
ICMP Flood           sends > 100 ICMP packets within 10 s

Each rule has a cooldown per source so one attack gives one alert, not hundreds.
"""
from collections import defaultdict, deque
from dataclasses import dataclass

from .packets import Pkt


@dataclass
class Alert:
    ts: float
    ip: str
    attack: str
    severity: str
    port: int
    protocol: str
    source: str = "rule"      # "rule" or "ml"


SEVERITY_SCORE = {"Critical": 90, "High": 65, "Medium": 40, "Low": 15}


class RuleDetector:
    def __init__(self, ssh_syns=6, ssh_window=60,
                 scan_ports=15, scan_window=30,
                 icmp_count=101, icmp_window=10, cooldown=60):
        self.ssh_syns, self.ssh_window = ssh_syns, ssh_window
        self.scan_ports, self.scan_window = scan_ports, scan_window
        self.icmp_count, self.icmp_window = icmp_count, icmp_window
        self.cooldown = cooldown
        self._ssh = defaultdict(deque)        # src -> timestamps of SYNs to :22
        self._scan = defaultdict(deque)       # src -> (ts, dport) of SYNs
        self._icmp = defaultdict(deque)       # src -> timestamps of ICMP
        self._last = {}                       # (src, attack) -> last alert ts

    @staticmethod
    def _evict(dq, now, window, key=lambda x: x):
        while dq and now - key(dq[0]) > window:
            dq.popleft()

    def _fire(self, p, attack, severity, port):
        last = self._last.get((p.src, attack))
        if last is not None and p.ts - last < self.cooldown:
            return None
        self._last[(p.src, attack)] = p.ts
        return Alert(p.ts, p.src, attack, severity, port, p.proto)

    def process(self, p: Pkt):
        """Feed one packet; returns a list of new alerts (usually empty)."""
        out = []
        is_syn = p.proto == "TCP" and p.flags == "S"

        if is_syn:
            if p.dport == 22:
                dq = self._ssh[p.src]
                dq.append(p.ts)
                self._evict(dq, p.ts, self.ssh_window)
                if len(dq) >= self.ssh_syns:
                    a = self._fire(p, "Brute Force", "Critical", 22)
                    if a: out.append(a)

            dq = self._scan[p.src]
            dq.append((p.ts, p.dport))
            self._evict(dq, p.ts, self.scan_window, key=lambda x: x[0])
            if len({port for _, port in dq}) >= self.scan_ports:
                a = self._fire(p, "Port Scan", "High", p.dport)
                if a: out.append(a)

        if p.proto == "ICMP":
            dq = self._icmp[p.src]
            dq.append(p.ts)
            self._evict(dq, p.ts, self.icmp_window)
            if len(dq) >= self.icmp_count:
                a = self._fire(p, "ICMP Flood", "Critical", 0)
                if a: out.append(a)
        return out
