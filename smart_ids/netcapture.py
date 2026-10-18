"""Live capture: converts Scapy packets into our simple Pkt records."""
import time

from .packets import Pkt


def to_pkt(sp, now=None):
    """Convert one Scapy packet to Pkt, or None if it is not IPv4."""
    from scapy.all import IP, TCP, UDP, ICMP
    if not sp.haslayer(IP):
        return None
    ip = sp[IP]
    ts = now if now is not None else time.time()
    if sp.haslayer(TCP):
        return Pkt(ts, ip.src, ip.dst, "TCP", int(sp[TCP].dport), str(sp[TCP].flags), len(sp))
    if sp.haslayer(UDP):
        return Pkt(ts, ip.src, ip.dst, "UDP", int(sp[UDP].dport), "", len(sp))
    if sp.haslayer(ICMP):
        return Pkt(ts, ip.src, ip.dst, "ICMP", 0, "", len(sp))
    return None


def sniff_forever(on_packet):
    """Needs admin rights and Npcap (Windows) or root (Linux)."""
    from scapy.all import sniff

    def cb(sp):
        p = to_pkt(sp)
        if p:
            on_packet(p)

    sniff(filter="ip", prn=cb, store=False)
