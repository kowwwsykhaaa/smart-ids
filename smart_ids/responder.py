"""Blocking an IP is dangerous if it goes wrong, so it is OFF by default.

Safety rules in this file:
- Default is dry-run: the block is logged but no firewall rule is added.
- Only PUBLIC IP addresses can ever be blocked (never private, loopback, or
  documentation ranges), so you cannot lock yourself out of your own network.
- The IP is validated and passed as a list argument (no shell, no injection).
"""
import ipaddress
import platform
import subprocess


def is_blockable(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _cmd(action: str, ip: str):
    if platform.system() == "Windows":
        if action == "add":
            return ["netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=IDS_BLOCK_{ip}", "dir=in", "action=block", f"remoteip={ip}"]
        return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=IDS_BLOCK_{ip}"]
    flag = "-A" if action == "add" else "-D"
    return ["iptables", flag, "INPUT", "-s", ip, "-j", "DROP"]


def block(ip: str, enforce: bool) -> str:
    if not is_blockable(ip):
        return "skipped: not a public IP"
    if not enforce:
        return "dry-run: block not applied"
    r = subprocess.run(_cmd("add", ip), capture_output=True, text=True)
    return "blocked" if r.returncode == 0 else f"failed: {r.stderr.strip() or r.stdout.strip()}"


def unblock(ip: str, enforce: bool) -> str:
    if not is_blockable(ip):
        return "skipped: not a public IP"
    if not enforce:
        return "dry-run: nothing to remove"
    r = subprocess.run(_cmd("delete", ip), capture_output=True, text=True)
    return "unblocked" if r.returncode == 0 else f"failed: {r.stderr.strip() or r.stdout.strip()}"
