"""
Backend: basic system health & security checks.

NOTE: A lot of this is heuristic and OS-dependent.
"""

import platform
import subprocess
from typing import List, Tuple

try:
    import psutil
except ImportError:
    psutil = None

try:
    import requests
except ImportError:
    requests = None


# ------------------------------------------------------------
# Helper: run a system command safely
# ------------------------------------------------------------
def _run_command(cmd: list) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=10)
        return out.strip()
    except Exception:
        return ""


# ------------------------------------------------------------
# Firewall Status
# ------------------------------------------------------------
def check_firewall_status() -> str:
    system = platform.system().lower()

    if "windows" in system:
        out = _run_command(["netsh", "advfirewall", "show", "allprofiles"])
        if "ON" in out.upper():
            return "Enabled"
        if "OFF" in out.upper():
            return "Disabled"
        return "Unknown (netsh)"

    elif "linux" in system:
        out = _run_command(["ufw", "status"])
        if "Status: active" in out:
            return "Enabled (ufw)"
        if "Status: inactive" in out:
            return "Disabled (ufw)"
        return "Unknown (ufw)"

    return "Unknown"


# ------------------------------------------------------------
# Defender Status
# ------------------------------------------------------------
def check_defender_status() -> str:
    system = platform.system().lower()

    if "windows" in system:
        cmd = [
            "powershell",
            "-Command",
            "Try { (Get-MpComputerStatus).RealTimeProtectionEnabled } Catch { '' }",
        ]
        out = _run_command(cmd)
        if "True" in out:
            return "Windows Defender: Real-time protection ON"
        if "False" in out:
            return "Windows Defender: Real-time protection OFF"
        return "Windows Defender: Unknown"

    return "AV status not available (non-Windows)"


# ------------------------------------------------------------
# SmartScreen
# ------------------------------------------------------------
def check_smartscreen_status() -> str:
    system = platform.system().lower()

    if "windows" in system:
        cmd = [
            "reg",
            "query",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
            "/v",
            "SmartScreenEnabled",
        ]
        out = _run_command(cmd)
        if "RequireAdmin" in out or "On" in out:
            return "SmartScreen: Enabled"
        if "Off" in out:
            return "SmartScreen: Disabled"
        return "SmartScreen: Unknown"

    return "SmartScreen: Not available"


# ------------------------------------------------------------
# Public IP
# ------------------------------------------------------------
def get_public_ip() -> str:
    if requests is None:
        return "requests not installed"

    try:
        return requests.get("https://api.ipify.org", timeout=5).text.strip()
    except Exception:
        return "Unable to fetch"

def get_dns_and_gateway() -> Tuple[List[str], str]:
    dns_servers: List[str] = []
    gateway: str = "Unknown"

    if psutil is None:
        return dns_servers, gateway

    system = platform.system().lower()

    if "windows" in system:
        out = _run_command(["ipconfig", "/all"])
        for line in out.splitlines():
            l = line.strip()

            if l.lower().startswith("dns servers"):
                parts = l.split(":", 1)
                if len(parts) == 2:
                    dns_servers.append(parts[1].strip())

            elif l.lower().startswith("default gateway"):
                parts = l.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    gateway = parts[1].strip()

    else:
        
        out = _run_command(["cat", "/etc/resolv.conf"])
        for line in out.splitlines():
            l = line.strip()
            if l.startswith("nameserver"):
                parts = l.split()
                if len(parts) >= 2:
                    dns_servers.append(parts[1])
        out_route = _run_command(["ip", "route"])
        for line in out_route.splitlines():
            if line.startswith("default via"):
                parts = line.split()
                if len(parts) >= 3:
                    gateway = parts[2]
                    break

    return dns_servers, gateway

def get_startup_programs() -> List[dict]:
    system = platform.system().lower()
    programs: List[dict] = []

    if "windows" in system:
        out = _run_command(["wmic", "startup", "get", "Caption,Command,User"])
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue

            programs.append(
                {
                    "name": line.split()[0][:40],
                    "location": line,
                    "enabled": True,
                }
            )

    return programs
def compute_risk_score(
    firewall_status: str,
    defender_status: str,
    smartscreen_status: str,
    startup_programs: List[dict],
) -> float:

    score = 0.0

    if "enabled" in firewall_status.lower():
        score += 30
    elif "disabled" in firewall_status.lower():
        score -= 20

    if "real-time protection on" in defender_status.lower():
        score += 30
    elif "off" in defender_status.lower():
        score -= 15

    if "enabled" in smartscreen_status.lower():
        score += 10
    elif "disabled" in smartscreen_status.lower():
        score -= 10

    startup_count = len(startup_programs)
    if startup_count > 20:
        score -= 10
    elif startup_count > 10:
        score -= 5

    score = max(0.0, min(100.0, 50.0 + score))
    return score
def build_summary(
    firewall_status: str,
    defender_status: str,
    smartscreen_status: str,
    public_ip: str,
    dns_servers: List[str],
    gateway: str,
    risk_score: float,
) -> str:

    lines = [
        f"Firewall: {firewall_status}",
        f"Defender / AV: {defender_status}",
        f"SmartScreen: {smartscreen_status}",
        f"Public IP: {public_ip}",
        f"DNS: {', '.join(dns_servers) if dns_servers else 'Unknown'}",
        f"Gateway: {gateway}",
        "",
        f"Overall Risk Score: {risk_score:.1f}/100",
        "",
    ]

    if risk_score >= 80:
        lines.append("System appears fairly hardened.")
    elif risk_score >= 50:
        lines.append("System is moderately secure. Review the findings above.")
    else:
        lines.append("System may be at higher risk. Check firewall/AV and startup programs.")

    return "\n".join(lines)


# ------------------------------------------------------------
# Main System Health Scan
# ------------------------------------------------------------
def run_system_health_scan() -> dict:
    firewall_status = check_firewall_status()
    defender_status = check_defender_status()
    smartscreen_status = check_smartscreen_status()
    public_ip = get_public_ip()
    dns_servers, gateway = get_dns_and_gateway()
    startup_programs = get_startup_programs()

    risk_score = compute_risk_score(
        firewall_status,
        defender_status,
        smartscreen_status,
        startup_programs,
    )

    summary = build_summary(
        firewall_status,
        defender_status,
        smartscreen_status,
        public_ip,
        dns_servers,
        gateway,
        risk_score,
    )

    return {
        "firewall_status": firewall_status,
        "defender_status": defender_status,
        "smartscreen_status": smartscreen_status,
        "public_ip": public_ip,
        "dns_servers": dns_servers,
        "gateway": gateway,
        "startup_programs": startup_programs,
        "risk_score": risk_score,
        "summary": summary,
    }
