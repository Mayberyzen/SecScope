

import datetime
import socket

import psutil

try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    sniff = None
    IP = TCP = UDP = None


def list_interfaces() -> list:
    """Return list of network interface names."""
    interfaces = []
    try:
        addrs = psutil.net_if_addrs()
        interfaces = list(addrs.keys())
    except Exception:
        pass
    return interfaces


def _format_addr(addr) -> str:
    if not addr:
        return ""
    if isinstance(addr, tuple):
        return f"{addr[0]}:{addr[1]}"
    return str(addr)


def score_connection(conn: psutil._common.sconn) -> float:
    """
    Very simple heuristic risk scoring.
    """
    score = 0.0

    # Remote address check
    if conn.raddr:
        ip = conn.raddr.ip if hasattr(conn.raddr, "ip") else conn.raddr[0]
        try:
            socket.inet_aton(ip)
            if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
                score += 5
            else:
                score += 25  # external IP
        except OSError:
            score += 10

    # Status
    if conn.status not in ("ESTABLISHED", "LISTEN"):
        score += 10

    # Port-based heuristics
    try:
        dport = conn.raddr.port
    except Exception:
        dport = None

    if dport in (22, 3389):
        score += 20
    if dport in (4444, 1337, 5555):
        score += 30

    # Process
    pname = ""
    if conn.pid:
        try:
            pname = psutil.Process(conn.pid).name().lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pname = ""

    if pname and any(k in pname for k in ("tor", "proxy", "ngrok")):
        score += 25

    return min(score, 100.0)


def get_active_connections() -> list:
    """
    Return list of active connections with basic metadata and risk score.
    """
    results = []
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        conns = []

    for c in conns:
        try:
            laddr = _format_addr((c.laddr.ip, c.laddr.port)) if c.laddr else ""
            raddr = _format_addr((c.raddr.ip, c.raddr.port)) if c.raddr else ""
        except AttributeError:
            laddr = _format_addr(c.laddr)
            raddr = _format_addr(c.raddr)

        pid = c.pid or 0
        try:
            process_name = psutil.Process(pid).name() if pid else ""
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            process_name = ""

        risk = score_connection(c)
        results.append(
            {
                "laddr": laddr,
                "raddr": raddr,
                "status": c.status,
                "pid": pid,
                "process": process_name,
                "risk_score": risk,
            }
        )
    return results


def score_packet(src_ip: str, dst_ip: str, sport, dport, proto: str) -> float:
    score = 0.0

    # External IP?
    for ip in (src_ip, dst_ip):
        if not ip:
            continue
        try:
            socket.inet_aton(ip)
            if not (
                ip.startswith("10.")
                or ip.startswith("192.168.")
                or ip.startswith("172.16.")
                or ip.startswith("127.")
            ):
                score += 10
        except OSError:
            score += 5

    # Port heuristics
    risky_ports = {22, 23, 445, 3389, 5555, 4444}
    if sport in risky_ports or dport in risky_ports:
        score += 30

    if proto.upper() == "TCP" and (sport == 80 or dport == 80):
        score += 5

    return min(score, 100.0)


class PacketSniffer:
    """
    Simple scapy-based packet sniffer that calls a callback with packet info dictionaries.
    """

    def __init__(self, interface: str):
        if sniff is None:
            raise ImportError("scapy is required for packet sniffing.")
        self.interface = interface

    def start_sniffing(self, callback, stop_event):
        """
        Start sniffing packets on the given interface.

        :param callback: function(packet_info_dict)
        :param stop_event: threading.Event used to request stop
        """

        def process(pkt):
            if IP is None or not pkt.haslayer(IP):
                return

            ip_layer = pkt[IP]
            src = ip_layer.src
            dst = ip_layer.dst
            sport = None
            dport = None
            proto = "IP"

            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                sport = tcp_layer.sport
                dport = tcp_layer.dport
                proto = "TCP"
            elif pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                sport = udp_layer.sport
                dport = udp_layer.dport
                proto = "UDP"

            risk = score_packet(src, dst, sport, dport, proto)
            packet_info = {
                "time": datetime.datetime.now().strftime("%H:%M:%S"),
                "src": src,
                "dst": dst,
                "sport": sport,
                "dport": dport,
                "proto": proto,
                "risk_score": risk,
            }
            callback(packet_info)

        def stop_filter(_):
            return stop_event.is_set()

        sniff(
            iface=self.interface,
            prn=process,
            store=False,
            stop_filter=stop_filter,
        )
