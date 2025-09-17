import ipaddress
import re
import socket
import ifaddr
import struct
import time

from typing import List, Tuple, Optional
from typing import Dict

FAKE_SUBNET_DEFAULT = "172.30.0.0/24"  # 你可以改成 172.30.0.0/16 或更具体的 /24


def get_ipaddrs(adapter):
    ipaddrs = []
    for ip in adapter.ips:
        ipaddrs.append(ip.ip)
    return ipaddrs

def get_interfaces():
    interfaces = []
    for adapter in ifaddr.get_adapters():
        if adapter.name == 'lo':
            continue
        interfaces.append({'name': adapter.name, 'ips': get_ipaddrs(adapter)})
    return interfaces

def _iface_is_veth(name: str) -> bool:
    return bool(re.match(r"^veth", name))

def _ip_in_subnet(ip: str, subnet_cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet_cidr, strict=False)
    except Exception:
        return False

def _candidate_fake_ifaces(interfaces: List[dict], subnet_cidr: str) -> List[dict]:
    """
    从 get_interfaces() 的结果里挑出可能挂 fake LiDAR 的网卡：
    - 名称以 veth 开头；或
    - 网卡自身有 IP 落在指定子网（例如 172.30.0.0/16 / /24）
    """
    cands = []
    for itf in interfaces:
        if _iface_is_veth(itf["name"]):
            cands.append(itf)
            continue
        if any(_ip_in_subnet(ip, subnet_cidr) for ip in itf["ips"] if isinstance(ip, str)):
            cands.append(itf)
    return cands

def pack_timeval(seconds: float) -> bytes:
    sec = int(seconds)
    usec = int((seconds - sec) * 1_000_000)
    return struct.pack("ll", sec, usec)   # 有些平台用 "ii" 也可


def _in_subnet(ip: str, subnet_cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet_cidr, strict=False)
    except Exception:
        return False

def discover_fake_lidar_on_interface_udp(
    interface: Dict,
    subnet_cidr: str = "172.30.0.0/24",
    port: int = 8011,
    listen_seconds: float = 3.0,
    per_recv_timeout: float = 0.3,
    min_packets: int = 1,
    sample_payload_bytes: int = 32,
) -> List[Tuple[str, bytes]]:
    """
    在指定网卡上监听 UDP:port（默认 8011）。
    收集来自 subnet_cidr 源 IP 的数据包样本，返回 [(src_ip, payload_prefix), ...]。
    注意：仅截取前 sample_payload_bytes 字节作为样本以避免刷屏。
    需要 root 权限 (SO_BINDTODEVICE)。
    """
    if_name = interface["name"]

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # 绑定到指定网卡（需要 sudo/cap）
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, if_name.encode())
    s.bind(("0.0.0.0", port))
    s.settimeout(per_recv_timeout)

    end_ts = time.time() + listen_seconds
    samples: List[Tuple[str, bytes]] = []

    while time.time() < end_ts:
        try:
            data, addr = s.recvfrom(65535)  # addr = (src_ip, src_port)
        except socket.timeout:
            continue
        except OSError:
            break

        src_ip, _src_port = addr
        if _in_subnet(src_ip, subnet_cidr):
            samples.append((src_ip, data[:sample_payload_bytes]))
            if len(samples) >= min_packets:
                break

    s.close()
    return samples

def discovery_fake_lidar_interface(
    subnet_cidr: str = FAKE_SUBNET_DEFAULT,
) -> Optional[str]:
    """
    遍历候选(veth* 或落在 subnet_cidr 的）网卡查找 fake LiDAR。
    成功则返回网卡名（如 vethd85986f), 并打印发现的设备信息；失败返回 None。
    """
    interfaces = get_interfaces()
    candidates = _candidate_fake_ifaces(interfaces, subnet_cidr)
    if not candidates:
        print(f"No candidate interfaces for {subnet_cidr}.")
        return None

    print("Candidate interfaces:", ", ".join(i["name"] for i in candidates))
    for itf in candidates:
        print(f"[fake-scan] Probing on {itf['name']} in {subnet_cidr} ...")
        found = discover_fake_lidar_on_interface_udp(
            itf,
            subnet_cidr=subnet_cidr,
            port=8011,
            listen_seconds=3.0,
            per_recv_timeout=0.3,
            min_packets=1
        )
        if found:
            for ip, payload in found:
                print(f"  Found fake LiDAR at {ip}: {itf['name']} ")
            return itf["name"]
    return None


if __name__ == "__main__":
    discovery_fake_lidar_interface()