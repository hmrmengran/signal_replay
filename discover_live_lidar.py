#!/usr/bin/env python3

import struct
import ifaddr
from socket import *
from sys import argv, exit
from typing import Optional

def timeout(s):
    return struct.pack("ll", int(s), int(s - int(s)) * 1000000)

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

def discover_lidars(interface):
    s = socket(AF_INET, SOCK_DGRAM)
    s.setsockopt(SOL_SOCKET, SO_BINDTODEVICE, interface['name'].encode())
    s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    s.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
    s.setsockopt(SOL_SOCKET, SO_RCVTIMEO, timeout(3))
    s.bind(('', 16800))
    s.sendto(b'Innovusion Host Search',('255.255.255.255', 16800))

    lidars = []
    while True:
        try:
            data, addr = s.recvfrom(1024)
        except Exception as e:
            break
        if addr[0] in interface['ips']:
            continue
        lidars.append(data.decode(errors='ignore'))

    return lidars

def dump_lidars(lidars):
    for lidar in lidars:
        print(lidar)

def discovery_live_lidar_interface() -> Optional[str]:
    """
    遍历所有非 lo 网卡，尝试发现 LiDAR。
    如果发现成功，返回网卡名称（例如 'eno1'），否则返回 None。
    """
    interfaces = get_interfaces()
    for interface in interfaces:
        print(f"Discovering Lidar on {interface['name']}")
        lidars = discover_lidars(interface)
        if lidars:
            dump_lidars(lidars)
            return interface['name']
    return None

if __name__ == "__main__":
    iface = discovery_live_lidar_interface()
    if iface is None:
        print("No LiDAR found.")
    else:
        print(f"Found LiDAR on interface: {iface}")
