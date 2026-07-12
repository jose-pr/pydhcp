from __future__ import annotations

import sys
import socket
import ipaddress
import subprocess
import ctypes
import re
import os
import logging
import typing as _ty

LOGGER = logging.getLogger("pydhcp")

def _mask_to_prefix(mask_str: str) -> int:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask_str}").prefixlen
    except Exception:
        return 24

def _parse_ipconfig() -> list[tuple[str, ipaddress.IPv4Interface | ipaddress.IPv6Interface, bytes | None]]:
    """Parse ipconfig /all output on Windows."""
    results: list[tuple[str, ipaddress.IPv4Interface | ipaddress.IPv6Interface, bytes | None]] = []
    try:
        # Run ipconfig /all with system default OEM code page or utf-8
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        output = subprocess.check_output(
            ["ipconfig", "/all"],
            startupinfo=startupinfo,
            text=True,
            encoding="oem",
            errors="ignore"
        )
    except Exception as e:
        LOGGER.debug(f"Failed to run ipconfig: {e}")
        return results

    current_adapter: _ty.Optional[str] = None
    mac: _ty.Optional[bytes] = None
    ips: list[tuple[str, int]] = []

    # Regex patterns
    adapter_pat = re.compile(r"^(?:Ethernet adapter|Wireless LAN adapter|Unknown adapter|Adapter)\s+(.*?):")
    mac_pat = re.compile(r"Physical Address.*:\s*([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})")
    ipv4_pat = re.compile(r"IPv4 Address.*:\s*([0-9.]+)")
    mask_pat = re.compile(r"Subnet Mask.*:\s*([0-9.]+)")
    ipv6_pat = re.compile(r"IPv6 Address.*:\s*([0-9a-fA-F:]+)")

    last_ipv4: _ty.Optional[str] = None

    for line in output.splitlines():
        line_strip = line.strip()
        if not line.startswith(" ") and line_strip:
            # New adapter section
            if current_adapter and (ips or mac):
                for ip_str, prefix in ips:
                    try:
                        iface: ipaddress.IPv4Interface | ipaddress.IPv6Interface
                        if ":" in ip_str:
                            iface = ipaddress.IPv6Interface(ip_str)
                        else:
                            iface = ipaddress.IPv4Interface(f"{ip_str}/{prefix}")
                        results.append((current_adapter, iface, mac))
                    except Exception:
                        pass
            current_adapter = None
            m = adapter_pat.match(line_strip)
            if m:
                current_adapter = m.group(1)
            mac = None
            ips = []
            last_ipv4 = None
            continue

        if not current_adapter:
            continue

        m_mac = mac_pat.search(line_strip)
        if m_mac:
            mac_str = m_mac.group(1).replace("-", "")
            try:
                mac = bytes.fromhex(mac_str)
            except Exception:
                mac = None
            continue

        m_ipv4 = ipv4_pat.search(line_strip)
        if m_ipv4:
            last_ipv4 = m_ipv4.group(1)
            continue

        m_mask = mask_pat.search(line_strip)
        if m_mask and last_ipv4:
            prefix = _mask_to_prefix(m_mask.group(1))
            ips.append((last_ipv4, prefix))
            last_ipv4 = None
            continue

        m_ipv6 = ipv6_pat.search(line_strip)
        if m_ipv6:
            ip_str = m_ipv6.group(1)
            ips.append((ip_str, 64))
            continue

    if current_adapter and (ips or mac):
        for ip_str, prefix in ips:
            try:
                iface_val: ipaddress.IPv4Interface | ipaddress.IPv6Interface
                if ":" in ip_str:
                    iface_val = ipaddress.IPv6Interface(ip_str)
                else:
                    iface_val = ipaddress.IPv4Interface(f"{ip_str}/{prefix}")
                results.append((current_adapter, iface_val, mac))
            except Exception:
                pass

    return results

def _parse_ip_addr() -> list[tuple[str, ipaddress.IPv4Interface | ipaddress.IPv6Interface, bytes | None]]:
    """Parse ip addr output on Linux/POSIX."""
    results: list[tuple[str, ipaddress.IPv4Interface | ipaddress.IPv6Interface, bytes | None]] = []
    try:
        output = subprocess.check_output(
            ["ip", "addr", "show"],
            text=True,
            errors="ignore"
        )
    except Exception:
        try:
            output = subprocess.check_output(
                ["ifconfig"],
                text=True,
                errors="ignore"
            )
        except Exception:
            return results

    # Simple best-effort parser for ip addr show
    current_iface: _ty.Optional[str] = None
    mac: _ty.Optional[bytes] = None
    
    # Matches Linux "ip addr": "2: eth0: <BROADCAST...>"
    iface_pat = re.compile(r"^\d+:\s+([^:]+):")
    # Matches MAC: "link/ether 00:11:22:33:44:55"
    mac_pat = re.compile(r"link/\w+\s+([0-9a-fA-F:]{17})")
    # Matches IPv4/IPv6 address: "inet 192.168.1.10/24", "inet6 fe80::1/64"
    inet_pat = re.compile(r"inet6?\s+([0-9a-fA-F.:]+/\d+)")

    for line in output.splitlines():
        line_strip = line.strip()
        if not line.startswith(" ") and line_strip:
            m = iface_pat.match(line_strip)
            if m:
                current_iface = m.group(1)
                mac = None
            continue
        if not current_iface:
            continue
        
        m_mac = mac_pat.search(line_strip)
        if m_mac:
            try:
                mac = bytes.fromhex(m_mac.group(1).replace(":", ""))
            except Exception:
                mac = None
        
        m_inet = inet_pat.search(line_strip)
        if m_inet:
            try:
                addr_part = m_inet.group(1)
                iface_obj: ipaddress.IPv4Interface | ipaddress.IPv6Interface
                if ":" in addr_part:
                    iface_obj = ipaddress.IPv6Interface(addr_part)
                else:
                    iface_obj = ipaddress.IPv4Interface(addr_part)
                results.append((current_iface, iface_obj, mac))
            except Exception:
                pass
                
    return results

def _get_interfaces_ctypes_posix() -> list[tuple[str, ipaddress.IPv4Interface | ipaddress.IPv6Interface, bytes | None]]:
    """ctypes implementation of getifaddrs on POSIX systems."""
    results: list[tuple[str, ipaddress.IPv4Interface | ipaddress.IPv6Interface, bytes | None]] = []
    try:
        # Define structures
        class sockaddr(ctypes.Structure):
            pass

        # Since struct layout of sockaddr depends on platform (sa_len exists on Darwin/macOS, not on Linux)
        is_darwin = sys.platform == "darwin"
        if is_darwin:
            sockaddr._fields_ = [
                ("sa_len", ctypes.c_ubyte),
                ("sa_family", ctypes.c_ubyte),
                ("sa_data", ctypes.c_char * 14)
            ]
        else:
            sockaddr._fields_ = [
                ("sa_family", ctypes.c_ushort),
                ("sa_data", ctypes.c_char * 14)
            ]

        class sockaddr_in(ctypes.Structure):
            if is_darwin:
                _fields_ = [
                    ("sin_len", ctypes.c_ubyte),
                    ("sin_family", ctypes.c_ubyte),
                    ("sin_port", ctypes.c_ushort),
                    ("sin_addr", ctypes.c_ubyte * 4),
                    ("sin_zero", ctypes.c_char * 8)
                ]
            else:
                _fields_ = [
                    ("sin_family", ctypes.c_ushort),
                    ("sin_port", ctypes.c_ushort),
                    ("sin_addr", ctypes.c_ubyte * 4),
                    ("sin_zero", ctypes.c_char * 8)
                ]

        class sockaddr_in6(ctypes.Structure):
            if is_darwin:
                _fields_ = [
                    ("sin6_len", ctypes.c_ubyte),
                    ("sin6_family", ctypes.c_ubyte),
                    ("sin6_port", ctypes.c_ushort),
                    ("sin6_flowinfo", ctypes.c_uint32),
                    ("sin6_addr", ctypes.c_ubyte * 16),
                    ("sin6_scope_id", ctypes.c_uint32)
                ]
            else:
                _fields_ = [
                    ("sin6_family", ctypes.c_ushort),
                    ("sin6_port", ctypes.c_ushort),
                    ("sin6_flowinfo", ctypes.c_uint32),
                    ("sin6_addr", ctypes.c_ubyte * 16),
                    ("sin6_scope_id", ctypes.c_uint32)
                ]

        # MAC Address struct representation
        # Linux AF_PACKET = 17
        class sockaddr_ll(ctypes.Structure):
            _fields_ = [
                ("sll_family", ctypes.c_ushort),
                ("sll_protocol", ctypes.c_ushort),
                ("sll_ifindex", ctypes.c_int),
                ("sll_hatype", ctypes.c_ushort),
                ("sll_pkttype", ctypes.c_ubyte),
                ("sll_halen", ctypes.c_ubyte),
                ("sll_addr", ctypes.c_ubyte * 8)
            ]

        # macOS AF_LINK = 18
        class sockaddr_dl(ctypes.Structure):
            _fields_ = [
                ("sdl_len", ctypes.c_ubyte),
                ("sdl_family", ctypes.c_ubyte),
                ("sdl_index", ctypes.c_ushort),
                ("sdl_type", ctypes.c_ubyte),
                ("sdl_nlen", ctypes.c_ubyte),
                ("sdl_alen", ctypes.c_ubyte),
                ("sdl_slen", ctypes.c_ubyte),
                ("sdl_data", ctypes.c_char * 12)
            ]

        class ifaddrs(ctypes.Structure):
            pass

        ifaddrs._fields_ = [
            ("ifa_next", ctypes.POINTER(ifaddrs)),
            ("ifa_name", ctypes.c_char_p),
            ("ifa_flags", ctypes.c_uint),
            ("ifa_addr", ctypes.POINTER(sockaddr)),
            ("ifa_netmask", ctypes.POINTER(sockaddr)),
            ("ifa_ifu", ctypes.c_void_p),
            ("ifa_data", ctypes.c_void_p)
        ]

        libc = ctypes.CDLL(None) if sys.platform != "darwin" else ctypes.CDLL("libSystem.dylib")
        
        # getifaddrs function signature
        libc.getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(ifaddrs))]
        libc.getifaddrs.restype = ctypes.c_int
        libc.freeifaddrs.argtypes = [ctypes.POINTER(ifaddrs)]
        libc.freeifaddrs.restype = None

        ifaddr_ptr = ctypes.POINTER(ifaddrs)()
        if libc.getifaddrs(ctypes.byref(ifaddr_ptr)) != 0:
            return results

        # Pass 1: Build interface names map to MAC address
        macs: dict[str, bytes] = {}
        curr = ifaddr_ptr
        while curr:
            iface = curr.contents
            name = iface.ifa_name.decode("utf-8", errors="ignore")
            if iface.ifa_addr:
                family = iface.ifa_addr.contents.sa_family
                # AF_PACKET is 17 on Linux
                if family == 17 and not is_darwin:
                    s_ll = ctypes.cast(iface.ifa_addr, ctypes.POINTER(sockaddr_ll)).contents
                    if s_ll.sll_halen > 0:
                        macs[name] = bytes(s_ll.sll_addr[:s_ll.sll_halen])
                # AF_LINK is 18 on macOS/BSD
                elif family == 18 and is_darwin:
                    s_dl = ctypes.cast(iface.ifa_addr, ctypes.POINTER(sockaddr_dl)).contents
                    if s_dl.sdl_alen > 0:
                        # MAC address starts at sdl_data[sdl_nlen]
                        mac_bytes = s_dl.sdl_data[s_dl.sdl_nlen:s_dl.sdl_nlen + s_dl.sdl_alen]
                        macs[name] = mac_bytes
            curr = iface.ifa_next

        # Pass 2: Extract IPs and netmasks
        curr = ifaddr_ptr
        while curr:
            iface = curr.contents
            name = iface.ifa_name.decode("utf-8", errors="ignore")
            if iface.ifa_addr and iface.ifa_netmask:
                family = iface.ifa_addr.contents.sa_family
                # IPv4
                if family == socket.AF_INET:
                    addr_in = ctypes.cast(iface.ifa_addr, ctypes.POINTER(sockaddr_in)).contents
                    mask_in = ctypes.cast(iface.ifa_netmask, ctypes.POINTER(sockaddr_in)).contents
                    ip_bytes = bytes(addr_in.sin_addr)
                    mask_bytes = bytes(mask_in.sin_addr)
                    ip_str = socket.inet_ntoa(ip_bytes)
                    mask_val = int.from_bytes(mask_bytes, "big")
                    # Count bits set in mask to get prefix length
                    prefix = bin(mask_val).count("1")
                    try:
                        iface_obj: ipaddress.IPv4Interface | ipaddress.IPv6Interface = ipaddress.IPv4Interface(f"{ip_str}/{prefix}")
                        results.append((name, iface_obj, macs.get(name)))
                    except Exception:
                        pass
                # IPv6
                elif family == socket.AF_INET6:
                    addr_in6 = ctypes.cast(iface.ifa_addr, ctypes.POINTER(sockaddr_in6)).contents
                    mask_in6 = ctypes.cast(iface.ifa_netmask, ctypes.POINTER(sockaddr_in6)).contents
                    ip_bytes = bytes(addr_in6.sin6_addr)
                    mask_bytes = bytes(mask_in6.sin6_addr)
                    ip_str = socket.inet_ntop(socket.AF_INET6, ip_bytes)
                    mask_val = int.from_bytes(mask_bytes, "big")
                    prefix = bin(mask_val).count("1")
                    try:
                        iface_obj = ipaddress.IPv6Interface(f"{ip_str}/{prefix}")
                        results.append((name, iface_obj, macs.get(name)))
                    except Exception:
                        pass

            curr = iface.ifa_next

        libc.freeifaddrs(ifaddr_ptr)
    except Exception as e:
        LOGGER.debug(f"getifaddrs ctypes failed: {e}")
    return results

def _get_interfaces_ctypes_nt() -> list[tuple[str, ipaddress.IPv4Interface | ipaddress.IPv6Interface, bytes | None]]:
    """ctypes implementation of GetAdaptersInfo on Windows."""
    results: list[tuple[str, ipaddress.IPv4Interface | ipaddress.IPv6Interface, bytes | None]] = []
    try:
        # Load iphlpapi.dll
        iphlpapi = ctypes.WinDLL("iphlpapi.dll")
        
        # Max limits
        MAX_ADAPTER_NAME_LENGTH = 256
        MAX_ADAPTER_DESCRIPTION_LENGTH = 128
        MAX_ADAPTER_ADDRESS_LENGTH = 8

        class IP_ADDR_STRING(ctypes.Structure):
            pass

        IP_ADDR_STRING._fields_ = [
            ("Next", ctypes.POINTER(IP_ADDR_STRING)),
            ("IpAddress", ctypes.c_char * 16),
            ("IpMask", ctypes.c_char * 16),
            ("Context", ctypes.c_ulong)
        ]

        class IP_ADAPTER_INFO(ctypes.Structure):
            pass

        IP_ADAPTER_INFO._fields_ = [
            ("Next", ctypes.POINTER(IP_ADAPTER_INFO)),
            ("ComboIndex", ctypes.c_ulong),
            ("AdapterName", ctypes.c_char * (MAX_ADAPTER_NAME_LENGTH + 4)),
            ("Description", ctypes.c_char * (MAX_ADAPTER_DESCRIPTION_LENGTH + 4)),
            ("AddressLength", ctypes.c_uint),
            ("Address", ctypes.c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
            ("Index", ctypes.c_ulong),
            ("Type", ctypes.c_uint),
            ("DhcpEnabled", ctypes.c_uint),
            ("HaveCurrentIpAddress", ctypes.c_uint),
            ("CurrentIpAddress", ctypes.POINTER(IP_ADDR_STRING)),
            ("IpAddressList", IP_ADDR_STRING),
            ("GatewayList", IP_ADDR_STRING),
            ("DhcpServer", IP_ADDR_STRING),
            ("HaveWins", ctypes.c_uint),
            ("PrimaryWinsServer", IP_ADDR_STRING),
            ("SecondaryWinsServer", IP_ADDR_STRING),
            ("LeaseObtained", ctypes.c_ulonglong),
            ("LeaseExpires", ctypes.c_ulonglong)
        ]

        # Call GetAdaptersInfo
        out_len = ctypes.c_ulong(0)
        # Call first to get the buffer size
        iphlpapi.GetAdaptersInfo(None, ctypes.byref(out_len))
        
        if out_len.value == 0:
            return results

        buf = ctypes.create_string_buffer(out_len.value)
        if iphlpapi.GetAdaptersInfo(ctypes.byref(buf), ctypes.byref(out_len)) == 0:
            adapter_info = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_INFO))
            curr = adapter_info
            while curr:
                info = curr.contents
                name = info.AdapterName.decode("utf-8", errors="ignore")
                
                # Retrieve MAC
                mac = None
                if info.AddressLength > 0:
                    mac = bytes(info.Address[:info.AddressLength])

                # Enumerate IP Addresses
                ip_node = ctypes.pointer(info.IpAddressList)
                while ip_node:
                    node = ip_node.contents
                    ip_str = node.IpAddress.decode("utf-8", errors="ignore").strip("\x00")
                    mask_str = node.IpMask.decode("utf-8", errors="ignore").strip("\x00")
                    if ip_str and ip_str != "0.0.0.0":
                        prefix = _mask_to_prefix(mask_str)
                        try:
                            iface: ipaddress.IPv4Interface | ipaddress.IPv6Interface = ipaddress.IPv4Interface(f"{ip_str}/{prefix}")
                            results.append((name, iface, mac))
                        except Exception:
                            pass
                    ip_node = node.Next
                
                curr = info.Next
    except Exception as e:
        LOGGER.debug(f"GetAdaptersInfo ctypes failed: {e}")
    return results

def get_interfaces() -> list[tuple[str, ipaddress.IPv4Interface | ipaddress.IPv6Interface, bytes | None]]:
    """
    Enumerate network interfaces with IP addresses and MAC addresses.
    Returns:
        List of tuples: (interface_name, IP_interface, MAC_address_bytes_or_None)
    """
    results: list[tuple[str, ipaddress.IPv4Interface | ipaddress.IPv6Interface, bytes | None]] = []
    
    # Try ctypes first
    if sys.platform == "win32":
        results = _get_interfaces_ctypes_nt()
        if not results:
            results = _parse_ipconfig()
    else:
        results = _get_interfaces_ctypes_posix()
        if not results:
            results = _parse_ip_addr()

    # Fallback/last-resort: use socket.getaddrinfo and socket.if_nameindex if both ctypes and CLI parsing yielded nothing
    if not results:
        names: list[str] = []
        try:
            # Unix-like interface list
            names = [name for _, name in socket.if_nameindex()]
        except Exception:
            # Fallback names
            names = ["lo", "eth0", "wlan0", "en0", "en1", "Ethernet"]

        for name in names:
            try:
                # Retrieve IPs
                addrinfo = socket.getaddrinfo(name, None)
                for item in addrinfo:
                    fam = item[0]
                    ip = item[4][0]
                    try:
                        iface_obj: ipaddress.IPv4Interface | ipaddress.IPv6Interface
                        if fam == socket.AF_INET:
                            iface_obj = ipaddress.IPv4Interface(f"{ip}/24")
                            results.append((name, iface_obj, None))
                        elif fam == socket.AF_INET6:
                            iface_obj = ipaddress.IPv6Interface(f"{ip}/64")
                            results.append((name, iface_obj, None))
                    except Exception:
                        pass
            except Exception:
                pass

    # Unique filter (avoid duplicate IP entries)
    seen = set()
    unique_results: list[tuple[str, ipaddress.IPv4Interface | ipaddress.IPv6Interface, bytes | None]] = []
    for res_item in results:
        key = (res_item[0], str(res_item[1].ip))
        if key not in seen:
            seen.add(key)
            unique_results.append(res_item)

    return unique_results
