import ctypes
import struct
import netaddr
import ctypes.wintypes
from ctypes import POINTER
from ctypes.wintypes import DWORD, WCHAR, BYTE, BOOL, INT, ULONG, USHORT, LPSTR, LPWSTR
from socket import AF_INET

class SOCKADDR(ctypes.Structure):
    _fields_ = [
    ("sa_family",              USHORT),
    ("sa_data",                BYTE * 14),
    ]

class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [
    ("Sockaddr",               POINTER(SOCKADDR)),
    ("SockaddrLength",         INT),
    ]

class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass
IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length",                 ULONG),
    ("Flags",                  DWORD),
    ("Next",                   POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address",                SOCKET_ADDRESS),
    ("PrefixOrigin",           INT),
    ("SuffixOrigin",           INT),
    ("DadState",               INT),
    ("ValidLifetime",          ULONG),
    ("PreferredLifetime",      ULONG),
    ("LeaseLifetime",          ULONG),
    ("OnLinkPrefixLength",     ctypes.c_ubyte)
    ]

MAX_ADAPTER_ADDRESS_LENGTH = 8
MAX_DHCPV6_DUID_LENGTH = 130
 		
class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass
IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length",                 ULONG),
    ("IfIndex",                DWORD),
    ("Next",                   POINTER(IP_ADAPTER_ADDRESSES)),
    ("AdapterName",            LPSTR),
    ("FirstUnicastAddress",    POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress",    ctypes.c_void_p), # Not used
    ("FirstMulticastAddress",  ctypes.c_void_p), # Not used
    ("FirstDnsServerAddress",  ctypes.c_void_p), # Not used
    ("DnsSuffix",              LPWSTR),
    ("Description",            LPWSTR),
    ("FriendlyName",           LPWSTR),
    ("PhysicalAddress",        BYTE * MAX_ADAPTER_ADDRESS_LENGTH),
    ("PhysicalAddressLength",  DWORD),
    ("Flags",                  DWORD),
    ("Mtu",                    DWORD),
    ("IfType",                 DWORD),
    ("OperStatus",             DWORD),
    ("Ipv6IfIndex",            DWORD),
    ("ZoneIndices",            DWORD * 16),
    ("FirstPrefix",            ctypes.c_void_p), # Not used
    ("TransmitLinkSpeed",      ctypes.c_uint64),
    ("ReceiveLinkSpeed",       ctypes.c_uint64),
    ("FirstWinsServerAddress", ctypes.c_void_p), # Not used
    ("FirstGatewayAddress",    ctypes.c_void_p), # Not used
    ("Ipv4Metric",             ULONG),
    ("Ipv6Metric",             ULONG),
    ("Luid",                   ctypes.c_uint64),
    ("Dhcpv4Server",           SOCKET_ADDRESS),
    ("CompartmentId",          DWORD),
    ("NetworkGuid",            BYTE * 16),
    ("ConnectionType",         DWORD),
    ("TunnelType",             DWORD),
    ("Dhcpv6Server",           SOCKET_ADDRESS),
    ("Dhcpv6ClientDuid",       BYTE * MAX_DHCPV6_DUID_LENGTH),
    ("Dhcpv6ClientDuidLength", ULONG),
    ("Dhcpv6Iaid",             ULONG),
    ("FirstDnsSuffix",         ctypes.c_void_p), # Not used
    ]


def get_adapters_addresses():
    """
    Returns an iteratable list of adapters
    """
    size = ctypes.c_ulong(15000)
    AdapterAddresses = ctypes.create_string_buffer(size.value)
    pAdapterAddresses = ctypes.cast(AdapterAddresses, POINTER(IP_ADAPTER_ADDRESSES))

    if not ctypes.windll.iphlpapi.GetAdaptersAddresses(AF_INET, 0, None, pAdapterAddresses, ctypes.byref(size)) == 0x0: # NO_ERROR
        self.logger.error('Failed calling GetAdaptersAddresses')
        return		

    while pAdapterAddresses:
        yield pAdapterAddresses.contents
        pAdapterAddresses = pAdapterAddresses.contents.Next

def get_ip_addresses():
    for i in get_adapters_addresses():
        if i.FirstUnicastAddress:
            fu = i.FirstUnicastAddress.contents
            ad = fu.Address.Sockaddr.contents
            ip_int = struct.unpack('>2xI8x', ad.sa_data)[0]
            ip = netaddr.IPAddress(ip_int)
            yield ip
 
