'''

This file is part of Intrusion Dectection System Project.

Intrusion Dectection System Project is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intrusion Dectection System Project is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intrusion Dectection System Project.  If not, see <http://www.gnu.org/licenses/>.
'''

# Based on https://gist.github.com/provegard/1536682, which was
# Based on getifaddrs.py from pydlnadms [http://code.google.com/p/pydlnadms/].
# Only tested on Linux!

from socket import AF_INET, AF_INET6, inet_ntop
from ctypes import (
    Structure, Union, POINTER,
    pointer, get_errno, cast,
    c_ushort, c_byte, c_void_p, c_char_p, c_uint, c_int, c_uint16, c_uint32
)
import ctypes.util
import ctypes

class struct_sockaddr(Structure):
    _fields_ = [
        ('sa_family', c_ushort),
        ('sa_data', c_byte * 14),]

class struct_sockaddr_in(Structure):
    _fields_ = [
        ('sin_family', c_ushort),
        ('sin_port', c_uint16),
        ('sin_addr', c_byte * 4)]

class struct_sockaddr_in6(Structure):
    _fields_ = [
        ('sin6_family', c_ushort),
        ('sin6_port', c_uint16),
        ('sin6_flowinfo', c_uint32),
        ('sin6_addr', c_byte * 16),
        ('sin6_scope_id', c_uint32)]

class union_ifa_ifu(Union):
    _fields_ = [
        ('ifu_broadaddr', POINTER(struct_sockaddr)),
        ('ifu_dstaddr', POINTER(struct_sockaddr)),]

class struct_ifaddrs(Structure):
    pass
struct_ifaddrs._fields_ = [
    ('ifa_next', POINTER(struct_ifaddrs)),
    ('ifa_name', c_char_p),
    ('ifa_flags', c_uint),
    ('ifa_addr', POINTER(struct_sockaddr)),
    ('ifa_netmask', POINTER(struct_sockaddr)),
    ('ifa_ifu', union_ifa_ifu),
    ('ifa_data', c_void_p),]

libc = ctypes.CDLL(ctypes.util.find_library('c'))

def ifap_iter(ifap):
    ifa = ifap.contents
    while True:
        yield ifa
        if not ifa.ifa_next:
            break
        ifa = ifa.ifa_next.contents

def getfamaddr(sa):
    family = sa.sa_family
    addr = None
    if family == AF_INET:
        sa = cast(pointer(sa), POINTER(struct_sockaddr_in)).contents
        addr = inet_ntop(family, sa.sin_addr)
    elif family == AF_INET6:
        sa = cast(pointer(sa), POINTER(struct_sockaddr_in6)).contents
        addr = inet_ntop(family, sa.sin6_addr)
    return family, addr


def getBrcastAddr(ifa):
    if not ifa.ifa_ifu.ifu_broadaddr:
        return ""
    sa = ifa.ifa_ifu.ifu_broadaddr.contents
    family = sa.sa_family
    if family == AF_INET:
        sa = cast(pointer(sa), POINTER(struct_sockaddr_in)).contents
        addr = inet_ntop(family, sa.sin_addr)
        return addr
    return ""

    
def getNetmask(ifa):
    if not ifa.ifa_netmask:
        return ""
    sa = ifa.ifa_netmask.contents
    family = sa.sa_family
    if family == AF_INET:
        sa = cast(pointer(sa), POINTER(struct_sockaddr_in)).contents
        addr = inet_ntop(family, sa.sin_addr)
        return addr
    return ""

class NetworkInterface(object):
    def __init__(self, name):
        self.name = name
        self.index = libc.if_nametoindex(name)
        self.addresses = {}
        self.brdcastAddress = ""
        self.netmask = ""

    def __str__(self):
        return "%s [index=%d, IPv4=%s, IPv6=%s]" % (
            self.name, self.index,
            self.addresses.get(AF_INET),
            self.addresses.get(AF_INET6))

def get_network_interfaces():
    ifap = POINTER(struct_ifaddrs)()
    result = libc.getifaddrs(pointer(ifap))
    if result != 0:
        raise OSError(get_errno())
    del result
    try:
        retval = {}
        for ifa in ifap_iter(ifap):
            name = ifa.ifa_name.decode("UTF-8")
            i = retval.get(name)
            if not i:
                i = retval[name] = NetworkInterface(name)
            family, addr = getfamaddr(ifa.ifa_addr.contents)
            brdcastAddr = getBrcastAddr(ifa)
            netmask = getNetmask(ifa)
            if addr:
                if family not in i.addresses:
                    i.addresses[family] = list()
                i.addresses[family].append(addr)
            if brdcastAddr != "":
                i.brdcastAddress = brdcastAddr
            if netmask != "":
                i.netmask = netmask
        return retval.values()
    finally:
        libc.freeifaddrs(ifap)
