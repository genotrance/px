# Copyright (c) 2021-2022 Adam Karpierz
# Licensed under the MIT License
# https://opensource.org/licenses/MIT

import sys
import os
import ctypes as ct

this_dir = os.path.dirname(os.path.abspath(__file__))
libcurl_dir = os.path.dirname(os.path.dirname(this_dir))
is_32bit = (sys.maxsize <= 2**32)
# arch     = "x86" if is_32bit else "x64"
# arch_dir = os.path.join(this_dir, arch)

# try:
#     from ...__config__ import config
#     DLL_PATH = config.get("LIBCURL", None)
#     del config
#     if DLL_PATH is None or DLL_PATH in ("", "None"):
#         raise ImportError()
# except ImportError:
DLL_PATH = os.path.join(libcurl_dir,
                        "libcurl.dll" if is_32bit else "libcurl-x64.dll")
if not os.path.exists(DLL_PATH):
    # Search PATH
    import ctypes.util
    file = os.path.basename(DLL_PATH)
    DLL_PATH = ctypes.util.find_library(os.path.splitext(file)[0])

from ctypes  import WinDLL as DLL
from _ctypes import FreeLibrary as dlclose
from ctypes  import WINFUNCTYPE as CFUNC

# Winsock doesn't have this POSIX type; it's used for the
# tv_usec value of struct timeval.
suseconds_t = ct.c_long

time_t = ct.c_uint64

# Taken from the file <winsock.h>
#
# struct timeval {
#     long tv_sec;   /* seconds */
#     long tv_usec;  /* and microseconds */
# };

class timeval(ct.Structure):
    _fields_ = [
    ("tv_sec",  ct.c_long),    # seconds
    ("tv_usec", suseconds_t),  # microseconds
]

# Taken from the file libpcap's "socket.h"

# Some minor differences between sockets on various platforms.
# We include whatever sockets are needed for Internet-protocol
# socket access.

# In Winsock, a socket handle is of type SOCKET.
SOCKET = ct.c_uint

# In Winsock, the error return if socket() fails is INVALID_SOCKET.
INVALID_SOCKET = SOCKET(-1).value

# Winsock doesn't have this UN*X type; it's used in the UN*X
# sockets API.
socklen_t = ct.c_int

class sockaddr(ct.Structure):
    _fields_ = [
    ("sa_family", ct.c_short),
    ("__pad1",    ct.c_ushort),
    ("ipv4_addr", ct.c_byte * 4),
    ("ipv6_addr", ct.c_byte * 16),
    ("__pad2",    ct.c_ulong),
]

FD_SETSIZE = 512

class fd_set(ct.Structure):
    _fields_ = [
    ("fd_count", ct.c_uint),
    ("fd_array", SOCKET * FD_SETSIZE),
]
