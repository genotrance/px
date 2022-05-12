# Copyright (c) 2021-2022 Adam Karpierz
# Licensed under the MIT License
# https://opensource.org/licenses/MIT

import sys
import os
import ctypes as ct

this_dir = os.path.dirname(os.path.abspath(__file__))
is_32bit = (sys.maxsize <= 2**32)
arch     = "x86" if is_32bit else "x64"
arch_dir = os.path.join(this_dir, arch)

if is_32bit:
    raise NotImplementedError("This 32 bit OS is not supported already!")

# try:
#     from ...__config__ import config
#     DLL_PATH = config.get("LIBCURL", None)
#     del config
#     if DLL_PATH is None or DLL_PATH in ("", "None"):
#         raise ImportError()
# except ImportError:
DLL_PATH = "libcurl.so.4"

from ctypes  import CDLL as DLL
from _ctypes import dlclose
from ctypes  import CFUNCTYPE as CFUNC

# X32 kernel interface is 64-bit.
if False:#if defined __x86_64__ && defined __ILP32__
    # quad_t is also 64 bits.
    time_t = suseconds_t = ct.c_longlong
else:
    time_t = suseconds_t = ct.c_long
#endif

# Taken from the file <sys/time.h>
#include <time.h>
#
# struct timeval {
#     time_t      tv_sec;   /* Seconds. */
#     suseconds_t tv_usec;  /* Microseconds. */
# };

class timeval(ct.Structure):
    _fields_ = [
    ("tv_sec",  time_t),       # seconds
    ("tv_usec", suseconds_t),  # microseconds
]

# Taken from the file libpcap's "socket.h"

# Some minor differences between sockets on various platforms.
# We include whatever sockets are needed for Internet-protocol
# socket access.

# In UN*X, a socket handle is a file descriptor, and therefore
# a signed integer.
SOCKET = ct.c_int

# In UN*X, the error return if socket() fails is -1.
INVALID_SOCKET = SOCKET(-1).value

class sockaddr(ct.Structure):
    _fields_ = [
    ("sa_family", ct.c_short),
    ("__pad1",    ct.c_ushort),
    ("ipv4_addr", ct.c_byte * 4),
    ("ipv6_addr", ct.c_byte * 16),
    ("__pad2",    ct.c_ulong),
]

fd_mask = ct.c_long

class fd_set(ct.Structure):
    _fields_ = [
    ("fds_bits", fd_mask * 32),
]
