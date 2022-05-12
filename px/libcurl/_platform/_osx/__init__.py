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

# try:
#     from ...__config__ import config
#     DLL_PATH = config.get("LIBCURL", None)
#     del config
#     if DLL_PATH is None or DLL_PATH in ("", "None"):
#         raise ImportError()
# except ImportError:
DLL_PATH = "libcurl.4.dylib"

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

fd_mask = ct.c_long

class fd_set(ct.Structure):
    _fields_ = [
    ("fds_bits", fd_mask * 32),
]
