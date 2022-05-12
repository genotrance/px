# Copyright (c) 2021-2022 Adam Karpierz
# Licensed under the MIT License
# https://opensource.org/licenses/MIT

import sys
import os
import platform
import ctypes as ct

is_windows = (bool(platform.win32_ver()[0]) or
              (sys.platform in ("win32", "cygwin")) or
              (sys.platform == "cli" and os.name in ("nt", "ce")) or
              (os.name == "java" and
               "windows" in platform.java_ver()[3][0].lower()))
is_linux   = sys.platform.startswith("linux")
is_osx     = (sys.platform == "darwin")
is_android = False
is_posix   = (os.name == "posix")
is_32bit   = (sys.maxsize <= 2**32)

def defined(varname, __getframe=sys._getframe):
    frame = __getframe(1)
    return varname in frame.f_locals or varname in frame.f_globals

def from_oid(oid, __cast=ct.cast, __py_object=ct.py_object):
    return __cast(oid, __py_object).value if oid else None

del sys, os, platform, ct

if is_windows:
    from ._windows import DLL_PATH, DLL, dlclose, CFUNC
    from ._windows import time_t
    from ._windows import SOCKET, INVALID_SOCKET, sockaddr, fd_set
elif is_linux:
    from ._linux   import DLL_PATH, DLL, dlclose, CFUNC
    from ._linux   import time_t
    from ._linux   import SOCKET, INVALID_SOCKET, sockaddr, fd_set
elif is_osx:
    from ._osx     import DLL_PATH, DLL, dlclose, CFUNC
    from ._osx     import time_t
    from ._osx     import SOCKET, INVALID_SOCKET, sockaddr, fd_set
else:
    raise ImportError("unsupported platform")
