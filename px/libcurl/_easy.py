# Copyright (c) 2021-2022 Adam Karpierz
# Licensed under the MIT License
# https://opensource.org/licenses/MIT

#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
#***************************************************************************

import ctypes as ct

from ._platform import CFUNC
from ._dll      import dll
from ._curl     import CURL, CURLcode, CURLoption, CURLINFO

# Flag bits in the curl_blob struct:
CURL_BLOB_COPY   = 1  # tell libcurl to copy the data
CURL_BLOB_NOCOPY = 0  # tell libcurl to NOT copy the data

class blob(ct.Structure):
    _fields_ = [
    ("data",  ct.c_void_p),
    ("len",   ct.c_size_t),
    ("flags", ct.c_uint),  # bit 0 is defined, the rest are reserved and should be
                           # left zeroes
]

easy_init = CFUNC(ct.POINTER(CURL))(
                  ("curl_easy_init", dll), (
                  ))

easy_setopt = CFUNC(CURLcode,
                    ct.POINTER(CURL),
                    CURLoption,
                    ct.c_void_p)(
                    ("curl_easy_setopt", dll), (
                    (1, "curl"),
                    (1, "option"),
                    (1, "value"),))

easy_perform = CFUNC(CURLcode,
                     ct.POINTER(CURL))(
                     ("curl_easy_perform", dll), (
                     (1, "curl"),))

easy_cleanup = CFUNC(None,
                     ct.POINTER(CURL))(
                     ("curl_easy_cleanup", dll), (
                     (1, "curl"),))

# NAME curl_easy_getinfo()
#
# DESCRIPTION
#
# Request internal information from the curl session with this function.  The
# third argument MUST be a pointer to a long, a pointer to a char * or a
# pointer to a double (as the documentation describes elsewhere).  The data
# pointed to will be filled in accordingly and can be relied upon only if the
# function returns CURLE_OK.  This function is intended to get used *AFTER* a
# performed transfer, all results from this function are undefined until the
# transfer is completed.

easy_getinfo = CFUNC(CURLcode,
                     ct.POINTER(CURL),
                     CURLINFO,
                     ct.c_void_p)(
                     ("curl_easy_getinfo", dll), (
                     (1, "curl"),
                     (1, "info"),
                     (1, "value"),))

# NAME curl_easy_duphandle()
#
# DESCRIPTION
#
# Creates a new curl session handle with the same options set for the handle
# passed in. Duplicating a handle could only be a matter of cloning data and
# options, internal state info and things like persistent connections cannot
# be transferred. It is useful in multithreaded applications when you can run
# curl_easy_duphandle() for each new thread to avoid a series of identical
# curl_easy_setopt() invokes in every thread.

easy_duphandle = CFUNC(ct.POINTER(CURL),
                       ct.POINTER(CURL))(
                       ("curl_easy_duphandle", dll), (
                       (1, "curl"),))

# NAME curl_easy_reset()
#
# DESCRIPTION
#
# Re-initializes a CURL handle to the default values. This puts back the
# handle to the same state as it was in when it was just created.
#
# It does keep: live connections, the Session ID cache, the DNS cache and the
# cookies.

easy_reset = CFUNC(None,
                   ct.POINTER(CURL))(
                   ("curl_easy_reset", dll), (
                   (1, "curl"),))

# NAME curl_easy_recv()
#
# DESCRIPTION
#
# Receives data from the connected socket. Use after successful
# curl_easy_perform() with CURLOPT_CONNECT_ONLY option.

easy_recv = CFUNC(CURLcode,
                  ct.POINTER(CURL),
                  ct.c_void_p,
                  ct.c_size_t,
                  ct.POINTER(ct.c_size_t))(
                  ("curl_easy_recv", dll), (
                  (1, "curl"),
                  (1, "buffer"),
                  (1, "buflen"),
                  (1, "n"),))

# NAME curl_easy_send()
#
# DESCRIPTION
#
# Sends data over the connected socket. Use after successful
# curl_easy_perform() with CURLOPT_CONNECT_ONLY option.

easy_send = CFUNC(CURLcode,
                  ct.POINTER(CURL),
                  ct.c_void_p,
                  ct.c_size_t,
                  ct.POINTER(ct.c_size_t))(
                  ("curl_easy_send", dll), (
                  (1, "curl"),
                  (1, "buffer"),
                  (1, "buflen"),
                  (1, "n"),))

# libcurl < 7.62
try:
    # NAME curl_easy_upkeep()
    #
    # DESCRIPTION
    #
    # Performs connection upkeep for the given session handle.

    easy_upkeep = CFUNC(CURLcode,
                        ct.POINTER(CURL))(
                        ("curl_easy_upkeep", dll), (
                        (1, "curl"),))
except AttributeError:
    pass

# eof
