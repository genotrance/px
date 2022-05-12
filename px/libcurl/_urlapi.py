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
# Copyright (C) 2018 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl.h"

# the error codes for the URL API
CURLUcode = ct.c_int
(
    CURLUE_OK,
    CURLUE_BAD_HANDLE,          # 1
    CURLUE_BAD_PARTPOINTER,     # 2
    CURLUE_MALFORMED_INPUT,     # 3
    CURLUE_BAD_PORT_NUMBER,     # 4
    CURLUE_UNSUPPORTED_SCHEME,  # 5
    CURLUE_URLDECODE,           # 6
    CURLUE_OUT_OF_MEMORY,       # 7
    CURLUE_USER_NOT_ALLOWED,    # 8
    CURLUE_UNKNOWN_PART,        # 9
    CURLUE_NO_SCHEME,           # 10
    CURLUE_NO_USER,             # 11
    CURLUE_NO_PASSWORD,         # 12
    CURLUE_NO_OPTIONS,          # 13
    CURLUE_NO_HOST,             # 14
    CURLUE_NO_PORT,             # 15
    CURLUE_NO_QUERY,            # 16
    CURLUE_NO_FRAGMENT,         # 17
    CURLUE_NO_ZONEID,           # 18
    CURLUE_BAD_FILE_URL,        # 19
    CURLUE_BAD_FRAGMENT,        # 20
    CURLUE_BAD_HOSTNAME,        # 21
    CURLUE_BAD_IPV6,            # 22
    CURLUE_BAD_LOGIN,           # 23
    CURLUE_BAD_PASSWORD,        # 24
    CURLUE_BAD_PATH,            # 25
    CURLUE_BAD_QUERY,           # 26
    CURLUE_BAD_SCHEME,          # 27
    CURLUE_BAD_SLASHES,         # 28
    CURLUE_BAD_USER,            # 29
    CURLUE_LAST
) = ( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
     10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
     20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
     30)

CURLUPart = ct.c_int
(
    CURLUPART_URL,
    CURLUPART_SCHEME,
    CURLUPART_USER,
    CURLUPART_PASSWORD,
    CURLUPART_OPTIONS,
    CURLUPART_HOST,
    CURLUPART_PORT,
    CURLUPART_PATH,
    CURLUPART_QUERY,
    CURLUPART_FRAGMENT,
    CURLUPART_ZONEID  # added in 7.65.0
) = range(11)

CURLU_DEFAULT_PORT       = (1 << 0)  # return default port number
CURLU_NO_DEFAULT_PORT    = (1 << 1)  # act as if no port number was set,
                                     # if the port number matches the
                                     # default for the scheme
CURLU_DEFAULT_SCHEME     = (1 << 2)  # return default scheme if
                                     # missing
CURLU_NON_SUPPORT_SCHEME = (1 << 3)  # allow non-supported scheme
CURLU_PATH_AS_IS         = (1 << 4)  # leave dot sequences
CURLU_DISALLOW_USER      = (1 << 5)  # no user+password allowed
CURLU_URLDECODE          = (1 << 6)  # URL decode on get
CURLU_URLENCODE          = (1 << 7)  # URL encode on set
CURLU_APPENDQUERY        = (1 << 8)  # append a form style part
CURLU_GUESS_SCHEME       = (1 << 9)  # legacy curl-style guessing
CURLU_NO_AUTHORITY       = (1 << 10) # Allow empty authority when the
                                     # scheme is unknown.
CURLU_ALLOW_SPACE        = (1 << 11) # Allow spaces in the URL

# typedef struct Curl_URL CURLU;
class Curl_URL(ct.Structure): pass
CURLU = Curl_URL

# curl_url() creates a new CURLU handle and returns a pointer to it.
# Must be freed with curl_url_cleanup().

url = CFUNC(ct.POINTER(CURLU))(
            ("curl_url", dll), (
            ))

# curl_url_cleanup() frees the CURLU handle and related resources used for
# the URL parsing. It will not free strings previously returned with the URL
# API.

url_cleanup = CFUNC(None,
                    ct.POINTER(CURLU))(
                    ("curl_url_cleanup", dll), (
                    (1, "handle"),))

# curl_url_dup() duplicates a CURLU handle and returns a new copy. The new
# handle must also be freed with curl_url_cleanup().

url_dup = CFUNC(ct.POINTER(CURLU),
                ct.POINTER(CURLU))(
                ("curl_url_dup", dll), (
                (1, "in"),))

# curl_url_get() extracts a specific part of the URL from a CURLU
# handle. Returns error code. The returned pointer MUST be freed with
# curl_free() afterwards.

url_get = CFUNC(CURLUcode,
                ct.POINTER(CURLU),
                CURLUPart,
                ct.POINTER(ct.c_char_p),
                ct.c_uint)(
                ("curl_url_get", dll), (
                (1, "handle"),
                (1, "what"),
                (1, "part"),
                (1, "flags"),))

# curl_url_set() sets a specific part of the URL in a CURLU handle. Returns
# error code. The passed in string will be copied. Passing a NULL instead of
# a part string, clears that part.

url_set = CFUNC(CURLUcode,
                ct.POINTER(CURLU),
                CURLUPart,
                ct.c_char_p,
                ct.c_uint)(
                ("curl_url_set", dll), (
                (1, "handle"),
                (1, "what"),
                (1, "part"),
                (1, "flags"),))

# curl_url_strerror() turns a CURLUcode value into the equivalent human
# readable error string.  This is useful for printing meaningful error
# messages.

# url_strerror = CFUNC(ct.c_char_p,
#                 ct.POINTER(CURLUcode))(
#                 ("curl_url_strerror", dll), (
#                 (1, "handle"),))

# eof
