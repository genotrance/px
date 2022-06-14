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
# Copyright (C) 2018 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
from ._curl     import CURLoption

easytype = ct.c_int
(
  CURLOT_LONG,     # long (a range of values)
  CURLOT_VALUES,   #      (a defined set or bitmask)
  CURLOT_OFF_T,    # curl_off_t (a range of values)
  CURLOT_OBJECT,   # pointer (void *)
  CURLOT_STRING,   #         (char * to zero terminated buffer)
  CURLOT_SLIST,    #         (struct curl_slist *)
  CURLOT_CBPTR,    #         (void * passed as-is to a callback)
  CURLOT_BLOB,     # blob (struct curl_blob *)
  CURLOT_FUNCTION  # function pointer
) = range(9)

# Flag bits

# "alias" means it is provided for old programs to remain functional,
#  we prefer another name
CURLOT_FLAG_ALIAS = (1 << 0)

# The CURLOPTTYPE_* id ranges can still be used to figure out what type/size
# to use for curl_easy_setopt() for the given id
class easyoption(ct.Structure):
    _fields_ = [
    ("name",  ct.c_char_p),
    ("id",    CURLoption),
    ("type",  easytype),
    ("flags", ct.c_uint),
]

# libcurl < 7.73
try:
    easy_option_by_name = CFUNC(ct.POINTER(easyoption),
                                ct.c_char_p)(
                                ("curl_easy_option_by_name", dll), (
                                (1, "name"),))

    easy_option_by_id = CFUNC(ct.POINTER(easyoption),
                              CURLoption)(
                              ("curl_easy_option_by_id", dll), (
                              (1, "id"),))

    easy_option_next = CFUNC(ct.POINTER(easyoption),
                            ct.POINTER(easyoption))(
                            ("curl_easy_option_next", dll), (
                            (1, "prev"),))
except AttributeError:
    pass

# eof
