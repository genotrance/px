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

class FILE(ct.Structure): pass

if 0: # deprecated
    mprintf    = (ct.c_int,
                  ct.c_char_p,
                  )(#...)(
                  ("curl_mprintf", dll), (
                  (1, "format"),
                  ))#(1, "???"),))

    mfprintf   = (ct.c_int,
                  ct.POINTER(FILE),
                  ct.c_char_p,
                  )(#...)(
                  ("curl_mfprintf", dll), (
                  (1, "fd"),
                  (1, "format"),
                  ))#(1, "???"),))

    msprintf   = (ct.c_int,
                  ct.c_char_p,
                  ct.c_char_p,
                  )(#...)(
                  ("curl_msprintf", dll), (
                  (1, "buffer"),
                  (1, "format"),
                  ))#(1, "???"),))

    msnprintf  = (ct.c_int,
                  ct.c_char_p,
                  ct.c_size_t,
                  ct.c_char_p,
                  )(#...)(
                  ("curl_msnprintf", dll), (
                  (1, "buffer"),
                  (1, "maxlength"),
                  (1, "format"),
                  ))#(1, "???"),))

    mvprintf   = (ct.c_int,
                  ct.c_char_p,
                  va_list)(
                  ("curl_mvprintf", dll), (
                  (1, "format"),
                  (1, "args"),))

    mvfprintf  = (ct.c_int,
                  ct.POINTER(FILE),
                  ct.c_char_p,
                  va_list)(
                  ("curl_mvfprintf", dll), (
                  (1, "fd"),
                  (1, "format"),
                  (1, "args"),))

    mvsprintf  = (ct.c_int,
                  ct.c_char_p,
                  ct.c_char_p,
                  va_list)(
                  ("curl_mvsprintf", dll), (
                  (1, "buffer"),
                  (1, "format"),
                  (1, "args"),))

    mvsnprintf = (ct.c_int,
                  ct.c_char_p,
                  ct.c_size_t,
                  ct.c_char_p,
                  va_list)(
                  ("curl_mvsnprintf", dll), (
                  (1, "buffer"),
                  (1, "maxlength"),
                  (1, "format"),
                  (1, "args"),))

    maprintf   = (ct.c_char_p,
                  ct.c_char_p,
                  )(#...)(
                  ("curl_maprintf", dll), (
                  (1, "format"),
                  ))#(1, "???"),))

    mvaprintf  = (ct.c_char_p,
                  ct.c_char_p,
                  va_list)(
                  ("curl_mvaprintf", dll), (
                  (1, "format"),
                  (1, "args"),))

# eof
