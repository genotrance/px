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

# Try to keep one section per platform, compiler and architecture, otherwise,
# if an existing section is reused for a different one and later on the
# original is adjusted, probably the piggybacking one can be adversely
# changed.
#
# In order to differentiate between platforms/compilers/architectures use
# only compiler built in predefined preprocessor symbols.
#
# curl_off_t
# ----------
#
# For any given platform/compiler curl_off_t must be typedef'ed to a 64-bit
# wide signed integral data type. The width of this data type must remain
# constant and independent of any possible large file support settings.
#
# As an exception to the above, curl_off_t shall be typedef'ed to a 32-bit
# wide signed integral data type if there is no 64-bit type.
#
# As a general rule, curl_off_t shall not be mapped to off_t. This rule shall
# only be violated if off_t is the only 64-bit data type available and the
# size of off_t is independent of large file support settings. Keep your
# build on the safe side avoiding an off_t gating.  If you have a 64-bit
# off_t then take for sure that another 64-bit data type exists, dig deeper
# and you will find it.

import ctypes as ct

#if defined("_MSC_VER"):
CURL_FORMAT_CURL_OFF_T     = "d"
CURL_FORMAT_CURL_OFF_TU    = "u"
CURL_TYPEOF_CURL_SOCKLEN_T = ct.c_int

"""
if defined("__DJGPP__") or defined("__GO32__"):
    if defined("__DJGPP__") and (__DJGPP__ > 1):
        CURL_TYPEOF_CURL_OFF_T  = ct.c_int64
        CURL_FORMAT_CURL_OFF_T  = "lld"
        CURL_FORMAT_CURL_OFF_TU = "llu"
        CURL_SUFFIX_CURL_OFF_T  = LL
        CURL_SUFFIX_CURL_OFF_TU = ULL
    else:
        CURL_TYPEOF_CURL_OFF_T  = long
        CURL_FORMAT_CURL_OFF_T  = "ld"
        CURL_FORMAT_CURL_OFF_TU = "lu"
        CURL_SUFFIX_CURL_OFF_T  = L
        CURL_SUFFIX_CURL_OFF_TU = UL
    CURL_TYPEOF_CURL_SOCKLEN_T  = ct.c_int

elif defined("__SALFORDC__"):
    CURL_TYPEOF_CURL_OFF_T     = long
    CURL_FORMAT_CURL_OFF_T     = "ld"
    CURL_FORMAT_CURL_OFF_TU    = "lu"
    CURL_SUFFIX_CURL_OFF_T     = L
    CURL_SUFFIX_CURL_OFF_TU    = UL
    CURL_TYPEOF_CURL_SOCKLEN_T = ct.c_int

elif defined("__BORLANDC__"):
    if __BORLANDC__ < 0x520:
        CURL_TYPEOF_CURL_OFF_T  = long
        CURL_FORMAT_CURL_OFF_T  = "ld"
        CURL_FORMAT_CURL_OFF_TU = "lu"
        CURL_SUFFIX_CURL_OFF_T  = L
        CURL_SUFFIX_CURL_OFF_TU = UL
    else:
        CURL_TYPEOF_CURL_OFF_T  = ct.c_int64
        CURL_FORMAT_CURL_OFF_T  = "I64d"
        CURL_FORMAT_CURL_OFF_TU = "I64u"
        CURL_SUFFIX_CURL_OFF_T  = i64
        CURL_SUFFIX_CURL_OFF_TU = ui64
    CURL_TYPEOF_CURL_SOCKLEN_T  = ct.c_int

elif defined("__TURBOC__"):
   CURL_TYPEOF_CURL_OFF_T     = long
   CURL_FORMAT_CURL_OFF_T     = "ld"
   CURL_FORMAT_CURL_OFF_TU    = "lu"
   CURL_SUFFIX_CURL_OFF_T     = L
   CURL_SUFFIX_CURL_OFF_TU    = UL
   CURL_TYPEOF_CURL_SOCKLEN_T = ct.c_int

elif defined("__WATCOMC__"):
    if defined("__386__"):
        CURL_TYPEOF_CURL_OFF_T  = ct.c_int64
        CURL_FORMAT_CURL_OFF_T  = "I64d"
        CURL_FORMAT_CURL_OFF_TU = "I64u"
        CURL_SUFFIX_CURL_OFF_T  = i64
        CURL_SUFFIX_CURL_OFF_TU = ui64
    else:
        CURL_TYPEOF_CURL_OFF_T  = long
        CURL_FORMAT_CURL_OFF_T  = "ld"
        CURL_FORMAT_CURL_OFF_TU = "lu"
        CURL_SUFFIX_CURL_OFF_T  = L
        CURL_SUFFIX_CURL_OFF_TU = UL
    CURL_TYPEOF_CURL_SOCKLEN_T  = ct.c_int

elif defined("__POCC__"):
    if __POCC__ < 280:
        CURL_TYPEOF_CURL_OFF_T  = long
        CURL_FORMAT_CURL_OFF_T  = "ld"
        CURL_FORMAT_CURL_OFF_TU = "lu"
        CURL_SUFFIX_CURL_OFF_T  = L
        CURL_SUFFIX_CURL_OFF_TU = UL
    elif defined("_MSC_VER"):
        CURL_TYPEOF_CURL_OFF_T  = ct.c_int64
        CURL_FORMAT_CURL_OFF_T  = "I64d"
        CURL_FORMAT_CURL_OFF_TU = "I64u"
        CURL_SUFFIX_CURL_OFF_T  = i64
        CURL_SUFFIX_CURL_OFF_TU = ui64
    else:
        CURL_TYPEOF_CURL_OFF_T  = ct.c_int64
        CURL_FORMAT_CURL_OFF_T  = "lld"
        CURL_FORMAT_CURL_OFF_TU = "llu"
        CURL_SUFFIX_CURL_OFF_T  = LL
        CURL_SUFFIX_CURL_OFF_TU = ULL
    CURL_TYPEOF_CURL_SOCKLEN_T  = ct.c_int

elif defined("__LCC__"):
    if defined("__e2k__"): # MCST eLbrus C Compiler
        CURL_TYPEOF_CURL_OFF_T     = long
        CURL_FORMAT_CURL_OFF_T     = "ld"
        CURL_FORMAT_CURL_OFF_TU    = "lu"
        CURL_SUFFIX_CURL_OFF_T     = L
        CURL_SUFFIX_CURL_OFF_TU    = UL
        CURL_TYPEOF_CURL_SOCKLEN_T = socklen_t
    else:                # Local (or Little) C Compiler
        CURL_TYPEOF_CURL_OFF_T     = long
        CURL_FORMAT_CURL_OFF_T     = "ld"
        CURL_FORMAT_CURL_OFF_TU    = "lu"
        CURL_SUFFIX_CURL_OFF_T     = L
        CURL_SUFFIX_CURL_OFF_TU    = UL
        CURL_TYPEOF_CURL_SOCKLEN_T = ct.c_int

elif defined("__SYMBIAN32__"):
    if defined("__EABI__"): # Treat all ARM compilers equally
        CURL_TYPEOF_CURL_OFF_T = ct.c_int64
    elif defined("__CW32__"):
        CURL_TYPEOF_CURL_OFF_T = ct.c_int64
    elif defined("__VC32__"):
        CURL_TYPEOF_CURL_OFF_T = ct.c_int64
    CURL_FORMAT_CURL_OFF_T     = "lld"
    CURL_FORMAT_CURL_OFF_TU    = "llu"
    CURL_SUFFIX_CURL_OFF_T     = LL
    CURL_SUFFIX_CURL_OFF_TU    = ULL
    CURL_TYPEOF_CURL_SOCKLEN_T = ct.c_uint

elif defined("__MWERKS__"):
   CURL_TYPEOF_CURL_OFF_T     = ct.c_int64
   CURL_FORMAT_CURL_OFF_T     = "lld"
   CURL_FORMAT_CURL_OFF_TU    = "llu"
   CURL_SUFFIX_CURL_OFF_T     = LL
   CURL_SUFFIX_CURL_OFF_TU    = ULL
   CURL_TYPEOF_CURL_SOCKLEN_T = ct.c_int

elif defined("_WIN32_WCE"):
   CURL_TYPEOF_CURL_OFF_T     = ct.c_int64
   CURL_FORMAT_CURL_OFF_T     = "I64d"
   CURL_FORMAT_CURL_OFF_TU    = "I64u"
   CURL_SUFFIX_CURL_OFF_T     = i64
   CURL_SUFFIX_CURL_OFF_TU    = ui64
   CURL_TYPEOF_CURL_SOCKLEN_T = ct.c_int

elif defined("__MINGW32__"):
   CURL_TYPEOF_CURL_OFF_T     = ct.c_int64
   CURL_FORMAT_CURL_OFF_T     = "I64d"
   CURL_FORMAT_CURL_OFF_TU    = "I64u"
   CURL_SUFFIX_CURL_OFF_T     = LL
   CURL_SUFFIX_CURL_OFF_TU    = ULL
   CURL_TYPEOF_CURL_SOCKLEN_T = socklen_t

elif defined("__VMS"):
    if defined("__VAX"):
        CURL_TYPEOF_CURL_OFF_T  = long
        CURL_FORMAT_CURL_OFF_T  = "ld"
        CURL_FORMAT_CURL_OFF_TU = "lu"
        CURL_SUFFIX_CURL_OFF_T  = L
        CURL_SUFFIX_CURL_OFF_TU = UL
    else:
        CURL_TYPEOF_CURL_OFF_T  = ct.c_int64
        CURL_FORMAT_CURL_OFF_T  = "lld"
        CURL_FORMAT_CURL_OFF_TU = "llu"
        CURL_SUFFIX_CURL_OFF_T  = LL
        CURL_SUFFIX_CURL_OFF_TU = ULL
    CURL_TYPEOF_CURL_SOCKLEN_T  = ct.c_uint

elif defined("__OS400__"):
    if defined("__ILEC400__"):
        CURL_TYPEOF_CURL_OFF_T     = ct.c_int64
        CURL_FORMAT_CURL_OFF_T     = "lld"
        CURL_FORMAT_CURL_OFF_TU    = "llu"
        CURL_SUFFIX_CURL_OFF_T     = LL
        CURL_SUFFIX_CURL_OFF_TU    = ULL
        CURL_TYPEOF_CURL_SOCKLEN_T = socklen_t

elif defined("__MVS__"):
    if defined("__IBMC__") or defined("__IBMCPP__"):
        if defined("_LONG_LONG"):
            CURL_TYPEOF_CURL_OFF_T  = ct.c_int64
            CURL_FORMAT_CURL_OFF_T  = "lld"
            CURL_FORMAT_CURL_OFF_TU = "llu"
            CURL_SUFFIX_CURL_OFF_T  = LL
            CURL_SUFFIX_CURL_OFF_TU = ULL
        elif defined("_LP64"):
            CURL_TYPEOF_CURL_OFF_T  = ct.c_int64
            CURL_FORMAT_CURL_OFF_T  = "ld"
            CURL_FORMAT_CURL_OFF_TU = "lu"
            CURL_SUFFIX_CURL_OFF_T  = L
            CURL_SUFFIX_CURL_OFF_TU = UL
        else:
            CURL_TYPEOF_CURL_OFF_T  = long
            CURL_FORMAT_CURL_OFF_T  = "ld"
            CURL_FORMAT_CURL_OFF_TU = "lu"
            CURL_SUFFIX_CURL_OFF_T  = L
            CURL_SUFFIX_CURL_OFF_TU = UL
        CURL_TYPEOF_CURL_SOCKLEN_T  = socklen_t

elif defined("__370__"):
    if defined("__IBMC__") or defined("__IBMCPP__"):
        if defined("_LONG_LONG"):
            CURL_TYPEOF_CURL_OFF_T  = ct.c_int64
            CURL_FORMAT_CURL_OFF_T  = "lld"
            CURL_FORMAT_CURL_OFF_TU = "llu"
            CURL_SUFFIX_CURL_OFF_T  = LL
            CURL_SUFFIX_CURL_OFF_TU = ULL
        elif defined("_LP64"):
            CURL_TYPEOF_CURL_OFF_T  = ct.c_int64
            CURL_FORMAT_CURL_OFF_T  = "ld"
            CURL_FORMAT_CURL_OFF_TU = "lu"
            CURL_SUFFIX_CURL_OFF_T  = L
            CURL_SUFFIX_CURL_OFF_TU = UL
        else:
            CURL_TYPEOF_CURL_OFF_T  = long
            CURL_FORMAT_CURL_OFF_T  = "ld"
            CURL_FORMAT_CURL_OFF_TU = "lu"
            CURL_SUFFIX_CURL_OFF_T  = L
            CURL_SUFFIX_CURL_OFF_TU = UL
        CURL_TYPEOF_CURL_SOCKLEN_T = socklen_t

elif defined("TPF"):
    CURL_TYPEOF_CURL_OFF_T     = long
    CURL_FORMAT_CURL_OFF_T     = "ld"
    CURL_FORMAT_CURL_OFF_TU    = "lu"
    CURL_SUFFIX_CURL_OFF_T     = L
    CURL_SUFFIX_CURL_OFF_TU    = UL
    CURL_TYPEOF_CURL_SOCKLEN_T = ct.c_int

elif defined("__TINYC__"): # also known as tcc
    CURL_TYPEOF_CURL_OFF_T     = ct.c_int64
    CURL_FORMAT_CURL_OFF_T     = "lld"
    CURL_FORMAT_CURL_OFF_TU    = "llu"
    CURL_SUFFIX_CURL_OFF_T     = LL
    CURL_SUFFIX_CURL_OFF_TU    = ULL
    CURL_TYPEOF_CURL_SOCKLEN_T = socklen_t

elif defined("__SUNPRO_C") or defined("__SUNPRO_CC"): # Oracle Solaris Studio
    if (not defined("__LP64") and (defined("__ILP32")   or
                                   defined("__i386")    or
                                   defined("__sparcv8") or
                                   defined("__sparcv8plus"))):
        CURL_TYPEOF_CURL_OFF_T  = ct.c_int64
        CURL_FORMAT_CURL_OFF_T  = "lld"
        CURL_FORMAT_CURL_OFF_TU = "llu"
        CURL_SUFFIX_CURL_OFF_T  = LL
        CURL_SUFFIX_CURL_OFF_TU = ULL
    elif defined("__LP64") or defined("__amd64") or defined("__sparcv9"):
        CURL_TYPEOF_CURL_OFF_T  = ct.c_int64
        CURL_FORMAT_CURL_OFF_T  = "ld"
        CURL_FORMAT_CURL_OFF_TU = "lu"
        CURL_SUFFIX_CURL_OFF_T  = L
        CURL_SUFFIX_CURL_OFF_TU = UL
    CURL_TYPEOF_CURL_SOCKLEN_T  = socklen_t

elif defined("__xlc__"): # IBM xlc compiler
    if not defined("_LP64"):
        CURL_TYPEOF_CURL_OFF_T  = ct.c_int64
        CURL_FORMAT_CURL_OFF_T  = "lld"
        CURL_FORMAT_CURL_OFF_TU = "llu"
        CURL_SUFFIX_CURL_OFF_T  = LL
        CURL_SUFFIX_CURL_OFF_TU = ULL
    else:
        CURL_TYPEOF_CURL_OFF_T  = ct.c_int64
        CURL_FORMAT_CURL_OFF_T  = "ld"
        CURL_FORMAT_CURL_OFF_TU = "lu"
        CURL_SUFFIX_CURL_OFF_T  = L
        CURL_SUFFIX_CURL_OFF_TU = UL
    CURL_TYPEOF_CURL_SOCKLEN_T  = socklen_t

# ===================================== #
#    KEEP MSVC THE PENULTIMATE ENTRY    #
# ===================================== #

elif defined("_MSC_VER"):
    if _MSC_VER >= 900 and _INTEGRAL_MAX_BITS >= 64:
        CURL_TYPEOF_CURL_OFF_T  = ct.c_int64
        CURL_FORMAT_CURL_OFF_T  = "I64d"
        CURL_FORMAT_CURL_OFF_TU = "I64u"
        CURL_SUFFIX_CURL_OFF_T  = i64
        CURL_SUFFIX_CURL_OFF_TU = ui64
    else:
        CURL_TYPEOF_CURL_OFF_T  = long
        CURL_FORMAT_CURL_OFF_T  = "ld"
        CURL_FORMAT_CURL_OFF_TU = "lu"
        CURL_SUFFIX_CURL_OFF_T  = L
        CURL_SUFFIX_CURL_OFF_TU = UL
    CURL_TYPEOF_CURL_SOCKLEN_T  = ct.c_int

# ===================================== #
#    KEEP GENERIC GCC THE LAST ENTRY    #
# ===================================== #

elif defined("__GNUC__") and not defined("_SCO_DS"):
    if (not defined("__LP64__") and
        (defined("__ILP32__")  or defined("__i386__")    or defined("__hppa__") or
         defined("__ppc__")    or defined("__powerpc__") or defined("__arm__")  or
         defined("__sparc__")  or defined("__mips__")    or defined("__sh__")   or
         defined("__XTENSA__") or
         (defined("__SIZEOF_LONG__") and __SIZEOF_LONG__ == 4)  or
         (defined("__LONG_MAX__")    and __LONG_MAX__ == 2147483647L))):
        CURL_TYPEOF_CURL_OFF_T  = ct.c_int64
        CURL_FORMAT_CURL_OFF_T  = "lld"
        CURL_FORMAT_CURL_OFF_TU = "llu"
        CURL_SUFFIX_CURL_OFF_T  = LL
        CURL_SUFFIX_CURL_OFF_TU = ULL
    elif (defined("__LP64__") or
          defined("__x86_64__") or defined("__ppc64__") or defined("__sparc64__") or
          defined("__e2k__") or
          (defined("__SIZEOF_LONG__") and __SIZEOF_LONG__ == 8) or
          (defined("__LONG_MAX__")    and __LONG_MAX__ == 9223372036854775807L)):
        CURL_TYPEOF_CURL_OFF_T  = ct.c_int64
        CURL_FORMAT_CURL_OFF_T  = "ld"
        CURL_FORMAT_CURL_OFF_TU = "lu"
        CURL_SUFFIX_CURL_OFF_T  = L
        CURL_SUFFIX_CURL_OFF_TU = UL
#  endif
    CURL_TYPEOF_CURL_SOCKLEN_T = socklen_t
else:
    # generic "safe guess" on old 32 bit style
    CURL_TYPEOF_CURL_OFF_T     = long
    CURL_FORMAT_CURL_OFF_T     = "ld"
    CURL_FORMAT_CURL_OFF_TU    = "lu"
    CURL_SUFFIX_CURL_OFF_T     = L
    CURL_SUFFIX_CURL_OFF_TU    = UL
    CURL_TYPEOF_CURL_SOCKLEN_T = ct.c_int

# Data type definition of curl_socklen_t.
if defined("CURL_TYPEOF_CURL_SOCKLEN_T"):
    typedef CURL_TYPEOF_CURL_SOCKLEN_T curl_socklen_t;

# Data type definition of curl_off_t.
if defined("CURL_TYPEOF_CURL_OFF_T"):
    typedef CURL_TYPEOF_CURL_OFF_T curl_off_t;

# CURL_ISOCPP and CURL_OFF_T_C definitions are done here in order to allow
# these to be visible and exported by the external libcurl interface API,
# while also making them visible to the library internals, simply including
# curl_setup.h, without actually needing to include curl.h internally.
# If some day this section would grow big enough, all this should be moved
# to its own header file.

# Figure out if we can use the ## preprocessor operator, which is supported
# by ISO/ANSI C and C++. Some compilers support it without setting __STDC__
# or  __cplusplus so we need to carefully check for them too.

if (defined("__STDC__") or defined("_MSC_VER")     or defined("__cplusplus") or
    defined("__HP_aCC") or defined("__BORLANDC__") or defined("__LCC__")     or
    defined("__POCC__") or defined("__SALFORDC__") or defined("__HIGHC__")   or
    defined("__ILEC400__")):
    # This compiler is believed to have an ISO compatible preprocessor
    #define CURL_ISOCPP
else:
    # This compiler is believed NOT to have an ISO compatible preprocessor
    #undef CURL_ISOCPP

#
# Macros for minimum-width signed and unsigned curl_off_t integer constants.
#

if defined("__BORLANDC__") and (__BORLANDC__ == 0x0551):
    #define CURLINC_OFF_T_C_HLPR2(x) x
    #define CURLINC_OFF_T_C_HLPR1(x) CURLINC_OFF_T_C_HLPR2(x)
    #define CURL_OFF_T_C(Val)  CURLINC_OFF_T_C_HLPR1(Val) ## CURLINC_OFF_T_C_HLPR1(CURL_SUFFIX_CURL_OFF_T)
    #define CURL_OFF_TU_C(Val) CURLINC_OFF_T_C_HLPR1(Val) ## CURLINC_OFF_T_C_HLPR1(CURL_SUFFIX_CURL_OFF_TU)
else:
    #ifdef CURL_ISOCPP
        #define CURLINC_OFF_T_C_HLPR2(Val,Suffix) Val ## Suffix
    else:
        #define CURLINC_OFF_T_C_HLPR2(Val,Suffix) Val/**/Suffix
    #define CURLINC_OFF_T_C_HLPR1(Val,Suffix) CURLINC_OFF_T_C_HLPR2(Val,Suffix)
    #define CURL_OFF_T_C(Val)  CURLINC_OFF_T_C_HLPR1(Val,CURL_SUFFIX_CURL_OFF_T)
    #define CURL_OFF_TU_C(Val) CURLINC_OFF_T_C_HLPR1(Val,CURL_SUFFIX_CURL_OFF_TU)
"""

# eof
