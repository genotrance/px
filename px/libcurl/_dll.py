# Copyright (c) 2021-2022 Adam Karpierz
# Licensed under the MIT License
# https://opensource.org/licenses/MIT

from ._platform import DLL_PATH, DLL, dlclose

try:
    dll = DLL(DLL_PATH)
except OSError as exc:  # pragma: no cover
    raise exc
except Exception as exc:  # pragma: no cover
    raise OSError("{}".format(exc)) from None
