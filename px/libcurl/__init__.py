# Copyright (c) 2021-2022 Adam Karpierz
# Licensed under the MIT License
# https://opensource.org/licenses/MIT

from . import __config__ ; del __config__
from .__about__ import * ; del __about__  # noqa
from .__config__ import set_config as config

from ._curl import *  # noqa
