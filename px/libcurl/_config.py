# Copyright (c) 2021-2022 Adam Karpierz
# Licensed under the MIT License
# https://opensource.org/licenses/MIT

__all__ = ('make_config',)


def make_config(cfg_fname, cfg_section=None):
    import sys
    from pathlib import Path
    from functools import partial
    fglobals = sys._getframe(1).f_globals
    fglobals.pop("__builtins__", None)
    fglobals.pop("__cached__",   None)
    if cfg_section is None: cfg_section = fglobals["__package__"]
    cfg_path = Path(fglobals["__file__"]).parent/cfg_fname
    fglobals["__all__"] = ("config", "set_config")
    fglobals["config"] = get_config(cfg_path, cfg_section)
    fglobals["set_config"] = partial(set_config, fglobals)


def get_config(cfg_path, cfg_section):
    from pathlib import Path
    from configparser import ConfigParser, ExtendedInterpolation
    cfg_path = Path(cfg_path)
    if not cfg_path.is_file():
        return {}
    cfg = ConfigParser(interpolation=ExtendedInterpolation(),
                       inline_comment_prefixes=('#', ';'),
                       default_section=cfg_section)
    cfg.read(str(cfg_path), "utf-8")
    return cfg[cfg_section]


def set_config(fglobals, **cfg_dict):
    import sys
    import importlib
    # Update config
    to_update = {key: str(val) for key, val in cfg_dict.items()
                 if val is not None}
    to_remove = {key for key, val in cfg_dict.items() if val is None}
    package_name = fglobals["__package__"]
    config_name  = package_name + ".__config__"
    config = sys.modules[config_name].config
    config.update(to_update)
    for key in to_remove: config.pop(key, None)
    # Reload
    for mod_name in tuple(sys.modules):
        if (mod_name.startswith(package_name + ".") and
            mod_name != config_name):
            del sys.modules[mod_name]
    importlib.reload(sys.modules[package_name])
