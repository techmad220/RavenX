
from __future__ import annotations
import os, sys, importlib.util, types
from typing import Callable, List, Any, Dict

class PluginAPI:
    def __init__(self):
        self.check_factories: List[Callable[[], Any]] = []
        self.exporters: Dict[str, Any] = {}
        self.triage_pre: List[Callable[[list], list]] = []
        self.triage_post: List[Callable[[list], list]] = []
        self.cli_args: List[Callable[[Any], None]] = []  # functions that accept argparse.ArgumentParser

    def register_check(self, factory: Callable[[], Any]):  # factory returns a BaseCheck instance
        self.check_factories.append(factory)

    def register_exporter(self, name: str, exporter: Any):
        self.exporters[name] = exporter

    def register_triage_pre(self, fn: Callable[[list], list]):
        self.triage_pre.append(fn)

    def register_triage_post(self, fn: Callable[[list], list]):
        self.triage_post.append(fn)

    def register_cli(self, fn: Callable[[Any], None]):
        self.cli_args.append(fn)

def _import_module_from_path(path: str) -> types.ModuleType | None:
    name = os.path.splitext(os.path.basename(path))[0]
    spec = importlib.util.spec_from_file_location(f"ravenx_plugin_{name}", path)
    if spec and spec.loader:
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)  # type: ignore
        return mod
    return None

def discover_plugins(plugins_path: str) -> PluginAPI:
    api = PluginAPI()
    if not os.path.isdir(plugins_path):
        return api
    for entry in os.listdir(plugins_path):
        p = os.path.join(plugins_path, entry)
        mod = None
        if os.path.isdir(p):
            main_py = os.path.join(p, "plugin.py")
            if os.path.exists(main_py):
                mod = _import_module_from_path(main_py)
        elif entry.endswith(".py"):
            mod = _import_module_from_path(p)
        if mod and hasattr(mod, "register"):
            try:
                mod.register(api)  # type: ignore
            except Exception as e:
                print(f"[plugin] failed to register {entry}: {e}")
    return api
