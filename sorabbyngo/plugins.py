from __future__ import annotations
import importlib, importlib.util, inspect, sys
from abc import ABC, abstractmethod
from pathlib import Path
from sorabbyngo.core.models import SecurityEvent

class BasePlugin(ABC):
    name: str = "unnamed"
    version: str = "0.1.0"
    description: str = ""
    enabled: bool = True
    def setup(self, config): pass
    def teardown(self): pass
    def to_dict(self):
        return {"name": self.name, "version": self.version, "description": self.description,
                "enabled": self.enabled, "type": self.__class__.__bases__[0].__name__}

class TriagePlugin(BasePlugin):
    @abstractmethod
    def score(self, event): ...
    def mitre_techniques(self, event): return []

class AlertPlugin(BasePlugin):
    @abstractmethod
    def send(self, alert_data): ...

class EnrichmentPlugin(BasePlugin):
    @abstractmethod
    def enrich(self, event): ...

class SourcePlugin(BasePlugin):
    @abstractmethod
    def poll(self): ...

class PluginRegistry:
    def __init__(self): self._plugins = {}
    def register(self, plugin, config=None):
        if not isinstance(plugin, BasePlugin): raise TypeError(f"Expected BasePlugin, got {type(plugin)}")
        if plugin.name in self._plugins: raise ValueError(f"Plugin '{plugin.name}' already registered")
        plugin.setup(config or {}); self._plugins[plugin.name] = plugin
    def unregister(self, name):
        plugin = self._plugins.pop(name, None)
        if plugin: plugin.teardown(); return True
        return False
    def enable(self, name):
        if name in self._plugins: self._plugins[name].enabled = True; return True
        return False
    def disable(self, name):
        if name in self._plugins: self._plugins[name].enabled = False; return True
        return False
    def get(self, name): return self._plugins.get(name)
    def all(self): return list(self._plugins.values())
    def of_type(self, t): return [p for p in self._plugins.values() if isinstance(p, t) and p.enabled]
    def triage_plugins(self): return self.of_type(TriagePlugin)
    def alert_plugins(self): return self.of_type(AlertPlugin)
    def enrichment_plugins(self): return self.of_type(EnrichmentPlugin)
    def source_plugins(self): return self.of_type(SourcePlugin)
    def count(self): return len(self._plugins)
    def stats(self):
        plugins = [p.to_dict() for p in self._plugins.values()]
        return {"total": len(plugins), "enabled": sum(1 for p in plugins if p["enabled"]),
                "disabled": sum(1 for p in plugins if not p["enabled"]), "plugins": plugins}
    def run_triage(self, event):
        scores = []
        for p in self.triage_plugins():
            try:
                s = p.score(event)
                if s is not None: scores.append(min(1.0, max(0.0, s)))
            except Exception: pass
        return max(scores) if scores else None
    def run_enrichment(self, event):
        for p in self.enrichment_plugins():
            try: event = p.enrich(event)
            except Exception: pass
        return event
    def run_alert(self, alert_data):
        results = {}
        for p in self.alert_plugins():
            try: results[p.name] = p.send(alert_data)
            except Exception: results[p.name] = False
        return results
    def collect_mitre(self, event):
        techniques = []
        for p in self.triage_plugins():
            try: techniques.extend(p.mitre_techniques(event))
            except Exception: pass
        return list(dict.fromkeys(techniques))
    def load_file(self, path):
        path = Path(path)
        if not path.exists(): raise FileNotFoundError(f"Plugin file not found: {path}")
        spec = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        registered = []
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, BasePlugin) and
                    obj not in (BasePlugin, TriagePlugin, AlertPlugin, EnrichmentPlugin, SourcePlugin) and
                    not inspect.isabstract(obj)):
                try: instance = obj(); self.register(instance); registered.append(instance.name)
                except Exception: pass
        return registered
