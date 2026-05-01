import importlib
import inspect
import pkgutil
from pathlib import Path


class PluginRegistry:
    def __init__(self):
        self._plugins = {}

    def load_directory(self, plugins_dir):
        from src.core.plugin_base import PluginBase
        plugins_dir = Path(plugins_dir).resolve()
        if not plugins_dir.exists():
            return
        root = Path(__file__).parent.parent.parent.resolve()
        pkg = ".".join(plugins_dir.relative_to(root).parts)
        for _, modname, _ in pkgutil.iter_modules([str(plugins_dir)]):
            if modname.startswith("_") or modname.startswith("template_"):
                continue
            try:
                mod = importlib.import_module(f"{pkg}.{modname}")
                for _, cls in inspect.getmembers(mod, inspect.isclass):
                    if (issubclass(cls, PluginBase) and cls is not PluginBase
                            and hasattr(cls, "meta")):
                        self._plugins[cls.meta.name] = cls
            except Exception as e:
                from src.utils import logger
                logger.warning(f"Plugin load error [{modname}]: {e}")

    def get(self, name):
        return self._plugins.get(name)

    def all(self):
        return dict(self._plugins)

    def by_category(self, category):
        return {k: v for k, v in self._plugins.items() if v.meta.category == category}

    def __len__(self):
        return len(self._plugins)
