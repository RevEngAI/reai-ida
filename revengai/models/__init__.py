# -*- coding: utf-8 -*-
from typing import Optional, Any
from os.path import dirname, isfile, join

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon


class SimpleItem(object):
    def __init__(self, text: Optional[str], data: Any = None):
        self.text: str = text
        self.data: Any = data

    def __repr__(self):
        if self.text:
            return self.text
        return super().__repr__()


class IconItem(SimpleItem):
    def __init__(self, text: str, resource_name: str = None):
        super().__init__(text=text)

        resource_path = IconItem._plugin_resource(resource_name) if resource_name else None

        self.icon: Optional[QIcon] = QIcon(resource_path) if (resource_path and isfile(resource_path)) else None

    @staticmethod
    def _plugin_resource(resource_name: str) -> str:
        """
        Return the full path for a given plugin resource file.
        """
        return join(dirname(__file__), "..", "resources", resource_name)


class CheckableItem(SimpleItem):
    def __init__(self, data: Any = None, checked: bool = True):
        super().__init__(text=None, data=data)

        self.checkState: int = Qt.Checked if checked else Qt.Unchecked
