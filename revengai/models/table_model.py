# -*- coding: utf-8 -*-
from typing import Optional

from PyQt5.QtCore import QAbstractTableModel, Qt
from PyQt5.QtGui import QIcon

from os.path import dirname, join


class TableItem(object):
    def __init__(self, text: str, resource_name: str = None):
        self.text: str = text

        self.icon: Optional[QIcon] = QIcon(TableItem._plugin_resource(resource_name)) if resource_name else None

    @staticmethod
    def _plugin_resource(resource_name: str) -> str:
        """
        Return the full path for a given plugin resource file.
        """
        return join(dirname(__file__), "../resources", resource_name)


class RevEngTableModel(QAbstractTableModel):
    def __init__(self, data: list, header: list, parent=None):
        QAbstractTableModel.__init__(self, parent)

        self._data: list = data
        self._header: list = header

    def rowCount(self, parent=None) -> int:
        return len(self._data) if self._data else 0

    def columnCount(self, parent=None) -> int:
        if self.rowCount(parent) > 0 and len(self._data) > 0:
            return len(self._data[0])
        return 0

    def data(self, index, role=None):
        if index.isValid():
            item = self._data[index.row()][index.column()]
            if isinstance(item, TableItem):
                if role == Qt.DecorationRole:
                    return item.icon
                elif role == Qt.DisplayRole:
                    return item.text
            elif role == Qt.DisplayRole:
                return item
        return None

    @property
    def get_data(self) -> list:
        return self._data

    def headerData(self, col, orientation, role=None):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self._header[col]
        return None

    def fill_table(self, data: list) -> None:
        self.layoutAboutToBeChanged.emit()
        self._data = data
        self.layoutChanged.emit()
