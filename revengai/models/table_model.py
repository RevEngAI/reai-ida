from typing import Any, Optional

from PyQt5.QtCore import QAbstractTableModel, Qt

from revengai.models import IconItem, SimpleItem

import logging

logger = logging.getLogger("REAI")


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

    def data(self, index, role=None) -> Any:
        if index.isValid():
            item = self._data[index.row()][index.column()]
            if role == Qt.DecorationRole and isinstance(item, IconItem):
                return item.icon
            elif role == Qt.DisplayRole:
                return item.text if isinstance(item, SimpleItem) else item
        return None

    def get_datas(self) -> list[Any]:
        return self._data

    def get_data(self, pos: int) -> Optional[Any]:
        return self._data[pos] if len(self._data) > pos else None

    def headerData(self, col, orientation, role=None) -> Any:
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self._header[col]
        return None

    def fill_table(self, data: list) -> None:
        self.layoutAboutToBeChanged.emit()
        self._data = data
        self.layoutChanged.emit()
