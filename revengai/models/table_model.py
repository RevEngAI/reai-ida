# -*- coding: utf-8 -*-

from PyQt5.QtCore import QAbstractTableModel, Qt


class RevEngTableModel(QAbstractTableModel):
    def __init__(self, data: list, header: list, parent=None):
        QAbstractTableModel.__init__(self, parent)
        self._data: list = data
        self._header: list = header

    def rowCount(self, parent=None):
        return len(self._data) if self._data else 0

    def columnCount(self, parent=None):
        if self.rowCount(parent) > 0 and len(self._data) > 0:
            return len(self._data[0])
        return 0

    def data(self, index, role=None):
        if index.isValid() and role == Qt.DisplayRole:
            return self._data[index.row()][index.column()]
        return None

    def headerData(self, col, orientation, role=None):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self._header[col]
        return None

    def fill_table(self, data: list):
        self.beginResetModel()
        self._data = data
        self.endResetModel()
