# -*- coding: utf-8 -*-

from PyQt5.QtCore import Qt, QPersistentModelIndex
from PyQt5.QtGui import QStandardItem

from revengai.models.table_model import RevEngTableModel


class RevEngCheckableTableModel(RevEngTableModel):
    def __init__(self, data: list, header: list, columns: list, parent=None,
                 flag: int = (Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsUserCheckable)):
        RevEngTableModel.__init__(self, data, header, parent)

        self._checked = {}

        self.flag = flag
        self._columns = columns

    def data(self, index, role=None):
        if index.isValid() and role == Qt.CheckStateRole and index.column() in self._columns:
            if isinstance(self._data[index.row()][index.column()], QStandardItem):
                return self._data[index.row()][index.column()].checkState()
            return self._check_state(QPersistentModelIndex(index))
        return super().data(index, role)

    def setData(self, index, value, role=None):
        if index.isValid() and role == Qt.CheckStateRole and index.column() in self._columns:
            self._checked[QPersistentModelIndex(index)] = value
            return True
        return super().setData(index, value, role)

    def flags(self, index):
        if index.isValid() and index.column() in self._columns:
            if isinstance(self._data[index.row()][index.column()], QStandardItem):
                return self._data[index.row()][index.column()].flags()
            return self.flag
        return super().flags(index)

    def _check_state(self, index):
        return self._checked[index] if index in self._checked.keys() else Qt.Unchecked
