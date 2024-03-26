from PyQt5.QtCore import Qt, QPersistentModelIndex

from revengai.table_model import RevEngTableModel


class RevEngCheckableTableModel(RevEngTableModel):
    def __init__(self, data: list, header: list, columns: list, parent=None):
        RevEngTableModel.__init__(self, data, header, parent)
        self._columns = columns
        self._checked = [[]]
        self.checks = {}

    def data(self, index, role=None):
        if index.isValid() and role == Qt.CheckStateRole and index.column() in self._columns:
            if role == Qt.CheckStateRole:
                return self._check_state(QPersistentModelIndex(index))
        return super().data(index, role)

    def setData(self, index, value, role=None):
        if index.isValid() and role == Qt.CheckStateRole and index.column() in self._columns:
            self.checks[QPersistentModelIndex(index)] = value
            return True
        return super().setData(index, value, role)

    def flags(self, index):
        flags = super().flags(index)

        if index.isValid() and index.column() in self._columns:
            flags |= Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsUserCheckable
        return flags

    def _check_state(self, index):
        return self.checks[index] if index in self.checks.keys() else Qt.Unchecked
