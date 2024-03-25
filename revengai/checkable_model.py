from PyQt5.QtCore import Qt

from revengai.table_model import RevEngTableModel


class RevEngCheckableTableModel(RevEngTableModel):
    def __init__(self, data: list, header: list, columns: list, parent=None):
        RevEngTableModel.__init__(self, data, header, parent)
        self._columns = columns
        self._checked = [[]]

    def data(self, index, role=None):
        if index.isValid() and role == Qt.CheckStateRole and index.column() in self._columns:
            if role == Qt.CheckStateRole:
                checked = self._data[index.row()][index.column()]
                return Qt.Checked if checked else Qt.Unchecked
            return '' if index.column() == 1 else self._data[index.row()][index.column()]
        return super().data(index, role)

    def setData(self, index, value, role=None):
        if index.isValid() and role == Qt.CheckStateRole and index.column() in self._columns:
            self._data[index.row()][index.column()] = value == Qt.Checked
            return True
        return super().setData(index, value, role)

    def flags(self, index):
        if index.isValid() and index.column() in self._columns:
            return Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsUserCheckable
        return super().flags(index)
