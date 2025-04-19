
from PyQt5.QtCore import Qt

from revengai.models import CheckableItem
from revengai.models.checkable_model import RevEngCheckableTableModel

import logging


logger = logging.getLogger("REAI")


class RevEngSingleCheckableTableModel(RevEngCheckableTableModel):
    def __init__(
            self,
            data: list,
            header: list,
            columns: list,
            parent=None,
            flag: Qt.ItemFlag = (
                Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsUserCheckable
            ),
    ):
        RevEngCheckableTableModel.__init__(
            self,
            data,
            header,
            columns,
            parent,
            flag
        )

    def _uncheck_all_except(self, index):
        # uncheck all other checkable items in all the other rows
        for row in range(self.rowCount()):
            if row != index.row():
                if isinstance(self._data[row][index.column()], CheckableItem):
                    self._data[row][index.column()].checkState = Qt.Unchecked
                    index = self.index(row, index.column())
                    self.dataChanged.emit(index, index)

    def setData(self, index, value, role=None) -> bool:
        super().setData(index, value, role)
        data = self._data[index.row()]
        data = list(data)

        if isinstance(data[index.column()], CheckableItem):
            if role == Qt.CheckStateRole:
                # set the check state
                if value == Qt.Checked:
                    # uncheck all other checkable items in all the other rows
                    self._uncheck_all_except(index)
                data[index.column()].checkState = value
                self.dataChanged.emit(index, index)
                return True
        else:
            # set the value
            data[index.column()] = value
            # convert it back to a tuple
            data = tuple(data)
            # set the data back to the original list
            self._data[index.row()] = data
            # emit the dataChanged signal
            self.dataChanged.emit(index, index)
            return True
