from typing import Any

from PyQt5.QtCore import Qt

from revengai.models import CheckableItem
from revengai.models.table_model import RevEngTableModel

import logging


logger = logging.getLogger("REAI")


class RevEngCheckableTableModel(RevEngTableModel):
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
        RevEngTableModel.__init__(self, data, header, parent)

        self.flag = flag
        self._columns = columns

    def data(self, index, role=None) -> Any:
        super().data(index, role)
        if (
                index.isValid()
                and role == Qt.CheckStateRole
                and index.column() in self._columns
        ):
            if isinstance(
                    self._data[index.row()][index.column()],
                    CheckableItem
            ):
                return self._data[index.row()][index.column()].checkState
            return Qt.Unchecked
        return super().data(index, role)

    def getModelData(self, index) -> Any:
        data = list(self._data[index.row()])
        return data[index.column()] if index.isValid() else None

    def setData(self, index, value, role=None) -> bool:
        # if (
        #         index.isValid()
        #         and role == Qt.CheckStateRole
        #         and index.column() in self._columns
        # ):
        #     if isinstance(
        #             self._data[index.row()][index.column()],
        #             CheckableItem
        #     ):
        #         self._data[index.row()][index.column()].checkState = value
        #         self.dataChanged.emit(index, index)
        #         return True
        super().setData(index, value, role)
        data = self._data[index.row()]
        # data is a tuple so first convert it to a list
        data = list(data)
        # set the value
        data[index.column()] = value
        # convert it back to a tuple
        data = tuple(data)
        # set the data back to the original list
        self._data[index.row()] = data
        # emit the dataChanged signal
        self.dataChanged.emit(index, index)
        return True

    def flags(self, index) -> Qt.ItemFlag:
        if index.isValid() and index.column() in self._columns:
            return self.flag
        return super().flags(index)
