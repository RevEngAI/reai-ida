from PyQt5 import QtCore
from typing import Any
from revengai.logger import plugin_logger


class Model:
    class Base(QtCore.QAbstractTableModel):
        """
        Most of this is copied from Model.Base from FIRST
        """

        def __init__(self, header, data, parent=None) -> None:
            super(Model.Base, self).__init__(parent)
            self._header = header
            self._data = data

        def rowCount(self, parent) -> int:
            if self._data:
                return len(self._data)
            else:
                return 0

        def columnCount(self, parent) -> int:
            if self._header:
                return len(self._header)
            else:
                return 0

        def data(self, index, role: int = QtCore.Qt.ItemDataRole.DisplayRole):
            """
            Returns the data stored under the given role for the item referred to by the index.
            """
            if index.isValid() and role == QtCore.Qt.ItemDataRole.DisplayRole:
                # get data from given row index
                row = self._data[index.row()]
                if index.column() == 0 and type(row) is not dict:
                    # the data itself is not a dict and the col val is 0.
                    return row
                elif index.column() < self.columnCount(self.parent):
                    # the data is a dict, need to check col val is valid
                    if type(row) is dict:
                        # index the header using the column value and then use that value to index the row
                        if self._header[index.column()].lower() in row:
                            return row[self._header[index.column()].lower()]
                        else:
                            plugin_logger.debug("not found column inside header")

                    else:
                        # get the element using the column from the row data.
                        return row[index.column()]

                # column val is not valid
                return None
            else:
                # fires whenever mouse moves over / clicks button in menu
                # plugin_logger.debug(f"data() - unexpected role {role}")
                return None

        def headerData(self, section: int, orientation, role: int = ...) -> Any:
            """
            Returns the data for the given role and section in the header with the specified orientation.
            For horizontal headers, the section number corresponds to the column number.
            Similarly, for vertical headers, the section number corresponds to the row number.
            """
            if (
                    role == QtCore.Qt.ItemDataRole.DisplayRole
                    and orientation == QtCore.Qt.Orientation.Horizontal
                    and section < len(self._header)
            ):
                plugin_logger.debug("headerData() called")
                return self._header[section]
            else:
                return None
