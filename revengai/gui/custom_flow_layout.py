from typing import Optional

from PyQt5.QtCore import QPoint
from PyQt5.QtCore import QRect
from PyQt5.QtCore import QSize
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QLayout
from PyQt5.QtWidgets import QLayoutItem
from PyQt5.QtWidgets import QSizePolicy
from PyQt5.QtWidgets import QWidget
from revengai.gui.custom_card import QRevEngCard
import logging

logger = logging.getLogger("REAI")


class CustomFlowLayout(QLayout):
    def __init__(
            self,
            parent: QWidget = None,
            margin: int = 0,
            spacing: int = -1
    ):
        super().__init__(parent)

        if parent is not None:
            self.setContentsMargins(margin, margin, margin, margin)

        self.setSpacing(spacing)

        self.callback = None

        self._items: list[QLayoutItem] = []
        self.__pending_positions: dict[QWidget, int] = {}

    def __del__(self):
        item = self.takeAt(0)
        while item:
            item = self.takeAt(0)

    def addItem(self, a0: QLayoutItem) -> None:
        # try:
        #     position = self.__pending_positions[a0.widget()]
        #     self._items.insert(position, a0)

        #     del self.__pending_positions[a0.widget()]
        # except KeyError:
        #     self._items.append(a0)
        widget = a0.widget()
        if isinstance(widget, QRevEngCard):
            self._items.append(a0)
        else:
            logger.warning("CustomFlowLayout: addItem: not a QRevEngCard")

    def addWidget(
            self,
            w: QWidget,
            position: int = None,
            align: Qt.AlignmentFlag = Qt.AlignLeft
    ) -> None:
        if position is not None:
            self.__pending_positions[w] = position

        if align is not None:
            frame_layout = w.layout()
            if frame_layout is not None:
                frame_layout.setAlignment(align)

        super().addWidget(w)

    def count(self):
        return len(self._items)

    def expandingDirections(self):
        return Qt.Orientations(Qt.Orientation(0))

    def itemAt(self, index: int) -> Optional[QLayoutItem]:
        if 0 <= index < len(self._items):
            return self._items[index]
        return None

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, width) -> int:
        return self._doLayout(QRect(0, 0, width, 0), True)

    def minimumSize(self) -> QSize:
        size = QSize()

        for item in self._items:
            size = size.expandedTo(item.minimumSize())

        margin, _, _, _ = self.getContentsMargins()

        size += QSize(2 * margin, 2 * margin)
        return size

    def removeItem(self, a0: QLayoutItem) -> None:
        logger.info("CustomFlowLayout: removeItem")
        widget = a0.widget()
        if widget and hasattr(widget, 'custom_data'):
            el = next(
                (item for item in self._items if item.widget() == widget), None
            )
            if el:
                self._items.remove(el)

    def removeWidget(self, widget: QRevEngCard) -> None:
        if widget is not None:
            if self.callback and hasattr(widget, 'custom_data'):
                data = widget.custom_data
                self.callback(data)
            super().removeWidget(widget)
            widget.deleteLater()

    def setGeometry(self, rect: QRect) -> None:
        super().setGeometry(rect)
        self._doLayout(rect)

    def sizeHint(self):
        return self.minimumSize()

    def takeAt(self, index: int) -> Optional[QLayoutItem]:
        if 0 <= index < len(self._items):
            item = self._items.pop(index)
            return item
        return None

    def _doLayout(self, rect: QRect, testOnly: bool = False):
        """
        This does the layout. Don't ask me how.
        Source:
        https://github.com/baoboa/pyqt5/blob/master/examples/layouts/flowlayout.py
        """
        x = rect.x()
        y = rect.y()
        line_height = 0

        for item in self._items:
            wid = item.widget()

            space_x = self.spacing() + wid.style().layoutSpacing(
                QSizePolicy.Label, QSizePolicy.Label, Qt.Horizontal
            )

            space_y = self.spacing() + wid.style().layoutSpacing(
                QSizePolicy.Label, QSizePolicy.Label, Qt.Vertical
            )

            next_x = x + item.sizeHint().width() + space_x
            if next_x - space_x > rect.right() and line_height > 0:
                x = rect.x()
                y += line_height + space_y
                next_x = x + item.sizeHint().width() + space_x
                line_height = 0

            if not testOnly:
                item.setGeometry(QRect(QPoint(x, y), item.sizeHint()))

            x = next_x
            line_height = max(line_height, item.sizeHint().height())

        return y + line_height - rect.y()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._doLayout(self.geometry())

    def add_card(self, data: dict) -> None:
        if not self.is_present(data):
            child: QRevEngCard = QRevEngCard(data["item_name"])
            child.custom_data = data
            child.setChecked(True)
            child.setObjectName(data["item_name"])
            child.setLayoutDirection(Qt.RightToLeft)
            child.stateChanged.connect(lambda: self.removeWidget(child))

            self.addWidget(child)

    def remove_card(self, data: dict) -> None:
        element = next(
            (
                item for item in self._items
                if item.widget().custom_data["item_id"] == data["item_id"] and
                item.widget().custom_data["item_name"] == data["item_name"]
            ),
            None
        )
        self.removeWidget(element.widget()) if element else None

    def is_present(self, data: dict) -> bool:
        return any(
            item.widget().custom_data["item_id"] == data["item_id"] and
            item.widget().custom_data["item_name"] == data["item_name"]
            for item in self._items
        ) if data else False

    def register_cb(self, fn):
        self.callback = fn
