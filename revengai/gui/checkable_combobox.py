# -*- coding: utf-8 -*-
from PyQt5.QtCore import Qt, QEvent, QObject
from PyQt5.QtGui import QFontMetrics, QStandardItem
from PyQt5.QtWidgets import QComboBox, QStyledItemDelegate


class CheckableComboBox(QComboBox):
    # Subclass Delegate to increase item height
    class Delegate(QStyledItemDelegate):
        def sizeHint(self, option, index):
            size = super().sizeHint(option, index)
            size.setHeight(20)
            return size

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Make the combo editable to set a custom text, but readonly
        self.setEditable(True)
        self.lineEdit().setReadOnly(True)

        # Use custom delegate
        self.setItemDelegate(CheckableComboBox.Delegate())

        # Update the text when an item is toggled
        self.model().dataChanged.connect(self.updateText)

        # Hide and show popup when clicking the line edit
        self.lineEdit().installEventFilter(self)
        self.closeOnLineEditClick = False

        # Prevent popup from closing when clicking on an item
        self.view().viewport().installEventFilter(self)

    def resizeEvent(self, event: any, QResizeEvent=None) -> None:
        # Recompute text to elide as needed
        self.updateText()

        super().resizeEvent(event)

    def eventFilter(self, watched: QObject, event) -> bool:
        if watched == self.lineEdit():
            if event.type() == QEvent.MouseButtonRelease:
                if self.closeOnLineEditClick:
                    self.hidePopup()
                else:
                    self.showPopup()
                return True
            return False

        if watched == self.view().viewport():
            if event.type() == QEvent.MouseButtonRelease:
                index = self.view().indexAt(event.pos())
                item = self.model().item(index.row())

                if item.checkState() == Qt.Checked:
                    item.setCheckState(Qt.Unchecked)
                else:
                    item.setCheckState(Qt.Checked)
                return True
        return False

    def showPopup(self) -> None:
        super().showPopup()

        # When the popup is displayed, a click on the lineedit should close it
        self.closeOnLineEditClick = True

    def hidePopup(self) -> None:
        super().hidePopup()

        # Used to prevent immediate reopening when clicking on the lineEdit
        self.startTimer(100)

        # Refresh the display text when closing
        self.updateText()

    def timerEvent(self, event) -> None:
        # After timeout, kill timer, and reenable click on line edit
        self.killTimer(event.timerId())

        self.closeOnLineEditClick = False

    def updateText(self) -> None:
        texts = []
        for i in range(self.model().rowCount()):
            if self.model().item(i).checkState() == Qt.Checked:
                texts.append(self.model().item(i).text())

        text = ", ".join(texts)

        # Compute elided text (with "…")
        metrics = QFontMetrics(self.lineEdit().font())
        elidedText = metrics.elidedText(text, Qt.ElideRight, self.lineEdit().width())
        self.lineEdit().setText(elidedText)

    def addItem(self, text: str, data=None) -> None:
        item = QStandardItem(text)

        item.setData(data if data else text)
        item.setData(Qt.Unchecked, Qt.CheckStateRole)
        item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled | Qt.ItemIsUserCheckable)

        self.model().appendRow(item)

    def addItems(self, texts: list, Optional=None, p_str=None) -> None:
        for text in texts:
            self.addItem(text)

    def currentData(self, role=None) -> list:
        # Return the list of selected items data
        res = []
        for i in range(self.model().rowCount()):
            if self.model().item(i).checkState() == Qt.Checked:
                res.append(self.model().item(i).data())

        return res
