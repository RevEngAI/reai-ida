from PyQt5.QtWidgets import QSlider
from PyQt5.QtWidgets import QToolTip


class Slider(QSlider):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setMouseTracking(True)

    def mouseMoveEvent(self, event) -> None:
        QToolTip.showText(event.globalPos(), f"{self.value():#02d}")

        super().mouseMoveEvent(event)
