from PyQt5.QtWidgets import QCheckBox
from PyQt5.QtCore import pyqtProperty, pyqtSignal


class QRevEngCard(QCheckBox):
    # Define a signal that will be emitted when a custom property changes
    customPropertyChanged = pyqtSignal(str)

    def __init__(self, text="", parent=None):
        super().__init__(text, parent)

        self.setStyleSheet(
            """
            QCheckBox {
                min-width: 2em;
                border-radius: 3px;
                border: 2px solid gray;
                padding: 2px 2px 2px 2px;
                background-color: #737373;
            }
            """
        )

        # Initialize custom properties
        self._custom_data = None

    # Define a custom property 'custom_data'
    @pyqtProperty(object)
    def custom_data(self):
        return self._custom_data

    @custom_data.setter
    def custom_data(self, value):
        if self._custom_data != value:
            self._custom_data = value
            self.customPropertyChanged.emit('custom_data')
