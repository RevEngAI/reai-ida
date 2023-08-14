from PyQt5 import QtWidgets, QtGui, QtCore
from idaapi import PluginForm
import urllib.request
import webbrowser


class LoginDialog(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Revenge.AI for IDA Pro")  # Set window title

        layout = QtWidgets.QVBoxLayout()

        # Logo
        logo_url = 'https://portal.reveng.ai/_next/image?url=%2Ficon.png&w=64&q=75'
        data = urllib.request.urlopen(logo_url).read()
        pixmap = QtGui.QPixmap()
        pixmap.loadFromData(data)
        logo_label = QtWidgets.QLabel()
        logo_label.setPixmap(pixmap)
        logo_label.setAlignment(QtCore.Qt.AlignCenter)  # Center the logo
        layout.addWidget(logo_label)

        # Title
        title_label = QtWidgets.QLabel('Input your user info')
        font = title_label.font()
        font.setBold(True)  # Set font to bold
        title_label.setFont(font)
        title_label.setAlignment(QtCore.Qt.AlignCenter)  # Center the title
        layout.addWidget(title_label)

        # API Key Field
        self.api_key_label = QtWidgets.QLabel('API Key:')
        self.api_key_field = QtWidgets.QLineEdit()
        layout.addWidget(self.api_key_label)
        layout.addWidget(self.api_key_field)

        # Model Name Field
        self.model_name_label = QtWidgets.QLabel('Model Name:')
        self.model_name_field = QtWidgets.QLineEdit()
        layout.addWidget(self.model_name_label)
        layout.addWidget(self.model_name_field)

        # Add some space between the last input box and the buttons
        layout.addSpacing(20)

        # Create a horizontal layout for the buttons
        button_layout = QtWidgets.QHBoxLayout()

        # Save Button
        self.save_button = QtWidgets.QPushButton('Save')
        self.save_button.clicked.connect(self.on_save_click)
        button_layout.addWidget(self.save_button)

        # "Don't know your API Key?" Button
        self.api_key_help_button = QtWidgets.QPushButton("Don't know your API Key?")
        self.api_key_help_button.clicked.connect(self.on_api_key_help_click)
        button_layout.addWidget(self.api_key_help_button)

        # Set spacing between the buttons
        button_layout.setSpacing(10)

        # Add the button layout to the main layout
        layout.addLayout(button_layout)

        self.setLayout(layout)

        self.setMinimumWidth(400)  # Set the minimum width of the window

    def on_save_click(self):
        api_key = self.api_key_field.text()
        model_name = self.model_name_field.text()

        # File path for the hidden file in the home directory
        file_path = os.path.expanduser('~/.read.test')

        # Writing to the file
        with open(file_path, 'w') as file:
            file.write(f'apikey = "{api_key}"\n')
            file.write('host = "https://api.reveng.ai"\n')
            file.write(f'model = "{model_name}"\n')

        print(f'User Info Saved: API Key - {api_key}, Model Name - {model_name}')
        self.accept()

    def on_api_key_help_click(self):
        webbrowser.open('https://portal.reveng.ai')


class LoginPlugin(PluginForm):
    def OnCreate(self, form):
        login_dialog = LoginDialog()
        login_dialog.exec_()

    def OnClose(self, form):
        pass


plg = LoginPlugin()
plg.Show("Login Window")
