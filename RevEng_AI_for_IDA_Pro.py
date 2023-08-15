import os
from PyQt5 import QtWidgets, QtGui, QtCore
import idaapi
import urllib.request
import webbrowser
import requests
from reait import api as reait_api


class SampleSubmitDialog(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("RevEng.AI for IDA Pro")

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

        title_label = QtWidgets.QLabel("Submit Sample for Analysis")
        font = title_label.font()
        font.setBold(True)  # Set font to bold
        title_label.setFont(font)
        title_label.setAlignment(QtCore.Qt.AlignCenter)  # Center the title
        layout.addWidget(title_label)

        # Sample Path Field with the current file name in IDA Pro
        current_file_path = idaapi.get_input_file_path()
        self.sample_path = current_file_path
        current_file_name = os.path.basename(current_file_path)  # Extract only the filename
        truncated_name = self.truncate_filename(current_file_name,
                                                max_length=30)  # Limit filename to a max of 30 characters for this example

        self.sample_path_field = QtWidgets.QLineEdit(truncated_name)
        self.sample_path_field.setReadOnly(True)  # So the user can't edit it

        # Calculate width based on text content and set the width of QLineEdit
        font_metrics = self.sample_path_field.fontMetrics()
        width = font_metrics.width(truncated_name) + 10  # Additional 10 pixels for some padding
        self.sample_path_field.setFixedWidth(width)

        # Adding "Opened File:" QLabel
        label = QtWidgets.QLabel("Opened File:")

        # Centering QLineEdit and label using QHBoxLayout
        hlayout = QtWidgets.QHBoxLayout()
        hlayout.addStretch(1)
        hlayout.addWidget(label)
        hlayout.addWidget(self.sample_path_field)
        hlayout.addStretch(1)

        layout.addLayout(hlayout)

        # Add a spacer for some distance between the QLineEdit and QPushButton
        spacer = QtWidgets.QSpacerItem(0, 10, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        layout.addItem(spacer)

        # Submit Button
        self.submit_button = QtWidgets.QPushButton('Submit')
        self.submit_button.setFixedWidth(100)  # Making the button shorter
        self.submit_button.clicked.connect(self.submit_sample)
        layout.addWidget(self.submit_button, alignment=QtCore.Qt.AlignCenter)

        self.setLayout(layout)
        self.setMinimumWidth(400)

    def truncate_filename(self, filename, max_length):
        if len(filename) > max_length:
            return filename[:max_length - 3] + "..."
        return filename

    def browse_for_sample(self):
        # Show a File Dialog and get the selected file's path
        sample_path = QtWidgets.QFileDialog.getOpenFileName(self, 'Select Sample')[0]
        if sample_path:
            self.sample_path_field.setText(sample_path)

    def submit_sample(self):
        if os.path.exists(self.sample_path):
            # Assuming RE_analysis takes the file path as an argument
            result = reait_api.RE_analyse(self.sample_path, "binnet-0.1")
            # Check the type of the result and format accordingly
            if isinstance(result, str):
                message = result
            elif isinstance(result, requests.Response):
                if result.status_code == 200:
                    message = "[+] Successfully submitted binary for analysis."
                else:
                    # Handle other status codes or extract more information from the response if needed
                    message = f"[-] Error: {result.text}"
            else:
                # Format other types of results, if any.
                # For this example, if the result is a dictionary, convert it to a readable string.
                message = '\n'.join(f"{k}: {v}" for k, v in result.items())

            # Show the result in a message box
            msg_box = QtWidgets.QMessageBox()
            msg_box.setWindowTitle("Submit Result")
            msg_box.setText(message)
            msg_box.exec_()
        else:
            QtWidgets.QMessageBox.warning(self, 'Error', 'Invalid file path.')


class LoginDialog(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("RevEng.AI for IDA Pro")  # Set window title

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
        title_label = QtWidgets.QLabel('Input Your User Info')
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
        home_path = os.path.expanduser("~")
        file_path = os.path.join(home_path, '.reait.toml')

        # Writing to the file
        with open(file_path, 'w') as file:
            file.write(f'apikey = "{api_key}"\n')
            file.write('host = "https://api.reveng.ai"\n')
            file.write(f'model = "{model_name}"\n')

        print(f'User Info Saved: API Key - {api_key}, Model Name - {model_name}')

        self.accept()

        sample_submit_dialog = SampleSubmitDialog()
        sample_submit_dialog.exec_()


    def on_api_key_help_click(self):
        webbrowser.open('https://portal.reveng.ai')


class LoginPlugin(idaapi.plugin_t):
    flags = 0  # Do not use PLUGIN_FIX
    comment = ("This is a RevEng.AI plugin")
    help = "Please go to help.reveng.ai for more information"
    wanted_name = "RevEng.AI for IDA Pro"
    wanted_hotkey = "Ctrl-Shift-A"

    def init(self):
        # This is executed when the plugin is loaded
        return idaapi.PLUGIN_OK

    def run(self, arg):
        # This method can be called if you register a hotkey or menu item.
        # Here, we'll just re-show the login dialog.
        self.show_login_dialog()

    def term(self):
        # Called when the plugin is unloaded
        pass

    def show_login_dialog(self):
        home_path = os.path.expanduser("~")
        config_file_path = os.path.join(home_path, '.reait.toml')
        if os.path.exists(config_file_path):
            # If the config file exists, show the SampleSubmitDialog
            dialog = SampleSubmitDialog()
        else:
            # Otherwise, show the LoginDialog
            dialog = LoginDialog()
        dialog.exec_()  # This will block until the dialog is closed


def PLUGIN_ENTRY():
    return LoginPlugin()
