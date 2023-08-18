import json
import os
from PyQt5 import QtWidgets, QtGui, QtCore
import idaapi
import urllib.request
import webbrowser
import requests
from reait import api as reait_api

logo_url = 'https://portal.reveng.ai/_next/image?url=%2Ficon.png&w=64&q=75'
download_button_url = 'https://portal.reveng.ai/_next/image?url=%2Ficon.png&w=64&q=75'


# show company logo
def company_logo(layout, url: str, window_title: str):
    # Logo
    logo_url = url
    data = urllib.request.urlopen(logo_url).read()
    pixmap = QtGui.QPixmap()
    pixmap.loadFromData(data)
    logo_label = QtWidgets.QLabel()
    logo_label.setPixmap(pixmap)
    logo_label.setAlignment(QtCore.Qt.AlignCenter)  # Center the logo
    layout.addWidget(logo_label)

    # Title
    title_label = QtWidgets.QLabel(window_title)
    font = title_label.font()
    font.setBold(True)  # Set font to bold
    title_label.setFont(font)
    title_label.setAlignment(QtCore.Qt.AlignCenter)  # Center the title
    layout.addWidget(title_label)

    return layout


# user key and model-name configure page
class LoginDialog(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("RevEng.AI for IDA Pro")  # Set window title

        layout = QtWidgets.QVBoxLayout()
        layout = company_logo(layout, logo_url, 'Input Your User Info')

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


# sample submit page and result re-fetch
class SampleSubmitDialog(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.is_submit_mode = True

        self.bin_dialog = None
        self.setWindowTitle("RevEng.AI for IDA Pro")

        layout = QtWidgets.QVBoxLayout()
        layout = company_logo(layout, logo_url, "Submit Sample for Analysis")

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

        self.model_name = "binnet-0.1"

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

    def on_msg_box_closed(self):
        self.bin_dialog = BinStatusDialog(self.sample_path, self.model_name, self)
        self.bin_dialog.exec_()

    def submit_sample(self):
        if self.is_submit_mode:
            if os.path.exists(self.sample_path):
                result = reait_api.RE_analyse(self.sample_path, self.model_name)

                # Check the type of the result and format accordingly
                if result.status_code == 200:
                    message = "[+] Success: Successfully submitted the binary for analysis."
                elif result.status_code == 400:
                    response = json.loads(result.text)
                    if 'error' in response.keys():
                        # Handle other status codes or extract more information from the response if needed
                        if 'The specified Hash-Model combination already exists' in response['error']:
                            message = (f"[+] Task Exists: The specified Hash-Model "
                                       f"combination already exists, \ntry to fetch result for you now")
                        else:
                            message = f"[-] Error {response['error']}"
                else:
                    # Format other types of results, if any.
                    # For this example, if the result is a dictionary, convert it to a readable string.
                    message = result.status_code

                self.close()
                # Show the result in a message box
                msg_box = QtWidgets.QMessageBox()
                msg_box.setWindowTitle("Submit Result")
                msg_box.setText(message)
                msg_box.accepted.connect(self.on_msg_box_closed)
                msg_box.exec_()
            else:
                self.close()
                QtWidgets.QMessageBox.warning(self, 'Error', 'Invalid file path.')
        else:
            # The user wants to fetch the result
            bin_status_dialog = BinStatusDialog(self.sample_path, self.model_name, self)
            bin_status_dialog.exec_()

    # if submitted, no more submit but only fetch result
    def set_to_fetch_again(self):
        self.is_submit_mode = False
        self.submit_button.disconnect()  # Disconnect all connections
        self.submit_button.setText("Fetch Again")
        self.submit_button.clicked.connect(self.fetch_again)

    def fetch_again(self):
        # Open the BinStatusDialog when the "Fetch Again" button is clicked
        bin_status_dialog = BinStatusDialog(self.sample_path, self.model_name, self)
        bin_status_dialog.exec_()


# used for checking analysis result
class BinStatusDialog(QtWidgets.QDialog):
    def __init__(self, fpath, model_name, sample_submit_dialog):
        super().__init__()

        self.sample_submit_dialog = sample_submit_dialog

        # Close the SampleSubmitDialog right when BinStatusDialog is opened
        if self.sample_submit_dialog:
            self.sample_submit_dialog.close()

        self.fpath = fpath
        self.model_name = model_name

        self.setWindowTitle("RevEng.AI for IDA Pro")

        self.layout = QtWidgets.QVBoxLayout()
        self.status_label = QtWidgets.QLabel("Checking Embeddings Status...")
        self.layout.addWidget(self.status_label)

        # List Widget to display embeddings (initially hidden)
        self.embeddings_list = QtWidgets.QListWidget()
        self.embeddings_list.setVisible(False)  # Hide it initially
        self.layout.addWidget(self.embeddings_list)

        self.setMinimumWidth(400)
        self.setLayout(self.layout)

        # Timer setup
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.check_status)
        self.timer.start(1000)  # Call check_status every 1 seconds

        # self.counter = 0

    def check_status(self):
        try:
            res_json = reait_api.RE_embeddings(self.fpath, self.model_name)

            self.timer.stop()
            self.status_label.setText("Analysis successfully fetched!")
            self.close()

            # Populate the list widget
            embeddings_dialog = EmbeddingsTableDialog(res_json, os.path.basename(self.fpath))
            embeddings_dialog.exec_()

        except requests.exceptions.HTTPError:
            # self.counter += 1
            # if self.counter > 3:
            self.status_label.setText("Error fetching result. Please try again later.")
            self.timer.stop()
            QtCore.QTimer.singleShot(3000, self.on_error_after_few_tries)

    def on_error_after_few_tries(self):
        self.close()  # Close the current dialog
        if self.sample_submit_dialog is not None:
            # self.counter = 0
            self.sample_submit_dialog.set_to_fetch_again()  # Change the button text of SampleSubmitDialog
            self.sample_submit_dialog.show()  # Show the SampleSubmitDialog again


class BaseTableDialog(QtWidgets.QDialog):
    def __init__(self, data_json, title, column_headers, column_keys, column_ratios=None, download_flag=False):
        super().__init__()

        self.setWindowTitle("RevEng.AI for IDA Pro")

        layout = QtWidgets.QVBoxLayout()
        layout = company_logo(layout, logo_url, title)

        self.table = QtWidgets.QTableWidget(self)
        self.table.setColumnCount(len(column_headers) + 1)  # +1 for the download button
        if download_flag:
            self.table.setHorizontalHeaderLabels(column_headers + ["Download"])
            column_keys = column_keys+["download"]

        for row_index, row_data in enumerate(data_json):
            self.table.insertRow(row_index)
            for col_index, cell_key in enumerate(column_keys):
                if cell_key != "download":
                    value = str(row_data[cell_key])
                    if cell_key == "vaddr":
                        value = hex(row_data[cell_key])
                    if cell_key == "size":
                        value = value + ' bytes'
                    item = QtWidgets.QTableWidgetItem(value)
                    item.setFlags(QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled)
                    if cell_key == "vaddr":
                        item.setTextAlignment(QtCore.Qt.AlignCenter)
                    self.table.setItem(row_index, col_index, item)
                else:
                    # Add a Download button to the last column
                    btn = QtWidgets.QPushButton("RE.AI Signature ⬇️")  # Using a Unicode arrow as a placeholder.
                    btn.setStyleSheet("""
                        QPushButton {
                            color: #1E88E5; /* Doodle Blue */
                            background-color: transparent;
                            border: none;
                            /* font-weight: bold; */
                            text-align: center;
                            padding-left: 5px;
                        }
                        QPushButton:hover {
                            color: #0E77D5; /* A shade darker for hover effect */
                        }
                        QPushButton:pressed {
                            color: #0A6CB5; /* Another shade darker for pressed effect */
                        }
                    """)

                    # Connect the button to a function if you wish
                    # print(f"Connecting button for row: {row_index}")
                    # btn.clicked.connect(lambda checked, row=row_index: self.download_signature(row, len(column_headers)))

                    self.table.setCellWidget(row_index, col_index, btn)

        self.table.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)

        header = self.table.horizontalHeader()
        for i, mode in enumerate(column_ratios or []):
            header.setSectionResizeMode(i, QtWidgets.QHeaderView.Interactive)
            header.resizeSection(i, mode)

        layout.addWidget(self.table)
        self.setLayout(layout)
        self.setMinimumWidth(800)
        self.setMinimumHeight(600)


class EmbeddingsTableDialog(BaseTableDialog):
    def __init__(self, res_json, filename):
        super().__init__(
            data_json=res_json,
            title=f"Analyse Result of binary {filename}",
            column_headers=["Functions", "Size", "Vaddr"],
            column_keys=["name", "size", "vaddr"],
            column_ratios=[300, 100, 150],
            download_flag=True
        )

        self.res_json = res_json

        for row_index in range(self.table.rowCount()):
            # Assuming the download button is in the last column
            btn = self.table.cellWidget(row_index, self.table.columnCount() - 1)
            if btn:
                btn.clicked.connect(lambda checked, row=row_index:
                                    self.save_json(self.res_json[row]))

        self.model_name = 'binnet-0.1'
        self.nns = 15
        self.add_context_menu(self.show_context_menu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)

    def show_context_menu(self, position):
        menu = QtWidgets.QMenu(self)
        search_action = menu.addAction("Search similar functions")
        show_action = menu.addAction("Show function embedding")

        action = menu.exec_(self.table.mapToGlobal(position))

        if action == show_action:
            self._handle_show_embedding()

        if action == search_action:
            self._handle_search_similar()

    def add_context_menu(self, callback):
        self.table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(callback)

    def _handle_show_embedding(self):
        row = self.table.currentRow()
        embedding = self.res_json[row]['embedding']  # assuming the embedding is in column 3
        func = self.res_json[row]['name']  # assuming the function name is in column 0
        if embedding:
            msgBox = ScrollableMessageBox(f"{func}'s embedding", str(embedding))
            msgBox.exec_()

    def _handle_search_similar(self):
        row = self.table.currentRow()
        embedding = self.res_json[row]['embedding']
        if embedding:
            nn_symbols = reait_api.RE_nearest_symbols(embedding, self.model_name, self.nns)
            symbolsDialog = NearestSymbolsDialog(nn_symbols)
            symbolsDialog.exec_()

    def save_json(self, data):
        # Determine the user's Downloads directory path
        downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')

        # Check if the Downloads directory exists, if not create one (this step might not be necessary in most cases)
        if not os.path.exists(downloads_path):
            os.makedirs(downloads_path)

        # Construct the initial file path
        base_filename = f'{data["name"]}.json'
        file_path = os.path.join(downloads_path, base_filename)

        # Modify the filename to avoid overwriting if it exists
        counter = 1
        while os.path.exists(file_path):
            # Split the base filename into name and extension
            name, ext = os.path.splitext(base_filename)
            file_path = os.path.join(downloads_path, f'{name} ({counter}){ext}')
            counter += 1

        # Save the JSON data to the file
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)

        # Notify the user or perform any other action you want
        print(f"Data saved to: {file_path}")


class NearestSymbolsDialog(BaseTableDialog):
    def __init__(self, symbols_json):
        super().__init__(
            data_json=symbols_json,
            title="Similar functions in our database",
            column_headers=["Filename", "Function Name", "Sha-256", "Distance"],
            column_keys=["binary_name", "name", "sha_256_hash", "distance"],
            column_ratios=[100, 100, 200, 170],
            download_flag=True
        )


class ScrollableMessageBox(QtWidgets.QDialog):

    def __init__(self, title, msg, parent=None):
        super(ScrollableMessageBox, self).__init__(parent)

        self.setWindowTitle(title)
        self.setMinimumSize(400, 400)

        # Setting up the scroll area
        scroll = QtWidgets.QScrollArea(self)
        scroll.setWidgetResizable(True)

        # Label to hold the text
        self.content = QtWidgets.QLabel(scroll)
        self.content.setText(msg)
        self.content.setWordWrap(True)
        self.content.setAlignment(QtCore.Qt.AlignTop)
        scroll.setWidget(self.content)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(scroll)


class REAI_Plugin(idaapi.plugin_t):
    flags = 0  # Do not use PLUGIN_FIX
    comment = "This is a RevEng.AI plugin"
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
        if not os.path.exists(config_file_path):
            # show the LoginDialog
            dialog = LoginDialog()
        else:
            # Otherwise, if the config file exists, show the SampleSubmitDialog
            dialog = SampleSubmitDialog()
        dialog.exec_()  # This will block until the dialog is closed


def PLUGIN_ENTRY():
    return REAI_Plugin()
