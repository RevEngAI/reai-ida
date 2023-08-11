import sys
from PyQt5 import QtWidgets


class LoginWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        layout = QtWidgets.QVBoxLayout()

        # Username Field
        self.username_label = QtWidgets.QLabel('API Key:')
        self.username_field = QtWidgets.QLineEdit()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_field)

        # Password Field
        self.password_label = QtWidgets.QLabel('Model Name:')
        self.password_field = QtWidgets.QLineEdit()
        self.password_field.setEchoMode(QtWidgets.QLineEdit.Password)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_field)

        # Login Button
        self.login_button = QtWidgets.QPushButton('Save')
        self.login_button.clicked.connect(self.on_login_click)
        layout.addWidget(self.login_button)

        self.setLayout(layout)

    def on_login_click(self):
        username = self.username_field.text()
        password = self.password_field.text()

        # Here you would typically authenticate the user using the provided
        # username and password.
        print(f'User Info Saved: {username}, {password}')


app = QtWidgets.QApplication(sys.argv)
window = LoginWindow()
window.show()
sys.exit(app.exec_())
