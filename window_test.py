from idaapi import PluginForm
from PyQt5 import QtGui, QtCore


class MyPluginFormClass(PluginForm):
    def OnCreate(self, form):
        """
        Called when the plugin form is created
        """
        # Get parent widget
        self.parent = self.FormToPySideWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        # Create layout
        layout = QtGui.QVBoxLayout()
        layout.addWidget(
            QtGui.QLabel("Hello from <font color=red>PySide</font>"))
        layout.addWidget(
            QtGui.QLabel("Hello from <font color=blue>IDAPython</font»"))
        self.parent.setLayout(layout)

    def OnClose(self, form):
        """
        Called when the plugin form is closed
        """
        pass


plg = MyPluginFormClass()
plg.Show("PySide hello world")