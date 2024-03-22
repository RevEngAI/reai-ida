import idaapi
from typing import Union, Dict
from PyQt5 import QtCore, QtGui, QtWidgets
from revengai.logger import plugin_logger
from revengai.model import Model


class MainForm(idaapi.PluginForm):
    """
    This is the main class that implements the main GUI component that consists of the
    plugin. It contains the various views that uses can use to do various things within
    the plugin.


    The main views are as follows, more may be added in the future:
    - Configuration - Configure the settings of the plugin api key, host etc
    - Uploads - Shows the user the status of uploaded files from the current session
    - About - Shows the user some information about the version of the plugin
    """

    def __init__(self, views: Dict, config) -> None:
        super(MainForm, self).__init__()
        self.parent = None
        self.configuration_views = views
        self.configuration = config

    def OnCreate(self, form) -> None:
        """
        Called on widget creation
        """
        plugin_logger.debug("plugin form OnCreate called()")
        self.form = form
        self.parent = self.FormToPyQtWidget(form)

        # add a property to all views so they can reference the parent widget
        # while it is visible
        for k, v in self.configuration_views.items():
            v._parent = self.parent

        self._populate_model()
        self.PopulateForm()

    def _populate_model(self):
        plugin_logger.debug(f"{self._populate_model.__name__}()")

        self.ui = {
            "Configuration": self.configuration_views["Configuration"].view,
            "About": self.configuration_views["About"].view,
            "Uploads": self.configuration_views["Upload"].view,
        }

        # pass the model to customised abstract class
        self.views = ["About", "Configuration", "Uploads"]
        self.views_model = Model.Base(["Views"], self.views)

    def PopulateForm(self):
        """
        Create layout for the form
        """
        plugin_logger.debug("plugin populate form called")

        list_view = QtWidgets.QListView()
        list_view.setFixedWidth(115)
        list_view.setModel(self.views_model)

        # selection list
        select = QtCore.QItemSelectionModel.Select
        list_view.selectionModel().select(
            self.views_model.createIndex(1, 0), select
        )  # ???
        list_view.clicked.connect(self.view_clicked)

        # split left/right
        self.splitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)
        self.splitter.addWidget(list_view)  # left
        self.splitter.addWidget(
            self.configuration_views["Configuration"].view()
        )  # opens on the about view initially
        self.splitter.setChildrenCollapsible(False)
        self.splitter.show()

        # set splitter inside a HBox layout
        outer = QtWidgets.QHBoxLayout()
        outer.addWidget(self.splitter)

        # add to parent
        self.parent.setLayout(outer)

    def OnClose(self, form):
        # remove the parent widget once the form has gone from the view classes
        # as the form widget doesn't exist anymore
        for k, v in self.configuration_views.items():
            v._parent = None
        plugin_logger.debug(f"{self.OnClose.__name__}()")
        self.configuration.persistConfig()

    def view_clicked(self, idx):
        """
        Callback to deal with item selection on the menu
        """
        k = self.views_model.data(idx)
        if k in self.ui:
            # setup new view
            widget = self.ui[k]()  # Returns a QGroupBox, top-level widget
            if not widget:
                widget = QtWidgets.QGroupBox("Error")
            # remove old view to the splitter
            old_widget = self.splitter.widget(1)
            if old_widget:
                old_widget.hide()
                old_widget.deleteLater()
            self.splitter.insertWidget(1, widget)
        else:
            plugin_logger.debug("item not found in model")
