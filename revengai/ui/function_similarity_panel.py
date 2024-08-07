# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'function_similarity_panel.ui'
#
# Created by: PyQt5 UI code generator 5.15.10
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets

from revengai.gui.custom_flow_layout import CustomFlowLayout
from revengai.gui.slider import Slider


class Ui_FunctionSimilarityPanel(object):
    def setupUi(self, FunctionSimilarityPanel):
        FunctionSimilarityPanel.setObjectName("FunctionSimilarityPanel")
        FunctionSimilarityPanel.resize(800, 600)
        FunctionSimilarityPanel.setContextMenuPolicy(QtCore.Qt.NoContextMenu)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("../resources/favicon.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        FunctionSimilarityPanel.setWindowIcon(icon)
        FunctionSimilarityPanel.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.verticalLayout = QtWidgets.QVBoxLayout(FunctionSimilarityPanel)
        self.verticalLayout.setSizeConstraint(QtWidgets.QLayout.SetDefaultConstraint)
        self.verticalLayout.setContentsMargins(8, 10, 8, 8)
        self.verticalLayout.setObjectName("verticalLayout")
        self.tabWidget = QtWidgets.QTabWidget(FunctionSimilarityPanel)
        self.tabWidget.setTabBarAutoHide(False)
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.vboxlayout = QtWidgets.QVBoxLayout(self.tab)
        self.vboxlayout.setSizeConstraint(QtWidgets.QLayout.SetDefaultConstraint)
        self.vboxlayout.setContentsMargins(2, 2, 2, 2)
        self.vboxlayout.setSpacing(4)
        self.vboxlayout.setObjectName("vboxlayout")
        self.central_widget = QtWidgets.QWidget()
        self.layoutFilter = CustomFlowLayout(parent=self.central_widget)
        self.layoutFilter.setObjectName("layoutFilter")
        self.central_widget.setLayout(self.layoutFilter)
        self.vboxlayout.addWidget(self.central_widget)
        self.collectionsFilter = QtWidgets.QLineEdit(self.tab)
        self.collectionsFilter.setClearButtonEnabled(True)
        self.collectionsFilter.setObjectName("collectionsFilter")
        self.vboxlayout.addWidget(self.collectionsFilter)
        self.collectionsTable = QtWidgets.QTableView(self.tab)
        self.collectionsTable.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.collectionsTable.setContextMenuPolicy(QtCore.Qt.NoContextMenu)
        self.collectionsTable.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.collectionsTable.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.collectionsTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.collectionsTable.setShowGrid(True)
        self.collectionsTable.setGridStyle(QtCore.Qt.SolidLine)
        self.collectionsTable.setSortingEnabled(False)
        self.collectionsTable.setWordWrap(False)
        self.collectionsTable.setCornerButtonEnabled(False)
        self.collectionsTable.setObjectName("collectionsTable")
        self.collectionsTable.horizontalHeader().setHighlightSections(False)
        self.collectionsTable.horizontalHeader().setMinimumSectionSize(20)
        self.collectionsTable.horizontalHeader().setStretchLastSection(True)
        self.collectionsTable.verticalHeader().setVisible(False)
        self.collectionsTable.verticalHeader().setHighlightSections(False)
        self.collectionsTable.verticalHeader().setMinimumSectionSize(20)
        self.vboxlayout.addWidget(self.collectionsTable)
        self.hboxlayout = QtWidgets.QHBoxLayout()
        self.hboxlayout.setObjectName("hboxlayout")
        self.checkBox = QtWidgets.QCheckBox(self.tab)
        self.checkBox.setObjectName("checkBox")
        self.hboxlayout.addWidget(self.checkBox)
        spacerItem = QtWidgets.QSpacerItem(400, 10, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.hboxlayout.addItem(spacerItem)
        self.label_2 = QtWidgets.QLabel(self.tab)
        self.label_2.setTextFormat(QtCore.Qt.PlainText)
        self.label_2.setAlignment(QtCore.Qt.AlignCenter)
        self.label_2.setIndent(0)
        self.label_2.setObjectName("label_2")
        self.hboxlayout.addWidget(self.label_2)
        self.lineEdit = QtWidgets.QLineEdit(self.tab)
        self.lineEdit.setAlignment(QtCore.Qt.AlignCenter|QtCore.Qt.AlignHCenter|QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.lineEdit.setClearButtonEnabled(True)
        self.lineEdit.setObjectName("lineEdit")
        self.hboxlayout.addWidget(self.lineEdit)
        self.vboxlayout.addLayout(self.hboxlayout)
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.vboxlayout1 = QtWidgets.QVBoxLayout(self.tab_2)
        self.vboxlayout1.setSizeConstraint(QtWidgets.QLayout.SetDefaultConstraint)
        self.vboxlayout1.setContentsMargins(2, 2, 2, 2)
        self.vboxlayout1.setSpacing(4)
        self.vboxlayout1.setObjectName("vboxlayout1")
        self.resultsTable = QtWidgets.QTableView(self.tab_2)
        self.resultsTable.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.resultsTable.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.resultsTable.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.resultsTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.resultsTable.setShowGrid(True)
        self.resultsTable.setGridStyle(QtCore.Qt.SolidLine)
        self.resultsTable.setSortingEnabled(False)
        self.resultsTable.setWordWrap(False)
        self.resultsTable.setCornerButtonEnabled(False)
        self.resultsTable.setObjectName("resultsTable")
        self.resultsTable.horizontalHeader().setHighlightSections(False)
        self.resultsTable.horizontalHeader().setMinimumSectionSize(20)
        self.resultsTable.horizontalHeader().setStretchLastSection(True)
        self.resultsTable.verticalHeader().setVisible(False)
        self.resultsTable.verticalHeader().setHighlightSections(False)
        self.resultsTable.verticalHeader().setMinimumSectionSize(20)
        self.vboxlayout1.addWidget(self.resultsTable)
        self.tabWidget.addTab(self.tab_2, "")
        self.verticalLayout.addWidget(self.tabWidget)
        self.description = QtWidgets.QLabel(FunctionSimilarityPanel)
        self.description.setTextFormat(QtCore.Qt.RichText)
        self.description.setAlignment(QtCore.Qt.AlignCenter)
        self.description.setWordWrap(True)
        self.description.setObjectName("description")
        self.verticalLayout.addWidget(self.description)
        self.confidenceSlider = Slider(FunctionSimilarityPanel)
        self.confidenceSlider.setMaximum(100)
        self.confidenceSlider.setPageStep(5)
        self.confidenceSlider.setSliderPosition(90)
        self.confidenceSlider.setOrientation(QtCore.Qt.Horizontal)
        self.confidenceSlider.setInvertedAppearance(False)
        self.confidenceSlider.setInvertedControls(False)
        self.confidenceSlider.setTickPosition(QtWidgets.QSlider.TicksBothSides)
        self.confidenceSlider.setTickInterval(5)
        self.confidenceSlider.setObjectName("confidenceSlider")
        self.verticalLayout.addWidget(self.confidenceSlider)
        self.progressBar = QtWidgets.QProgressBar(FunctionSimilarityPanel)
        self.progressBar.setProperty("value", 0)
        self.progressBar.setAlignment(QtCore.Qt.AlignCenter)
        self.progressBar.setInvertedAppearance(False)
        self.progressBar.setObjectName("progressBar")
        self.verticalLayout.addWidget(self.progressBar)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem1)
        self.fetchButton = QtWidgets.QPushButton(FunctionSimilarityPanel)
        self.fetchButton.setObjectName("fetchButton")
        self.horizontalLayout.addWidget(self.fetchButton)
        self.renameButton = QtWidgets.QPushButton(FunctionSimilarityPanel)
        self.renameButton.setEnabled(False)
        self.renameButton.setObjectName("renameButton")
        self.horizontalLayout.addWidget(self.renameButton)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(FunctionSimilarityPanel)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(FunctionSimilarityPanel)

    def retranslateUi(self, FunctionSimilarityPanel):
        _translate = QtCore.QCoreApplication.translate
        FunctionSimilarityPanel.setWindowTitle(_translate("FunctionSimilarityPanel", "RevEng.AI Toolkit: Function Rename"))
        self.collectionsFilter.setPlaceholderText(_translate("FunctionSimilarityPanel", "Search collections…"))
        self.checkBox.setText(_translate("FunctionSimilarityPanel", "Use Debug Symbols"))
        self.label_2.setText(_translate("FunctionSimilarityPanel", "Results:"))
        self.lineEdit.setText(_translate("FunctionSimilarityPanel", "5"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("FunctionSimilarityPanel", "Collections"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("FunctionSimilarityPanel", "Results"))
        self.fetchButton.setText(_translate("FunctionSimilarityPanel", "Fetch Results"))
        self.renameButton.setText(_translate("FunctionSimilarityPanel", "Rename"))
