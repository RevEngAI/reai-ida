# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'function_simularity_panel.ui'
#
# Created by: PyQt5 UI code generator 5.15.10
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_FunctionSimularityPanel(object):
    def setupUi(self, FunctionSimularityPanel):
        FunctionSimularityPanel.setObjectName("FunctionSimularityPanel")
        FunctionSimularityPanel.resize(800, 400)
        FunctionSimularityPanel.setContextMenuPolicy(QtCore.Qt.NoContextMenu)
        FunctionSimularityPanel.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.gridLayout_5 = QtWidgets.QGridLayout(FunctionSimularityPanel)
        self.gridLayout_5.setSizeConstraint(QtWidgets.QLayout.SetDefaultConstraint)
        self.gridLayout_5.setContentsMargins(8, 8, 8, 8)
        self.gridLayout_5.setHorizontalSpacing(8)
        self.gridLayout_5.setObjectName("gridLayout_5")
        self.groupBox = QtWidgets.QGroupBox(FunctionSimularityPanel)
        self.groupBox.setObjectName("groupBox")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.groupBox)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        spacerItem = QtWidgets.QSpacerItem(0, 0, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_6.addItem(spacerItem)
        self.checkBox = QtWidgets.QCheckBox(self.groupBox)
        self.checkBox.setChecked(False)
        self.checkBox.setObjectName("checkBox")
        self.horizontalLayout_6.addWidget(self.checkBox)
        spacerItem1 = QtWidgets.QSpacerItem(0, 0, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_6.addItem(spacerItem1)
        self.verticalLayout.addLayout(self.horizontalLayout_6)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        spacerItem2 = QtWidgets.QSpacerItem(0, 0, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem2)
        self.label_2 = QtWidgets.QLabel(self.groupBox)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_3.addWidget(self.label_2)
        self.lineEdit = QtWidgets.QLineEdit(self.groupBox)
        self.lineEdit.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.lineEdit.setObjectName("lineEdit")
        self.horizontalLayout_3.addWidget(self.lineEdit)
        spacerItem3 = QtWidgets.QSpacerItem(4, 0, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem3)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        spacerItem4 = QtWidgets.QSpacerItem(0, 0, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem4)
        self.progressBar = QtWidgets.QProgressBar(self.groupBox)
        self.progressBar.setEnabled(True)
        self.progressBar.setProperty("value", 0)
        self.progressBar.setAlignment(QtCore.Qt.AlignCenter)
        self.progressBar.setTextVisible(False)
        self.progressBar.setObjectName("progressBar")
        self.verticalLayout.addWidget(self.progressBar)
        spacerItem5 = QtWidgets.QSpacerItem(0, 0, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem5)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem6 = QtWidgets.QSpacerItem(0, 0, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem6)
        self.renameButton = QtWidgets.QPushButton(self.groupBox)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.renameButton.sizePolicy().hasHeightForWidth())
        self.renameButton.setSizePolicy(sizePolicy)
        self.renameButton.setAutoFillBackground(False)
        self.renameButton.setAutoDefault(True)
        self.renameButton.setObjectName("renameButton")
        self.horizontalLayout.addWidget(self.renameButton)
        spacerItem7 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem7)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        spacerItem8 = QtWidgets.QSpacerItem(0, 0, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem8)
        self.fetchButton = QtWidgets.QPushButton(self.groupBox)
        self.fetchButton.setEnabled(False)
        self.fetchButton.setObjectName("fetchButton")
        self.horizontalLayout_2.addWidget(self.fetchButton)
        spacerItem9 = QtWidgets.QSpacerItem(0, 0, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem9)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.gridLayout_5.addWidget(self.groupBox, 0, 0, 1, 1)
        self.tableView = QtWidgets.QTableView(FunctionSimularityPanel)
        self.tableView.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tableView.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.tableView.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tableView.setShowGrid(True)
        self.tableView.setGridStyle(QtCore.Qt.SolidLine)
        self.tableView.setSortingEnabled(False)
        self.tableView.setWordWrap(True)
        self.tableView.setCornerButtonEnabled(False)
        self.tableView.setObjectName("tableView")
        self.tableView.horizontalHeader().setHighlightSections(False)
        self.tableView.horizontalHeader().setStretchLastSection(True)
        self.tableView.verticalHeader().setVisible(False)
        self.tableView.verticalHeader().setHighlightSections(False)
        self.gridLayout_5.addWidget(self.tableView, 0, 1, 1, 1)
        self.gridLayout_5.setColumnStretch(1, 1)

        self.retranslateUi(FunctionSimularityPanel)
        QtCore.QMetaObject.connectSlotsByName(FunctionSimularityPanel)

    def retranslateUi(self, FunctionSimularityPanel):
        _translate = QtCore.QCoreApplication.translate
        FunctionSimularityPanel.setWindowTitle(_translate("FunctionSimularityPanel", "RevEng.AI Toolkit: Function Rename"))
        self.groupBox.setTitle(_translate("RenameSymbolsPanel", "Symbol Options"))
        self.checkBox.setText(_translate("RenameSymbolsPanel", "Use Debug Symbol"))
        self.label_2.setText(_translate("RenameSymbolsPanel", "Results"))
        self.lineEdit.setText(_translate("RenameSymbolsPanel", "5"))
        self.renameButton.setText(_translate("RenameSymbolsPanel", "Rename"))
        self.fetchButton.setText(_translate("RenameSymbolsPanel", "Fetch Results"))