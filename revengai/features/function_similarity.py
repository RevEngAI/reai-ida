# -*- coding: utf-8 -*-
import logging

import idc
from PyQt5.QtWidgets import QMenu
from idaapi import ASKBTN_YES, hide_wait_box, show_wait_box

from PyQt5.QtCore import Qt, QModelIndex
from PyQt5.QtGui import QIntValidator, QCursor

from requests import Response, HTTPError, RequestException

from reait.api import RE_nearest_symbols_batch

from revengai.api import RE_collection_search
from revengai.features import BaseDialog
from revengai.gui.dialog import Dialog
from revengai.manager import RevEngState
from revengai.misc.utils import IDAUtils
from revengai.misc.qtutils import inthread, inmain
from revengai.models import CheckableItem, IconItem, SimpleItem
from revengai.models.checkable_model import RevEngCheckableTableModel
from revengai.models.table_model import RevEngTableModel
from revengai.ui.function_similarity_panel import Ui_FunctionSimilarityPanel


logger = logging.getLogger("REAI")


class FunctionSimilarityDialog(BaseDialog):
    def __init__(self, state: RevEngState, fpath: str):
        BaseDialog.__init__(self, state, fpath)

        start_addr = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)

        if start_addr is not idc.BADADDR:
            self.v_addr = start_addr - self.base_addr
        else:
            logger.error("Pointer location not in valid function")
            Dialog.showError("Find Similar Functions", "Cursor position not in a function.")

        self.ui = Ui_FunctionSimilarityPanel()
        self.ui.setupUi(self)

        self.ui.renameButton.setEnabled(False)

        self.ui.lineEdit.setValidator(QIntValidator(1, 256, self))

        self.ui.layoutFilter.register_cb(self._callback)

        self.ui.collectionsFilter.textChanged.connect(self._filter)
        self.ui.collectionsTable.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        self.ui.collectionsTable.setModel(RevEngCheckableTableModel(data=[], columns=[1], parent=self,
                                                                    header=["Collection Name", "Include",]))

        self.ui.collectionsTable.model().dataChanged.connect(self._state_change)

        self.ui.resultsTable.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        self.ui.resultsTable.setModel(RevEngTableModel(data=[], parent=self,
                                                       header=["Function Name", "Confidence", "Source File",]))

        self.ui.resultsTable.customContextMenuRequested.connect(self._table_menu)

        self.ui.confidenceSlider.valueChanged.connect(self._confidence)

        self.ui.fetchButton.setFocus()
        self.ui.fetchButton.clicked.connect(self._fetch)
        self.ui.renameButton.clicked.connect(self._rename_symbol)

        self._confidence(self.ui.confidenceSlider.sliderPosition())

    def showEvent(self, event):
        super(FunctionSimilarityDialog, self).showEvent(event)

        inthread(self._search_collection)

    def closeEvent(self, event):
        super(FunctionSimilarityDialog, self).closeEvent(event)

    def _fetch(self):
        if self.v_addr != idc.BADADDR:
            inthread(self._load,
                     self._selected_collections(),
                     (100 - int(self.ui.confidenceSlider.property("value"))) / 100)

    def _load(self, collections: list[str], distance: float = 0.1):
        try:
            model = inmain(self.ui.resultsTable.model)

            inmain(model.fill_table, [])
            inmain(self.ui.fetchButton.setEnabled, False)
            inmain(self.ui.renameButton.setEnabled, False)
            inmain(self.ui.progressBar.setProperty, "value", 25)
            inmain(show_wait_box, "HIDECANCEL\nGetting results…")

            if not self.analyzed_functions or len(self.analyzed_functions) == 0:
                self._get_analyze_functions()

            function_id = self.analyzed_functions.get(self.v_addr, None)

            if function_id is None:
                func_name = inmain(IDAUtils.get_demangled_func_name, self.v_addr + self.base_addr)

                inmain(idc.warning, f"No matches found for {func_name}.")
                logger.error("No similar functions found for: %s", func_name)
                return

            inmain(self.ui.progressBar.setProperty, "value", 50)

            nb_results = inmain(self.ui.lineEdit.text)

            res = RE_nearest_symbols_batch(function_ids=[function_id,],
                                           nns=int(nb_results) if nb_results else 1,
                                           distance=distance, collections=collections,
                                           debug_enabled=inmain(self.ui.checkBox.isChecked))

            inmain(self.ui.progressBar.setProperty, "value", 75)

            data = []
            for function in res.json()["function_matches"]:
                data.append((SimpleItem(function["nearest_neighbor_function_name"], function),
                             f"{float(str(function['confidence'])[:6]) * 100:#.02f}%",
                             function["nearest_neighbor_binary_name"],))

            inmain(model.fill_table, data)
            inmain(self.ui.renameButton.setEnabled, len(data) > 0)

            if len(data) == 0:
                inmain(idc.warning, "No matches found. Try a different confidence value.")
                logger.error("No similar functions found for: %s with confidence: %d",
                             inmain(IDAUtils.get_demangled_func_name, inmain(idc.here)), (1 - distance) * 100)
        except HTTPError as e:
            error = e.response.json().get("error", "An unexpected error occurred. Sorry for the inconvenience.")
            Dialog.showError("Function Renaming", error)
        except RequestException as e:
            logger.error("An unexpected error has occurred. %s", e)
        finally:
            inmain(hide_wait_box)
            inmain(self.ui.tabWidget.setCurrentIndex, 1)
            inmain(self.ui.fetchButton.setEnabled, True)
            inmain(self.ui.progressBar.setProperty, "value", 0)

            width: int = inmain(self.ui.resultsTable.width)

            inmain(self.ui.resultsTable.setColumnWidth, 0, width * .38)
            inmain(self.ui.resultsTable.setColumnWidth, 1, width * .12)
            inmain(self.ui.resultsTable.setColumnWidth, 2, width * .5)

    def _rename_symbol(self):
        if not self.ui.resultsTable.selectedIndexes():
            Dialog.showInfo("Function Renaming", "Select one of the listed functions that you wish to use.")
            return

        rows = sorted(set(index.row() for index in self.ui.resultsTable.selectedIndexes()))
        selected = self.ui.resultsTable.model().get_data(rows[0])

        if selected and isinstance(selected[0], SimpleItem):
            if not IDAUtils.set_name(self.v_addr + self.base_addr, selected[0].text):
                Dialog.showError("Rename Function Error", f"Function {selected[0].text} already exists.")
            else:
                inthread(self._set_function_renamed, self.v_addr, selected[0].text)

                logger.info("Renowned %s in %s with confidence of '%s",
                            IDAUtils.get_demangled_func_name(idc.here()),
                            selected[0].text, selected[0].data["confidence"])

                if self.state.project_cfg.get("func_type") and \
                        ASKBTN_YES == idc.ask_yn(ASKBTN_YES,
                                                 "HIDECANCEL\nWould you also like to update the function declaration?"):
                    # Prevent circular import
                    from revengai.actions import function_signature

                    function_signature(self.state, self.v_addr + self.base_addr, self._get_function_id(self.v_addr))

    def _search_collection(self, search: str = None):
        try:
            inmain(show_wait_box, "HIDECANCEL\nGetting RevEng.AI collections…")

            inmain(self.ui.fetchButton.setEnabled, False)

            res: Response = RE_collection_search(search)

            collections = []

            for collection in res.json()["collections"]:
                if isinstance(collection, str):
                    collections.append((collection,
                                        CheckableItem(checked=self.ui.layoutFilter.is_present(collection)),))
                else:
                    collections.append((IconItem(collection["collection_name"],
                                                 "lock.png" if collection["collection_scope"] == "PRIVATE" else
                                                 "unlock.png"),
                                        CheckableItem(checked=self.ui.layoutFilter.is_present(collection["collection_name"])),))

            inmain(inmain(self.ui.collectionsTable.model).fill_table, collections)
            inmain(self.ui.collectionsTable.setColumnWidth, 0, inmain(self.ui.collectionsTable.width) * .8)
        except HTTPError as e:
            logger.error("Getting collections failed. Reason: %s", e)

            Dialog.showError("Function Rename", f"Function Rename Error: {e.response.json().get('error', 'unknown')}")
        except RequestException as e:
            logger.error("An unexpected error has occurred. %s", e)
        finally:
            inmain(hide_wait_box)
            inmain(self.ui.fetchButton.setEnabled, True)
            inmain(self.ui.fetchButton.setFocus)

    def _table_menu(self) -> None:
        rows = sorted(set(index.row() for index in self.ui.resultsTable.selectedIndexes()))
        selected = self.ui.resultsTable.model().get_data(rows[0])

        if selected and self.ui.renameButton.isEnabled() and isinstance(selected[0], SimpleItem):
            menu = QMenu()
            renameAction = menu.addAction(self.ui.renameButton.text())
            renameAction.triggered.connect(self._rename_symbol)

            func_id = selected[0].data["nearest_neighbor_id"]
            breakdownAction = menu.addAction("View Function Breakdown")
            breakdownAction.triggered.connect(lambda: self._function_breakdown(func_id))

            menu.exec_(QCursor.pos())

    def _selected_collections(self) -> list[str]:
        return [self.ui.layoutFilter.itemAt(idx).widget().objectName() for idx in range(self.ui.layoutFilter.count())]

    def _filter(self, _) -> None:
        self.typing_timer.start(self.searchDelay)     # Starts the countdown to call the filtering method

    def _confidence(self, value: int) -> None:
        self.ui.description.setText(f"Confidence: {value:#02d}")

    def _filter_collections(self):
        self._search_collection(self.ui.collectionsFilter.text().lower())

    def _state_change(self, index: QModelIndex):
        item = self.ui.collectionsTable.model().get_data(index.row())

        if item[1].checkState == Qt.Checked:
            self.ui.layoutFilter.add_card(item[0])
        else:
            self.ui.layoutFilter.remove_card(item[0])

    def _callback(self, text: str) -> None:
        for row_item in self.ui.collectionsTable.model().get_datas():
            if isinstance(row_item[1], CheckableItem) and \
                    (isinstance(row_item[0], str) and row_item[0] == text or
                     isinstance(row_item[0], SimpleItem) and row_item[0].text == text):
                row_item[1].checkState = Qt.Unchecked

        self.ui.collectionsTable.model().layoutChanged.emit()
