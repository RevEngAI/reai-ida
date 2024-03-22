import ida_kernwin
import idaapi
import ida_nalt
import ida_name
from PyQt5 import QtCore, QtWidgets
from binascii import hexlify
from pathlib import Path
from typing import Tuple
import ida_funcs
from ida_kernwin import warning
from revengai.logger import plugin_logger
from revengai.api import Endpoint
from revengai.gui.dialog import Dialog
from revengai.gui.upload_view import UploadView
from revengai.misc.configuration import Configuration
from revengai.exception import ReturnValueException


class IdaUtils(object):

    @staticmethod
    def get_selected_function() -> Tuple[any, str]:
        """
        Get the name of the function that the user has selected
        returns (location, function_name)
        """
        location = ida_kernwin.get_screen_ea()
        if location is not None:
            func_name = ida_funcs.get_func_name(location)
            if func_name:
                return location, func_name
            else:
                raise ReturnValueException("Failed to get function name")
        else:
            raise ReturnValueException("Failed to get screen address location")

    @staticmethod
    def rename_function(location: int, new_name: str) -> bool:
        return ida_name.set_name(location, new_name)
        pass


# class FileRename(ida_kernwin.Form):
#     class FileRenameChooser(ida_kernwin.Choose):
#         def __init__(
#             self,
#             title,
#             items,
#             flags=ida_kernwin.Choose.CH_MULTI,
#         ):
#             ida_kernwin.Choose.__init__(
#                 self,
#                 title,
#                 [
#                     ["File name", 20],
#                     ["analysis id", 5],
#                     ["status", 5],
#                     ["submitted", 5],
#                 ],
#                 flags,
#                 embedded=True,
#                 width=30,
#                 height=10,
#             )
#             self.items = items

#         def OnGetLine(self, n):
#             plugin_logger.debug(f"getline {n}")
#             return self.items[n]

#         def OnGetSize(
#             self,
#         ):
#             n = len(self.items)
#             plugin_logger.debug(f"getsizeof {n}")
#             return n

#     def __init__(self, items):
#         self.invert = False
#         F = ida_kernwin.Form
#         F.__init__(
#             self,
#             r"""STARTITEM 0
# BUTTON Yes* Select
# BUTTON CANCEL Cancel
# Analysis

# {OnChangeFormCallback}
# <:{Analysis}>

#                 """,
#             {
#                 "Analysis": F.EmbeddedChooserControl(
#                     StatusForm.StatusFormChooser("Analysis Tasks", items)
#                 ),
#                 "OnChangeFormCallback": F.FormChangeCb(self.OnFormChange),
#             },
#         )

#     def OnFormChange(self, fid):
#         """
#         Triggered when an event occurs on form
#         """
#         return 1


class FunctionRename(ida_kernwin.Form):
    class another_chooser(ida_kernwin.Choose):
        def __init__(self, title, data):
            ida_kernwin.Choose.__init__(
                self,
                title,
                [["Function", 30], ["Confidence", 10], ["Source", 20]],
                embedded=True,
                width=30,
                height=6,
            )
            self.items = data
            # self.icon = 5 # sets an icon for the row

        def OnGetLine(self, n):
            # NOTE - If these callbacks are no implemented properly then
            # the list may not draw properly
            plugin_logger.info(f"getline {self.items[n]}")
            return self.items[n]

        def OnGetSize(self):
            plugin_logger.info(f"size {len(self.items)}")
            return len(self.items)

    def __init__(self, data):
        self.invert = False
        f = ida_kernwin.Form
        f.__init__(
            self,
            r"""
RevEng.AI Function Renaming
{formchange}
<Similar functions:{funcChooser}>
<#Refresh#~Re~fresh:{btnRefresh}>
""",
            {
                "formchange": f.FormChangeCb(self.change_callback),
                "funcChooser": f.EmbeddedChooserControl(
                    FunctionRename.another_chooser("chooser title", data=data)
                ),
                "btnRefresh": f.ButtonInput(self.refresh_button_callback),
            },
        )

    def change_callback(self, id: int) -> None:
        plugin_logger.info(f"change callback {id}")
        return 1

    def refresh_button_callback(self, code) -> None:
        # issue request to get symbol embeddings
        # once we have the embeddings, issue another request
        # to get the nearest symbols.
        plugin_logger.info(f"refresh button clicked {code}")

    @staticmethod
    def show(data: list) -> int:
        # returns the index of the selected row
        # create form
        f = FunctionRename(data=data)
        f.Compile()
        ok = f.Execute()
        selection = None
        if ok == 1:
            selection = f.funcChooser.selection
            plugin_logger.info(f"selection was {selection}")
        f.Free()
        return selection


class RenameFileHandlerDialog(QtWidgets.QDialog):
    def __init__(self, pluging_configuration: Configuration, embeddings: list[dict], loc: any):
        super(RenameFileHandlerDialog, self).__init__()

        # record the location where the user triggered the context menu
        self.location = loc

        # set size and geometry stuff
        screen = QtWidgets.QDesktopWidget().screenGeometry()
        self.setGeometry(0, 0, screen.width() * 0.5, screen.height() * 0.5)
        self.move(
            screen.width() // 2 - self.width() // 2, screen.height() // 2 - self.height() // 2
        )

        #
        # the format of the nearest neighbours from the endpoint is of the form where there is no
        # collection information
        #  {
        #     "binary_id": 902,
        #     "binary_name": "b8e7d04229a437d1aabf41445a2e44d2908f46b0fda3041879e2d7b2c4e776c4.exe",
        #     "distance": 1,
        #     "embedding": "[..]",
        #     "id": 222771,
        #     "name": "entry",
        #         "sha_256_hash": "b8e7d04229a437d1aabf41445a2e44d2908f46b0fda3041879e2d7b2c4e776c4"
        # }
        #

        self.embeddings = embeddings

        # TODO - make a request to the endpoint for all the collections known to the user
        # and pass via constructor
        self.collections = []

        layout = QtWidgets.QVBoxLayout()

        # table views
        self.func_table = QtWidgets.QTableWidget()
        self.func_table.setColumnCount(3)

        # no grid
        self.func_table.setShowGrid(False)

        # selections are done across the whole row
        self.func_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectionBehavior.SelectRows)

        # rows are clickable for selection
        self.func_table.setFocusPolicy(QtCore.Qt.FocusPolicy.ClickFocus)

        # headers
        self.func_table.setHorizontalHeaderLabels(["Function", "Confidence", "Binary"])

        # non-editable
        self.func_table.setEditTriggers(QtWidgets.QTableWidget.EditTrigger.NoEditTriggers)

        # single-selection
        self.func_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

        # stretch to fill space
        self.func_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)

        # binaries filter selection
        self.binary_filter_selection = QtWidgets.QComboBox()
        self.binary_filter_selection.addItems(self.update_binaries_filter())

        # register call back to fire only when a change has occured!
        self.binary_filter_selection.currentIndexChanged.connect(self.user_collection_select)

        # set layout for the collection combom bpx
        collection_selection_layout = QtWidgets.QHBoxLayout()
        collection_selection_layout.addWidget(self.binary_filter_selection)

        # collection drop-down group box
        collection_group_box = QtWidgets.QGroupBox("Binaries")
        collection_group_box.setAlignment(
            QtCore.Qt.AlignmentFlag.AlignLeft
        )  # NOTE - Does not seem to have any effect

        # add Combo drop down box with horizontal box layout to group box
        collection_group_box.setLayout(collection_selection_layout)

        # buttons
        buttonBox = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Cancel)
        rename_function = QtWidgets.QPushButton(
            "Rename Function",
        )
        rename_file = QtWidgets.QPushButton("Rename File")
        buttonBox.addButton(rename_function, QtWidgets.QDialogButtonBox.ActionRole)
        buttonBox.addButton(rename_file, QtWidgets.QDialogButtonBox.ActionRole)

        buttonBox.clicked.connect(self.clicked)
        buttonBox.rejected.connect(self.reject)

        # layout for the slider and confidence label
        confidence_layout = QtWidgets.QHBoxLayout()

        # group box
        confidence_group_box = QtWidgets.QGroupBox("Confidence Level")
        confidence_group_box.setAlignment(
            QtCore.Qt.AlignmentFlag.AlignLeft
        )  # Does not seem to have any effect

        # slider
        slider = QtWidgets.QSlider(QtCore.Qt.Orientation.Horizontal)
        slider.setSingleStep(1)
        slider.setPageStep(10)
        slider.setMinimum(0)
        slider.setMaximum(100)
        slider.setValue(100)
        slider.setTickPosition(QtWidgets.QSlider.TicksBelow)
        slider.setTickInterval(10)
        slider.valueChanged.connect(self.slider_change)

        # label
        self.confidence_level = QtWidgets.QLineEdit()
        self.confidence_level.setReadOnly(True)
        self.confidence_level.setText(str(slider.value()))

        confidence_layout.addWidget(self.confidence_level)
        confidence_layout.addWidget(slider)

        # set stretch ratios between slider and text
        confidence_layout.setStretch(0, 1)
        confidence_layout.setStretch(1, 10)

        confidence_group_box.setLayout(confidence_layout)

        # fill table with initial data
        if embeddings:
            self.update_table("All", 0)

        # add widgets - existing working code for when we were not using tabs
        # layout.addWidget(self.func_table)
        # layout.addWidget(collection_group_box)
        # layout.addWidget(confidence_group_box)
        # layout.addWidget(buttonBox)

        # first tab - figure out how to draw a tabbed dialog!
        self.tabWidget = QtWidgets.QTabWidget()
        self.function_widget = QtWidgets.QWidget()
        self.file_widget = QtWidgets.QWidget()

        # layout for the tabs
        tab_function_layout = QtWidgets.QVBoxLayout()

        # add the widgets to the layouts
        tab_function_layout.addWidget(self.func_table)
        tab_function_layout.addWidget(collection_group_box)
        tab_function_layout.addWidget(confidence_group_box)
        tab_function_layout.addWidget(buttonBox)

        # layouts for the tabs
        self.function_widget.setLayout(tab_function_layout)
        self.file_widget.setLayout(self.create_batch_tab())

        # add the tabs to the QTabbedWidget thing
        self.tabWidget.addTab(self.function_widget, "Functions")
        self.tabWidget.addTab(self.file_widget, "Batch Renaming")

        # add tabbed widget to the main layout
        layout.addWidget(self.tabWidget)

        """
        
        GUI - Setup separate tab that display the collections to the user for the given users creds
        user can select which collections to scan for functions
        send request for each function given a selection of collections
        apply renaming of said functions given the highest one returned
        display the changed functions in a results list
        
        for the whole set of file functions use the /ann/symbol/batch endpoint -> n
        not sure on how the data itself is returned to the user.
        
        """

        # set main layout that contains all descendents
        self.setLayout(layout)

    def slider_change(self, value):
        # plugin_logger.info(f"slider value {value}")
        self.confidence_level.setText(str(value))
        self.update_table(self.binary_filter_selection.currentText(), value)

    def reject(self):
        # close window if the user selects cancel
        plugin_logger.info("reject")
        super().reject()

    def create_batch_tab(self):
        """
        TODO - This tab will display the collections that the user can select
        to perform automated analysis on the binary. The endpoint is currently
        not setup so this will need to be finished once the endpoint has been setup.


        This will be of the form <collection> <selected> - see ghidra plugin for example

        """

        layout = QtWidgets.QVBoxLayout()
        table = QtWidgets.QTableWidget()

        # column
        table.setColumnCount(2)

        # no grid
        table.setShowGrid(False)

        # selections are done across the whole row
        table.setSelectionBehavior(QtWidgets.QTableWidget.SelectionBehavior.SelectRows)

        # rows are clickable for selection
        table.setFocusPolicy(QtCore.Qt.FocusPolicy.ClickFocus)

        # headers
        table.setHorizontalHeaderLabels(["Collection", "Include"])

        # non-editable
        table.setEditTriggers(QtWidgets.QTableWidget.EditTrigger.NoEditTriggers)

        # single-selection
        table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

        # stretch to fill space
        table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)

        layout.addWidget(table)
        return layout

    def clicked(self, button):
        # Called before action-specifc handlers are called
        if "function" in button.text().lower():
            # check user has selected a function in the list
            item = self.func_table.selectedItems()
            if len(item) > 0:
                plugin_logger.info(
                    f"clicked {button.text()} - user selected function {item[0].text()}"
                )
                IdaUtils.rename_function(self.location, item[0].text())
                self.close()
            else:
                warning("No function selected!")
        elif "file" in button.text().lower():
            # check user has selected a collection from the drop down
            if self.binary_filter_selection.currentText() == "All":
                warning("Select a collection first!")
            else:
                # TODO - Do some stuff in IDA to now rename ALL the functions given the selected collection
                # and confidence level?
                # what requests do I need to do in order to rename all the functions in a file?
                #
                # 1. Get a list of collections that you have available and display these to the user
                # 2. User selects colelctions and then clicks start button / use slider to select the confidence level
                # 3. Use ANN batch renaming, any function returned that is higher than this value will
                # automatically trigger the function to be renamed.
                # 4. results table will show all the functions from -> to and the confidence
                # Results will be a table
                # there will also be other information about the number of functions seen, renamed, skipped or error
                pass
        else:
            plugin_logger.info(f"clicked {button.text()}")

    def user_collection_select(self, idx):
        # called whenever the user select an item in the drop-down
        # and it is different from the previous selection
        text = self.binary_filter_selection.itemText(idx)
        plugin_logger.info(f"user selected {text}")
        self.update_table(text, int(self.confidence_level.text()))

    def update_binaries_filter(self) -> list[str]:
        """Updates the drop-down list that enables binary filtering for given nearest neighbours given the list of embedding passed in when the dialog was opened."""
        bins = []
        for e in self.embeddings:
            bins.append(e["binary_name"])
        return ["all"] + list(set(bins))

    def update_table(self, sel: str, confidence: int) -> None:
        """Updates the table with the ANN information returned from the endpoint given
        the selected binary name.

        Passing None will re-fill the table with no filtering on binaries

        Args:
            sel (str): Binary name to filter on or None.
        """
        # remove rows manually and set row count to 0
        for i in range(self.func_table.rowCount()):
            self.func_table.removeRow(i)

        self.func_table.setRowCount(0)

        # update the table with all of the embeddings
        def create(idx: int, item: dict):
            self.func_table.setItem(idx, 0, QtWidgets.QTableWidgetItem(item["name"]))
            # the confidence values are returned between 0 and 1
            self.func_table.setItem(idx, 1, QtWidgets.QTableWidgetItem(str(item["distance"] * 100)))
            self.func_table.setItem(idx, 2, QtWidgets.QTableWidgetItem(item["binary_name"]))

        if sel.lower() == "all":
            self.func_table.setRowCount(len(self.embeddings))
            [
                create(i, v)
                for i, v in enumerate(self.embeddings)
                if v["distance"] * 100 >= confidence
            ]
        else:
            self.func_table.setRowCount(len(self.embeddings))
            [
                create(i, v)
                for i, v in enumerate(self.embeddings)
                if v["binary_name"] == sel and v["distance"] * 100 >= confidence
            ]


class RenameFileHandler(ida_kernwin.action_handler_t):
    def __init__(self, conf: Configuration, endpoint: Endpoint) -> None:
        ida_kernwin.action_handler_t.__init__(self)
        self._config = conf
        self._endpoint = endpoint

    def activate(self, ctx) -> None:
        if (
            "selected_analysis" in self._config.context.keys()
            and self._config.context["selected_analysis"] is not None
        ):
            try:
                loc, func = IdaUtils.get_selected_function()
                # get the embedding for the selected function, given analysis ID and file.
                embedding = self.get_file_embeddings(func)
                # get the nearest neighbours given the embedding
                neighbours = self.get_neighbours(embedding)
                # draw dialog and pass in the data
                f = RenameFileHandlerDialog(self._config, neighbours, loc)
                f.exec()
            except ReturnValueException as rve:
                plugin_logger.error(f"{rve.message}")
                warning(f"{rve.message}")
        else:
            warning("No analysis ID selected - Select an analysis or send file for analysis!")

    def get_file_embeddings(self, func_name: str) -> list[int]:
        #
        # given the current analysis, get the embeddings for the file
        # return the function_embedding value for the function name
        # which is a list of numbers.
        #
        # raise exception if any errors occurs
        #
        js, resp = self._endpoint.get_symbol_embeddings(self._config.context["selected_analysis"])
        if resp.status_code == 200:
            #
            # {
            #     "function_embedding": [
            #       3365.9301286813807,
            #       454.6004420717171,
            #       -381.89370716621335
            #     ],
            #     "function_id": 2463421,
            #     "function_name": "entry",
            #     "function_size": 37,
            #     "function_vaddr": 32800
            #  },
            #
            plugin_logger.info(f"Got {len(js)} embeddings")
            for idx, entry in enumerate(js):
                if entry["function_name"] == func_name:
                    plugin_logger.debug(f"Found function at index {idx}")
                    return entry["function_embedding"]
            raise ReturnValueException("Failed to find function in returned list of embeddings!")
        else:
            raise ReturnValueException(
                f"Failed to get embeddings for file {resp.status_code} - response {js}"
            )

    def get_neighbours(self, embedding: list[int]) -> list[dict]:
        # make request to endpoint given an embedding to find
        # the nearest neighbours
        plugin_logger.debug(f"Getting nearest neighbours for function with embedding {embedding}")
        js, response = self._endpoint.get_symbol_nearest(
            hexlify(ida_nalt.retrieve_input_file_sha256()).decode(), embedding
        )
        if response.status_code == 200:
            plugin_logger.info(f"Got {len(js)} nearest neighbours")
            plugin_logger.debug(f"{js}")
            return js
        else:
            raise ReturnValueException(f"Failed getting nearest neighbours for function")


# class RenameFunctionHandler(ida_kernwin.action_handler_t):
#     # TODO - hook this up to function rename window
#     def __init__(self, form, endpoint: Endpoint, current_file_info: dict) -> None:
#         ida_kernwin.action_handler_t.__init__(self)
#         self._form = form
#         self._endpoint: Endpoint = endpoint
#         self.current_file = current_file_info
#         self.current_function = None

#     def activate(self, ctx) -> None:
#         # issue requests to get the matching functions before drawing the form
#         # or issue error diaglog
#         location = ida_kernwin.get_screen_ea()
#         if location is not None:
#             self.current_function = ida_funcs.get_func_name(location)
#             if self.current_function is not None:
#                 plugin_logger.info(f"function name is {self.current_function}")
#                 idx, fs = self.api_get_embeddings()
#                 if idx:
#                     display_data = self.api_get_nearest_symbol(fs[idx]["embedding"])
#                     if display_data:
#                         data = [
#                             [x["name"], str(x["distance"]), x["binary_name"]] for x in display_data
#                         ]
#                         plugin_logger.info(f"{data}")
#                         f = FunctionRename.show(data)
#                         if f:
#                             ida_name.set_name(location, data[f[0]][0])
#                             func: ida_funcs.func_t = ida_funcs.get_func(location)
#                             if func:
#                                 # This also seems to trigger a re-analysis but it works
#                                 # TODO - try doing func_t.refresh_func_ctext()
#                                 ida_funcs.update_func(func)
#                                 # TODO - works but refreshes all of pseudocode view
#                                 # view = ida_kernwin.get_current_widget()
#                                 # if view:
#                                 #     plugin_logger.info(f"refreshing text")
#                                 #     vdui = ida_hexrays.get_widget_vdui(view)
#                                 #     vdui.refresh_view(True)
#                 else:
#                     warning("Could not find function in returned list of embeddings!")
#             else:
#                 warning("Failed to get function name")

#     def update(self, ctx) -> None:
#         return ida_kernwin.AST_ENABLE_ALWAYS

# def api_get_embeddings(self) -> Union[Tuple[int, dict], None]:

# def api_get_nearest_symbol(self, func_embedding: list) -> Union[dict, None]:


# TODO - Explain endpoint is currently broken so disable this.
# class ExplainFunctionHandler(ida_kernwin.action_handler_t):
#     def __init__(self, endpoint: Endpoint):
#         ida_kernwin.action_handler_t.__init__(self)
#         self._endpoint = endpoint

#     def activate(self, ctx):
#         location = ida_kernwin.get_screen_ea()
#         if location is not None:
#             Dialog.ok_box("Adding a comment to our function!")
#             # decompiled pseudocode
#             # result = ida_hexrays.decompile(location).pseudocode
#             # lines = []
#             # l = "\n"
#             # for sline in result:
#             #     line = ida_lines.tag_remove(sline.line)
#             #     lines.append(line)
#             # l now has the full pseudocode listing
#             func = ida_funcs.get_func(location)
#             inst = idautils.FuncItems(func.start_ea)
#             asm = []
#             l = "\n"
#             for i in inst:
#                 line = ida_lines.generate_disasm_line(i)
#                 asm.append(ida_lines.tag_remove(line))

#             listing = l.join(asm)
#             plugin_logger.info(f"{listing}")

#             js, resp = self._endpoint.explain(listing)
#             if js and resp.status_code == 200:
#                 plugin_logger.info(f"{resp}")
#                 if resp.status_code == 200:
#                     ida_funcs.set_func_cmd(location, js["explanation"])
#             else:
#                 warning(f"Response code {resp.status_code} - see log for further details")

#     def update(self, ctx):
#         return ida_kernwin.AST_ENABLE_ALWAYS


class ConfigurationHandler(ida_kernwin.action_handler_t):
    """
    Handler class that deals with pressing the configuration button in the menu.
    It opens up the main plugin form when activated
    """

    def __init__(self, form):
        ida_kernwin.action_handler_t.__init__(self)
        self._form = form

    def activate(self, ctx):
        self._form.Show("RevEng.ai")

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class RequestAnalysis(ida_kernwin.Form):
    def __init__(self):
        self.invert = False
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""STARTITEM 0
BUTTON YES* Yes
BUTTON CANCEL No
Analysis


Request analysis of file also?
                """,
            {},
        )


class UploadBinaryHandler(ida_kernwin.action_handler_t):
    MAX_FILE_SIZE_UPLOAD_BYTES = 16000000  # 1MB = 1000 bytes

    """
    Handler that deals with the "Upload binary
    """

    def __init__(self, upload_view: UploadView, endpoint: Endpoint):
        ida_kernwin.action_handler_t.__init__(self)
        self._endpoint = endpoint
        self._upload_view = upload_view

    def activate(self, ctx):
        plugin_logger.info("Upload button pressed")
        request_analysis = False
        # check file is opened in the database
        # then attempt to read the file from disk
        # then issue API call using key to endpoint to submit it

        # check if user wants to request analysis
        ra = RequestAnalysis()
        ra.Compile()
        ok = ra.Execute()
        if ok == 1:
            request_analysis = True

        fp = idaapi.get_input_file_path()
        plugin_logger.debug(
            f"input file is {fp} with hash {hexlify(ida_nalt.retrieve_input_file_sha256()).decode()}"
        )
        # limit file size to 16MB
        try:
            if fp is not None:
                pobj = Path(fp)
                if Path.exists(pobj):
                    if pobj.stat().st_size <= UploadBinaryHandler.MAX_FILE_SIZE_UPLOAD_BYTES:
                        data = open(fp, "rb").read()
                        j, resp = self._endpoint.upload(data)
                        if j and resp.status_code == 200:
                            # upload the file to the remote endpoint
                            assert (
                                j["sha_256_hash"]
                                == hexlify(ida_nalt.retrieve_input_file_sha256()).decode()
                            )
                            self._upload_view.insert_entry(fp)

                            Dialog.ok_box("File uploaded successfully!")
                            # the user still needs to send the file for analysis!

                            if request_analysis:
                                # send request to trigger analysis of file
                                json, resp = self._endpoint.analyze(pobj.name, j["sha_256_hash"])
                                if resp.status_code == 200:
                                    Dialog.ok_box(
                                        f"{json['success']} - Binary ID {json['binary_id']}"
                                    )

                                    # update current context with selected analysis id
                                    self._endpoint._conf.context["selected_analysis"] = json[
                                        "binary_id"
                                    ]
                                else:
                                    plugin_logger.error(
                                        f"Failed to submit file for analysis {json}"
                                    )
                                    warning("Failed to submit file for analysis, see log")
                        else:
                            warning("Failed to upload, see debug log")
                    else:
                        warning(f"File too big!")
                else:
                    plugin_logger.debug(
                        f"Opened file {fp} apparently does not exist on disk anymore!"
                    )
            else:
                plugin_logger.error("No file opened!")
                warning(f"No file opened, try opening a file first.")
        except KeyError as ke:
            warning("Model is not set in Configuration")
            plugin_logger.error(f"Missing key exception, missing -> {ke}")
        except Exception as e:
            raise e

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
