import ida_kernwin
import idaapi
import ida_nalt
import idc
import ida_name
import ida_hexrays
import ida_lines
import ida_ua
import idautils
from binascii import hexlify
from pathlib import Path
from typing import Dict, Union, Tuple
import ida_funcs
from ida_kernwin import warning
from revengai.logger import plugin_logger
from revengai.api import Endpoint
from revengai.gui.dialog import Dialog
from revengai.gui.upload_view import UploadView


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


class RenameFunctionHandler(ida_kernwin.action_handler_t):
    # TODO - hook this up to function rename window
    def __init__(self, form, endpoint: Endpoint, current_file_info: dict) -> None:
        ida_kernwin.action_handler_t.__init__(self)
        self._form = form
        self._endpoint: Endpoint = endpoint
        self.current_file = current_file_info
        self.current_function = None

    def activate(self, ctx) -> None:
        # issue requests to get the matching functions before drawing the form
        # or issue error diaglog
        location = ida_kernwin.get_screen_ea()
        if location is not None:
            self.current_function = ida_funcs.get_func_name(location)
            if self.current_function is not None:
                plugin_logger.info(f"function name is {self.current_function}")
                idx, fs = self.api_get_embeddings()
                if idx:
                    display_data = self.api_get_nearest_symbol(fs[idx]["embedding"])
                    if display_data:
                        data = [
                            [x["name"], str(x["distance"]), x["binary_name"]]
                            for x in display_data
                        ]
                        plugin_logger.info(f"{data}")
                        f = FunctionRename.show(data)
                        if f:
                            ida_name.set_name(location, data[f[0]][0])
                            func: ida_funcs.func_t = ida_funcs.get_func(location)
                            if func:
                                # This also seems to trigger a re-analysis but it works
                                # TODO - try doing func_t.refresh_func_ctext()
                                ida_funcs.update_func(func)
                                # TODO - works but refreshes all of pseudocode view
                                # view = ida_kernwin.get_current_widget()
                                # if view:
                                #     plugin_logger.info(f"refreshing text")
                                #     vdui = ida_hexrays.get_widget_vdui(view)
                                #     vdui.refresh_view(True)
                else:
                    warning("Could not find function in returned list of embeddings!")
            else:
                warning("Failed to get function name")

    def update(self, ctx) -> None:
        return ida_kernwin.AST_ENABLE_ALWAYS

    def api_get_embeddings(self) -> Union[Tuple[int, dict], None]:
        # make the request and return the index and list of function embeddings
        id = self._endpoint.get_id(self.current_file["hash"])
        if id:
            js, resp = self._endpoint.get_symbol_embeddings(id)
            if resp.status_code == 200:
                for idx, entry in enumerate(js):
                    if entry["name"] == self.current_function:
                        plugin_logger.debug(f"found function at index {idx}")
                        return idx, js
                warning(f"failed to find function in returned embeddings!")
            else:
                warning(f"failed to get symbol embeddings")
        return None, None

    def api_get_nearest_symbol(self, func_embedding: list) -> Union[dict, None]:
        # make the request and format data to give it back to the form
        js, response = self._endpoint.get_symbol_nearest(
            self.current_file["hash"], func_embedding
        )
        if response.status_code == 200:
            return js
        else:
            warning(
                f"Failed getting nearest neighbours for function, see logger output"
            )
        return None


class ExplainFunctionHandler(ida_kernwin.action_handler_t):
    def __init__(self, endpoint: Endpoint):
        ida_kernwin.action_handler_t.__init__(self)
        self._endpoint = endpoint

    def activate(self, ctx):
        location = ida_kernwin.get_screen_ea()
        if location is not None:
            Dialog.ok_box("Adding a comment to our function!")
            # decompiled pseudocode
            # result = ida_hexrays.decompile(location).pseudocode
            # lines = []
            # l = "\n"
            # for sline in result:
            #     line = ida_lines.tag_remove(sline.line)
            #     lines.append(line)
            # l now has the full pseudocode listing
            func = ida_funcs.get_func(location)
            inst = idautils.FuncItems(func.start_ea)
            asm = []
            l = "\n"
            for i in inst:
                line = ida_lines.generate_disasm_line(i)
                asm.append(ida_lines.tag_remove(line))

            listing = l.join(asm)
            plugin_logger.info(f"{listing}")

            js, resp = self._endpoint.explain(listing)
            if js and resp.status_code == 200:
                plugin_logger.info(f"{resp}")
                if resp.status_code == 200:
                    ida_funcs.set_func_cmd(location, js["explanation"])
            else:
                warning(
                    f"Response code {resp.status_code} - see log for further details"
                )

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


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
        # check file is opened in the database
        # then attempt to read the file from disk
        # then issue API call using key to endpoint to submit it
        fp = idaapi.get_input_file_path()
        plugin_logger.debug(
            f"input file is {fp} with hash {hexlify(ida_nalt.retrieve_input_file_sha256()).decode()}"
        )
        # limit file size to 16MB
        try:
            if fp is not None:
                pobj = Path(fp)
                if Path.exists(pobj):
                    if (
                        pobj.stat().st_size
                        <= UploadBinaryHandler.MAX_FILE_SIZE_UPLOAD_BYTES
                    ):
                        data = open(fp, "rb").read()
                        j, resp = self._endpoint.upload(data, pobj.name)
                        if j and resp.status_code == 200:
                            assert (
                                j["sha_256_hash"]
                                == hexlify(
                                    ida_nalt.retrieve_input_file_sha256()
                                ).decode()
                            )
                            self._upload_view.insert_entry(fp)
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
