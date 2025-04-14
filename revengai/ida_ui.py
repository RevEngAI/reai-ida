from json import load
from os.path import dirname, isfile, join

from idaapi import AST_ENABLE_ALWAYS
from idaapi import BWN_DISASM
from idaapi import BWN_PSEUDOCODE
from idaapi import DP_TAB, SETMENU_APP
from idaapi import IDA_SDK_VERSION
from idaapi import PluginForm
from idaapi import SETMENU_ENSURE_SEP
from idaapi import SETMENU_INS
from idaapi import UI_Hooks
from idaapi import action_desc_t
from idaapi import action_handler_t
from idaapi import add_hotkey
from idaapi import attach_action_to_menu
from idaapi import attach_action_to_popup
from idaapi import attach_action_to_toolbar
from idaapi import create_menu
from idaapi import create_toolbar
from idaapi import del_hotkey
from idaapi import delete_menu
from idaapi import delete_toolbar
from idaapi import get_widget_type
from idaapi import register_action
from idaapi import set_dock_pos
from idaapi import unregister_action
from idc import get_input_file_path
from idc import here

import logging

from revengai import actions
from revengai.api import RE_models
from revengai.actions import load_recent_analyses, setup_wizard
from revengai.manager import RevEngState
from revengai.misc.utils import IDAUtils

MENU = "RevEng.AI/"

logger = logging.getLogger("REAI")


class Handler(action_handler_t):
    def __init__(self, callback, state: RevEngState):
        """Create a Handler calling @callback when activated"""
        super(Handler, self).__init__()

        self.name = None
        self.state = state

        from inspect import getmembers, isfunction

        for func in getmembers(actions, isfunction):
            if func[0] == callback:
                self.callback = func[1]

    def activate(self, _):
        if self.callback:
            self.callback(self.state)
        return True

    def update(self, _):
        return AST_ENABLE_ALWAYS

    def register(
            self,
            name: str,
            label: str,
            shortcut: str = None,
            tooltip: str = None,
            icon: int = -1,
    ) -> bool:
        self.name = name

        action = action_desc_t(
            name,  # The action name. This acts like an ID and must be unique
            label,  # The action text
            self,  # The action handler
            shortcut,  # Optional: the action shortcut
            # Optional: the action tooltip (available in menus/toolbar)
            tooltip,
            # Optional: the action icon (shows when in menus/toolbars)
            icon,
        )

        return register_action(action)

    def attach_to_menu(self, menu: str, flags: int = SETMENU_INS) -> bool:
        return attach_action_to_menu(menu, self.name, flags)

    def attach_to_toolbar(self, toolbar: str) -> bool:
        return attach_action_to_toolbar(toolbar, self.name)


class Hooks(UI_Hooks):
    def __init__(self, state: RevEngState):
        super(Hooks, self).__init__()

        self.state = state

    def ready_to_run(self) -> None:
        load_recent_analyses(self.state)

    def populating_widget_popup(self, form, popup):
        fpath = get_input_file_path()

        if (
                fpath
                and isfile(fpath)
                and get_widget_type(form) in [BWN_DISASM, BWN_PSEUDOCODE]
        ):
            # Add separator
            attach_action_to_popup(form, popup, None, None)

            # Add actions
            with open(join(dirname(__file__), "conf", "actions.json")) as fd:
                func_ea = here()
                for action in load(fd):
                    if action.get("enabled", True):
                        if self.state.config.is_valid():
                            if (
                                    action["id"] == "reai:wizard"
                                    or (
                                    action["id"]
                                    in (
                                            "reai:rename",
                                            "reai:breakdown",
                                            "reai:summary",
                                    )
                                    and not IDAUtils.is_function(func_ea)
                            )
                                    or (
                                    get_widget_type(form) != BWN_PSEUDOCODE
                                    and action["id"]
                                    in (
                                            "reai:explain",
                                            "reai:signature",
                                    )
                            )
                            ):
                                continue
                        elif action["id"] != "reai:wizard":
                            continue
                        attach_action_to_popup(
                            form, popup, action["id"], MENU, SETMENU_APP
                        )


class RevEngConfigForm_t(PluginForm):
    def __init__(self, state: RevEngState):
        super().__init__()

        self.state = state
        self.shown = False
        self.created = False
        self.parent = None

        self._hotkeys = []
        self._menus_names = []

        self._hooks = Hooks(self.state)

    def OnClose(self, form):
        self.shown = False
        self.unregister_actions()

    def Show(self, caption, options=0):
        if not self.shown:
            self.shown = True

            return PluginForm.Show(
                self,
                caption,
                options=(
                        options
                        | PluginForm.WOPN_TAB
                        | PluginForm.WCLS_SAVE
                        | PluginForm.WOPN_MENU
                        | PluginForm.WOPN_PERSIST
                        | PluginForm.WOPN_RESTORE
                ),
            )

    def OnCreate(self, form):
        self.created = True

        self.register_actions()

    def register_actions(self, init: bool = True):
        # Add UI hook
        self._hooks.hook()

        if IDA_SDK_VERSION < 820:
            # Add menubar item
            create_menu("reai:menubar", MENU[:-1], "View")
        elif not init:
            delete_toolbar("reai:toolbar")
            create_menu("reai:menubar", MENU[:-1], "View")
        else:
            # Add toolbar item
            if create_toolbar("reai:toolbar", MENU[:-1]):
                handler = Handler("toolbar", self.state)
                handler.register(
                    "reai:toolbar", MENU[:-1], icon=self.state.icon_id)
                handler.attach_to_toolbar("reai:toolbar")
            else:
                self.register_actions(False)

        with open(join(dirname(__file__), "conf", "actions.json")) as fd:
            for action in load(fd):
                if action.get("enabled", True) and (
                        self.state.config.is_valid(
                        ) or action["id"] == "reai:wizard"
                ):
                    if "children" in action:
                        for child in action["children"]:
                            handler = Handler(child["callback"], self.state)
                            handler.register(
                                child["id"],
                                child["name"],
                                shortcut=child.get("shortcut"),
                                tooltip=child.get("tooltip"),
                                icon=child.get("icon", -1),
                            )
                            if handler.attach_to_menu(
                                    f"{MENU}{action['name']}/"
                            ):
                                self._menus_names.append(handler.name)
                    else:
                        # Register menu actions
                        handler = Handler(action["callback"], self.state)
                        handler.register(
                            action["id"],
                            action["name"],
                            shortcut=action.get("shortcut"),
                            tooltip=action.get("tooltip"),
                            icon=action.get("icon", -1),
                        )
                        if handler.attach_to_menu(MENU):
                            self._menus_names.append(handler.name)
                        # Register hotkey actions
                    if hasattr(action, "shortcut") and handler.callback:
                        self._hotkeys.append(
                            add_hotkey(action.get("shortcut"),
                                       handler.callback)
                        )

            # context menu for About
            handler = Handler("about", self.state)
            handler.register("reai:about", "About", icon=self.state.icon_id)
            if handler.attach_to_menu(MENU, SETMENU_ENSURE_SEP):
                self._menus_names.append(handler.name)

            # context menu for Check for Update
            handler = Handler("update", self.state)
            handler.register("reai:update", "Check for Update")
            if handler.attach_to_menu(MENU):
                self._menus_names.append(handler.name)

    def unregister_actions(self):
        # Remove UI hook
        self._hooks.unhook()

        # Unregister hotkey actions
        for hotkey in list(filter(lambda key: key is not None, self._hotkeys)):
            del_hotkey(hotkey)

        # Unregister menu actions
        for menu_name in self._menus_names:
            unregister_action(menu_name)

        # Remove menubar and toolbar item
        delete_menu("reai:menubar")
        delete_toolbar("reai:toolbar")


class RevEngGUI(object):
    def __init__(self, state: RevEngState):
        self.state = state
        self.config_form = RevEngConfigForm_t(self.state)

        set_dock_pos(MENU[:-1], "IDA View-A", DP_TAB)

    def show_windows(self):
        self.config_form.register_actions()
        self._handle_first_time()
        
        logger.info('Refreshing your RevEng.AI models..')
        self._handle_model_update()
        logger.info('Updated to the latest model!')

    def term(self):
        self.config_form.Close(PluginForm.WCLS_SAVE)

    def _handle_first_time(self):
        if not self.state.config.is_valid():
            setup_wizard(self.state)

    def _handle_model_update(self):
        response = RE_models().json()

        self.state.config.set(
            "models", [model["model_name"]
                for model in response["models"]]
        )