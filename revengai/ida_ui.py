# -*- coding: utf-8 -*-

from json import load
from os.path import abspath, dirname, join, realpath

from ida_kernwin import set_dock_pos, PluginForm, DP_TAB, unregister_action, attach_action_to_menu, register_action, \
    action_desc_t, action_handler_t, AST_ENABLE_ALWAYS, create_menu, SETMENU_APP, SETMENU_INS, UI_Hooks, \
    attach_action_to_popup, add_hotkey, del_hotkey, get_widget_type, BWN_DISASM, BWN_PSEUDOCODE

from revengai import actions
from revengai.manager import RevEngState


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

    def activate(self, ctx):
        if self.callback:
            self.callback(self.state)
        return 1

    def update(self, ctx):
        return AST_ENABLE_ALWAYS

    def register(self, name, label, shortcut=None, tooltip=None, icon=-1) -> None:
        action = action_desc_t(
            name,      # The action name. This acts like an ID and must be unique
            label,     # The action text
            self,      # The action handler
            shortcut,  # Optional: the action shortcut
            tooltip,   # Optional: the action tooltip (available in menus/toolbar)
            icon,      # Optional: the action icon (shows when in menus/toolbars)
        )

        if not register_action(action):
            print(f"Failed to register '{name}'.")

        self.name = name

    def attach_to_menu(self, menu) -> None:
        if not attach_action_to_menu(menu, self.name, SETMENU_INS):
            print(f"Failed to attach to {menu} the action '{self.name}'.")


class Hooks(UI_Hooks):
    def __init__(self, state: RevEngState):
        super(Hooks, self).__init__()

        self.state = state

    def populating_widget_popup(self, form, popup):
        if get_widget_type(form) in [BWN_DISASM, BWN_PSEUDOCODE]:
            # Add separator
            attach_action_to_popup(form, popup, None, None)

            # Add actions
            with open(join(abspath(dirname(realpath(__file__))), "conf/actions.json"), "r") as fd:
                for action in load(fd):
                    if action["id"] == "reai:wizard" and not self.state.config.is_valid():
                        attach_action_to_popup(form, popup, action["id"], "RevEng.AI/", SETMENU_APP)
                    elif action["id"] != "reai:wizard" and self.state.config.is_valid():
                        attach_action_to_popup(form, popup, action["id"], "RevEng.AI/", SETMENU_APP)


class RevEngConfigForm_t(PluginForm):
    def __init__(self, state: RevEngState):
        super().__init__()

        self.state = state
        self.shown = False
        self.created = False
        self.parent = None

        self._hotkeys = []

        self._hooks = Hooks(self.state)

    def OnClose(self, form):
        self.shown = False
        self.unregister_actions()

    def Show(self, caption, options=0):
        if not self.shown:
            self.shown = True
            return PluginForm.Show(self, caption,
                                   options=(PluginForm.WOPN_TAB |
                                            PluginForm.WCLS_SAVE |
                                            PluginForm.WOPN_MENU |
                                            PluginForm.WOPN_PERSIST |
                                            PluginForm.WOPN_RESTORE))

    def OnCreate(self, form):
        self.created = True
        self.register_actions()

    def register_actions(self):
        # Add ui hook
        self._hooks.hook()

        with open(join(abspath(dirname(realpath(__file__))), "conf/actions.json"), "r") as fd:
            for action in load(fd):
                # Register menu actions
                handler = Handler(action["callback"], self.state)
                handler.register(action["id"], action["name"],
                                 shortcut=action.get("shortcut"),
                                 tooltip=action.get("tooltip"),
                                 icon=action.get("icon", -1))
                handler.attach_to_menu("View/RevEng.AI/")

                # Register hotkey actions

                if hasattr(action, "shortcut") and handler.callback:
                    self._hotkeys.append(add_hotkey(action.get("shortcut"), handler.callback))

    def unregister_actions(self):
        # Remove ui hook
        self._hooks.unhook()

        # Unregister hotkey actions
        for hotkey in list(filter(lambda key: key is not None, self._hotkeys)):
            del_hotkey(hotkey)

        # Unregister menu actions
        with open(join(abspath(dirname(realpath(__file__))), "conf/actions.json"), "r") as fd:
            for action in load(fd):
                unregister_action(action["id"])


class RevEngGUI(object):
    def __init__(self, state: RevEngState):
        self.state = state
        self.config_form = RevEngConfigForm_t(self.state)

        create_menu("reai:menu", "RevEng.AI", "View")
        set_dock_pos("RevEng.AI", "IDA View-A", DP_TAB)

    def show_windows(self):
        if self.state.config.auto_start:
            self.config_form.register_actions()
        else:
            self.config_form.Show("RevEng.AI Configuration")

    def term(self):
        self.config_form.Close(PluginForm.WCLS_SAVE)
