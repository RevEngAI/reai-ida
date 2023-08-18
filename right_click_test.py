# please run it via File->script file->right_click_test.py

import idaapi
import idc
import ida_kernwin

class MyHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    # Display function name when invoked.
    def activate(self, ctx):
        func_ea = ida_kernwin.get_screen_ea()
        function_name = idc.get_func_name(func_ea)
        idaapi.info("Function name: %s" % function_name)
        return 1

    # This action is available if a function is selected.
    def update(self, ctx):
        if idaapi.get_func(ida_kernwin.get_screen_ea()):
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET

# Create the action
action_desc = idaapi.action_desc_t(
    'my:action',          # The action name
    'Show Function Name', # The action text.
    MyHandler(),          # The action handler
    None,                 # Optional: action shortcut
    'Displays the function name in a messagebox', # Optional: tooltip
    0                     # Optional: icon
)

# Register the action
idaapi.register_action(action_desc)

# Attach the action to the function list context menu
idaapi.attach_action_to_popup(
    idaapi.get_current_widget(),
    None,
    'my:action',
    'Function Info'
)
