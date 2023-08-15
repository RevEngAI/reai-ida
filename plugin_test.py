import idaapi

class MyPlugin(idaapi.plugin_t):
    flags = 0
    comment = "This is my custom plugin"
    help = "This plugin does something amazing"
    wanted_name = "MyPlugin"
    wanted_hotkey = ""

    def init(self):
        print("MyPlugin: Initialized")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        print("MyPlugin: Running!")
        # Here you can call your IDAPython script or whatever code you want to execute

    def term(self):
        print("MyPlugin: Terminated")

def PLUGIN_ENTRY():
    return MyPlugin()
