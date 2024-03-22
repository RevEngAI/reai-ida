from revengai.conf import RevEngConfiguration


class RevEngState(object):
    def __init__(self, reai_config: RevEngConfiguration):
        self.gui = None
        self.reai_config = reai_config

    def start_plugin(self):
        from revengai.ida_ui import RevEngGUI
        
        self.gui = RevEngGUI(self)
        self.gui.show_windows()

    def stop_plugin(self):
        if self.gui:
            self.gui.term()
            self.gui = None
