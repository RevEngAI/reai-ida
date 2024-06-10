# -*- coding: utf-8 -*-
from os.path import dirname, join

from idaapi import load_custom_icon, free_custom_icon

from revengai.conf import RevEngConfiguration, ProjectConfiguration


class RevEngState(object):
    def __init__(self):
        self.gui = None
        self.icon_id = 0
        self.config = RevEngConfiguration()
        self.project_cfg = ProjectConfiguration()

    def start_plugin(self):
        self.icon_id = load_custom_icon(file_name=join(dirname(__file__), "resources/favicon.png"),
                                        format="png")

        from revengai.ida_ui import RevEngGUI

        self.gui = RevEngGUI(self)

        self.gui.show_windows()

    def stop_plugin(self):
        if self.gui:
            # Free the custom icon
            if self.icon_id:
                free_custom_icon(self.icon_id)

            self.gui.term()
            self.gui = None
            self.icon_id = 0
