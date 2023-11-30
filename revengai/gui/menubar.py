import ida_kernwin
from revengai.logger import plugin_logger


class ConfigBar:
    """
    Contains the logic to create the configuration menu bar, creates the handlers and attaches
    the associated functions to them.
    """

    def __init__(self, form, endpoint, config_handler_class) -> None:
        # For some reason we cannot add the anything to the top-level menu bar so
        # we will add it to the View menu for the time being.
        ida_kernwin.create_menu("configmenu", "RevEng.ai", "View")

        # API endpoint
        self._endpoint = endpoint

        # create action and register it to the menu
        ACTION_CONFIG = "config_action_0"

        config_action = ida_kernwin.action_desc_t(
            ACTION_CONFIG, "Configuration", config_handler_class(form)
        )

        # register action
        if not ida_kernwin.register_action(config_action):
            plugin_logger.error(f"failed to register {config_handler_class.__name__}")

        if not ida_kernwin.attach_action_to_menu(
            "View/RevEng.ai/", ACTION_CONFIG, ida_kernwin.SETMENU_INS
        ):
            plugin_logger.error("failed to attach config action to menu")
