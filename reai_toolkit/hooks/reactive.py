import time

import ida_funcs
import ida_kernwin as kw
import idaapi
from loguru import logger

from reai_toolkit.app.app import App
from reai_toolkit.app.services.rename.schema import RenameInput

# ---- Add this: a small event router ----
def _is_func_ea(ea: int) -> bool:
    return ida_funcs.get_func(ea) is not None


# Reactive Hooks to function changes
class FuncChangeHooks(idaapi.IDB_Hooks):
    def __init__(self, app: App):
        super().__init__()
        self.app: App = app

    # Hook called when a function is renamed
    def renamed(self, ea, new_name, local_name):
        if _is_func_ea(ea):
            self._function_rename(ea, new_name)
        return 0

    def _function_rename(self, ea: int, new_name: str):
        if not self.app.analysis_sync_service.is_worker_running():
            self.app.rename_service.enqueue_rename(
                [RenameInput(ea=ea, new_name=new_name)]
            )


class ChatContextHooks(kw.UI_Hooks):
    def __init__(self, coordinator):
        super().__init__()
        self.coordinator = coordinator
        self._last_func_start = None
        self._is_hooked = False

    def hook(self) -> bool:
        if self._is_hooked:
            return False
        ok = super().hook()
        if ok:
            self._is_hooked = True
            func = ida_funcs.get_func(kw.get_screen_ea())
            self._last_func_start = func.start_ea if func else None
        return ok

    def unhook(self) -> None:
        if self._is_hooked:
            super().unhook()
            self._is_hooked = False
        self._last_func_start = None

    def screen_ea_changed(self, ea: int, prev_ea: int) -> None:
        func = ida_funcs.get_func(ea)
        if not func or func.start_ea == self._last_func_start:
            return
        self._last_func_start = func.start_ea
        try:
            self.coordinator.on_screen_function_changed(func.start_ea)
        except Exception as e:
            logger.error(f"[ChatContextHooks] context update failed: {e}")


ATTRIBUTION_BG_COLOR = 0xFF000000 | 0x63_4A_3D


class LineAttributionHooks(kw.UI_Hooks):
    """
    Paints the disassembly lines a decompiled line was attributed to, and
    reports cursor movement in the disassembly so the panel can light the
    matching decompilation lines.

    Rendering is transient: nothing is written to the IDB.
    """

    def __init__(self, coordinator):
        super().__init__()
        self.coordinator = coordinator
        self._addresses: frozenset[int] = frozenset()
        self._is_hooked = False

    def hook(self) -> bool:
        if self._is_hooked:
            return False
        self._is_hooked = super().hook()
        return self._is_hooked

    def unhook(self) -> None:
        if self._is_hooked:
            super().unhook()
            self._is_hooked = False
        self._addresses = frozenset()

    def set_addresses(self, addresses) -> None:
        self._addresses = frozenset(addresses)

    def has_addresses(self) -> bool:
        return bool(self._addresses)

    def get_lines_rendering_info(self, out, widget, rin) -> None:
        if not self._addresses:
            return
        if kw.get_widget_type(widget) != idaapi.BWN_DISASM:
            return
        for section in rin.sections_lines:
            for line in section:
                if line.at.toea() in self._addresses:
                    out.entries.push_back(
                        kw.line_rendering_output_entry_t(
                            line, kw.LROEF_FULL_LINE, ATTRIBUTION_BG_COLOR
                        )
                    )

    def screen_ea_changed(self, ea: int, prev_ea: int) -> None:
        try:
            self.coordinator.on_disassembly_ea(ea)
        except Exception as e:
            logger.debug(f"[LineAttributionHooks] reverse highlight failed: {e}")


class AiDecompFunctionViewHooks(kw.UI_Hooks):
    """
    Hook that tracks when the screen EA changes (user moves between functions),
    with debounce to avoid excessive refreshes.

    Works entirely on the IDA main thread.
    """

    # AiDecompCoordinator - cannot import due to circular dependency

    def __init__(self, coordinator, debounce_ms: int = 500):
        super().__init__()
        self.coordinator = coordinator
        self._debounce_ms = debounce_ms
        self._last_func_start = None
        self._pending_ea = None
        self._last_change_time = 0.0
        self._timer_id = None
        self._is_hooked = False

    # --------------------------------------------------------
    # Lifecycle
    # --------------------------------------------------------

    def hook(self) -> bool:
        """Register this UI hook."""
        if self._is_hooked:
            return False
        ok = super().hook()
        if ok:
            # First hook, does not trigger event. Manual call to coordinator.
            self._is_hooked = True
            func = ida_funcs.get_func(kw.get_screen_ea())
            if func is not None:
                self._last_func_start = func.start_ea
                self.coordinator.start_decompilation(ea=func.start_ea)
            logger.debug("[FunctionViewHooks] Hook registered.")
        else:
            logger.error("[FunctionViewHooks] Failed to register.")
        return ok

    def unhook(self) -> None:
        """Unregister the hook and clear any timers."""
        if self._timer_id:
            idaapi.unregister_timer(self._timer_id)
            self._timer_id = None
        if self._is_hooked:
            super().unhook()
            self._is_hooked = False
            logger.debug("[FunctionViewHooks] Hook removed.")
        self._pending_ea = None
        self._last_func_start = None

    # --------------------------------------------------------
    # Event Handling
    # --------------------------------------------------------

    def screen_ea_changed(self, ea: int, prev_ea: int) -> None:
        """
        Triggered when the user moves the cursor to a new address.
        Debounced to detect actual function changes only.
        """
        func = ida_funcs.get_func(ea)
        if not func:
            return

        start = func.start_ea
        if start == self._last_func_start:
            return  # same function, ignore

        # record and schedule debounce check
        self._pending_ea = start
        self._last_change_time = time.time()

        if not self._timer_id:
            self._timer_id = idaapi.register_timer(
                self._debounce_ms, self._check_debounce
            )

    def _check_debounce(self):
        """Timer callback; runs on the main thread."""
        now = time.time()

        # Wait until no changes for the debounce interval
        if self._pending_ea and (now - self._last_change_time) >= (
            self._debounce_ms / 1000.0
        ):
            ea = self._pending_ea
            self._pending_ea = None
            self._timer_id = None
            self._last_func_start = ea

            logger.debug(f"[FunctionViewHooks] Function changed (debounced): {hex(ea)}")

            try:
                # Delegate to coordinator
                self.coordinator.start_decompilation(ea=ea)
            except Exception as e:
                logger.error(f"[FunctionViewHooks] Callback failed: {e}")
            return -1  # stop timer

        return 1  # keep timer alive until debounce passes
