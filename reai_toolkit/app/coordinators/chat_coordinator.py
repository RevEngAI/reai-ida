"""Agent Chat coordinator.

Owns the :class:`ChatState`, the active conversation id, and the streaming worker
lifecycle; wires the dockable :class:`ChatPanel` to the :class:`ChatService`. The
panel is a dumb renderer — every state transition goes through the pure
``chat_reducer`` here, mirroring the Dashboard's ``useChat`` hook.
"""

from __future__ import annotations

import threading
import uuid
from logging import Logger
from typing import TYPE_CHECKING, Optional

import ida_funcs
import ida_kernwin
import ida_name
from libbs.decompilers.ida.compat import execute_read, execute_ui

from reai_toolkit.app.app import App
from reai_toolkit.app.components.tabs.chat_tab import ChatPanel, ChatStreamWorker
from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.factory import DialogFactory
from reai_toolkit.app.services.chat.chat_service import ChatService
from reai_toolkit.app.services.chat.reducer import (
    ApiError,
    Cancel,
    ConfirmTool,
    EventAction,
    SendMessage,
    build_initial_state,
    chat_reducer,
    initial_state,
)
from reai_toolkit.app.services.chat.schema import (
    ChatState,
    ConversationContextDTO,
)
from reai_toolkit.hooks.reactive import ChatContextHooks

if TYPE_CHECKING:
    from reai_toolkit.app.coordinators.ai_decomp_coordinator import AiDecompCoordinator

AI_DECOMP_TOOL_HINTS = ("decomp",)
EDIT_FUNCTION_TYPES_TOOL = "edit_function_types"
DATA_TYPES_SYNC_DEBOUNCE_S = 0.5


class ChatCoordinator(BaseCoordinator):
    def __init__(
        self,
        *,
        app: "App",
        factory: "DialogFactory",
        log: Logger,
        chat_service: ChatService,
        ai_decomp_coord: "Optional[AiDecompCoordinator]" = None,
    ) -> None:
        super().__init__(app=app, factory=factory, log=log)
        self.chat_service: ChatService = chat_service
        self._ai_decomp_coord: "Optional[AiDecompCoordinator]" = ai_decomp_coord
        self._panel: Optional[ChatPanel] = None
        self._state: ChatState = initial_state()
        self._conversation_id: Optional[str] = None
        self._last_event_id: Optional[int] = None
        self._last_context: Optional[ConversationContextDTO] = None
        self._context_hooks: Optional[ChatContextHooks] = None
        self._pending_type_ids: set[int] = set()
        self._type_sync_timer: Optional[threading.Timer] = None
        self._type_sync_lock = threading.Lock()

    @execute_ui
    def run_dialog(self, prefill_context: bool = False) -> None:
        if self._panel is None:
            self._panel = self.factory.chat(on_closed=self._on_pane_closed)
            self._wire_panel(self._panel)
            self._panel.Create(self._panel.TITLE)
            self._enable_context_tracking()
        self._panel.focus()
        self._update_context_chip()
        if prefill_context:
            self._panel.focus_input()

        if self._conversation_id is None and not self._state.items:
            last = self._get_persisted_conversation()
            if last:
                self.load_conversation(last)
                return
        self._render()

    def _wire_panel(self, panel: ChatPanel) -> None:
        panel.on_send = self.send
        panel.on_stop = self.stop
        panel.on_confirm = self.confirm_tool
        panel.on_new_chat = self.new_conversation
        panel.on_select_conversation = self.load_conversation
        panel.on_request_history = self.request_history
        panel.on_jump = self.jump_to
        panel.on_stream_event = self.on_stream_event
        panel.on_stream_conversation_created = self.on_stream_conversation_created
        panel.on_stream_error = self.on_stream_error
        panel.on_stream_finished = self.on_stream_finished

    def _on_pane_closed(self) -> None:
        if self._panel is not None:
            self._panel.stop_stream_worker()
        with self._type_sync_lock:
            if self._type_sync_timer is not None:
                self._type_sync_timer.cancel()
                self._type_sync_timer = None
            self._pending_type_ids.clear()
        self._disable_context_tracking()
        self._panel = None
        self.log.info("Agent Chat panel closed.")

    def _enable_context_tracking(self) -> None:
        if self._context_hooks is None:
            self._context_hooks = ChatContextHooks(self)
            self._context_hooks.hook()

    def _disable_context_tracking(self) -> None:
        if self._context_hooks is not None:
            self._context_hooks.unhook()
            self._context_hooks = None

    def on_screen_function_changed(self, ea: int) -> None:
        self._update_context_chip(ea)

    def send(self, text: str) -> None:
        content = (text or "").strip()
        if not content or self._state.run_status == "running":
            return
        self._state = chat_reducer(
            self._state, SendMessage(id=uuid.uuid4().hex, content=content)
        )
        self._render()

        context = self._resolve_context()
        self._last_context = context
        self._update_context_chip()
        worker = ChatStreamWorker(
            chat_service=self.chat_service,
            conversation_id=self._conversation_id,
            content=content,
            context=context,
            last_event_id=None,
        )
        if self._panel is not None:
            self._panel.start_stream_worker(worker)

    def stop(self) -> None:
        if self._panel is not None:
            self._panel.stop_stream_worker()
        self._state = chat_reducer(self._state, Cancel())
        self._render()
        if self._conversation_id:
            self._post_async(self.chat_service.cancel_run, self._conversation_id)

    def confirm_tool(self, tool_call_id: str, approved: bool) -> None:
        self._state = chat_reducer(
            self._state, ConfirmTool(id=tool_call_id, approved=approved)
        )
        self._render()
        if not self._conversation_id:
            return
        self._post_async(self.chat_service.confirm_tool, self._conversation_id, approved)
        if (
            approved
            and self._panel is not None
            and not self._panel.is_streaming()
        ):
            worker = ChatStreamWorker(
                chat_service=self.chat_service,
                conversation_id=self._conversation_id,
                content=None,
                context=self._resolve_context(),
                last_event_id=self._last_event_id,
            )
            self._panel.start_stream_worker(worker)

    def new_conversation(self) -> None:
        if self._panel is not None:
            self._panel.stop_stream_worker()
        self._conversation_id = None
        self._last_event_id = None
        self._state = initial_state()
        self._render()

    def load_conversation(self, conversation_uuid: str) -> None:
        if self._panel is not None:
            self._panel.stop_stream_worker()

        def _work() -> None:
            res = self.chat_service.get_conversation(conversation_uuid)
            if not res.success or res.data is None:
                if res.error_message:
                    self.show_error_dialog(message=res.error_message)
                return
            replay = res.data
            state = build_initial_state(replay.events)
            state.title = replay.title
            self._apply_loaded_state(conversation_uuid, state)

        threading.Thread(target=_work, daemon=True).start()

    def request_history(self) -> None:
        def _work() -> None:
            res = self.chat_service.list_conversations()
            if res.success and res.data is not None:
                self._set_history(res.data)
            elif res.error_message:
                self.log.warning(f"Failed to list conversations: {res.error_message}")

        threading.Thread(target=_work, daemon=True).start()

    def on_stream_event(self, ev) -> None:
        self._state = chat_reducer(self._state, EventAction(ev))
        if ev.event_id is not None:
            self._last_event_id = ev.event_id
        if ev.type == "TOOL_CALL_RESULT" and not ev.is_error:
            self._handle_tool_result(ev)
        self._render()

    def on_stream_conversation_created(self, conversation_uuid: str) -> None:
        self._conversation_id = conversation_uuid
        self._persist_conversation(conversation_uuid)

    def on_stream_error(self, msg: str) -> None:
        self._state = chat_reducer(self._state, ApiError(message=msg))
        self._render()

    def on_stream_finished(self) -> None:
        self._render()

    def _handle_tool_result(self, ev) -> None:
        if ev.updated:
            func_ids = [i for u in ev.updated if u.type == "function" for i in u.ids]
            if func_ids and self._is_edit_types_tool(ev):
                self._sync_data_types(func_ids)
            elif func_ids:
                self._sync_functions(func_ids)
            elif any(u.type == "analysis" for u in ev.updated):
                self.refresh_disassembly_view()
        self._maybe_open_viewer(ev)

    @staticmethod
    def _is_edit_types_tool(ev) -> bool:
        return (ev.tool_name or "").lower() == EDIT_FUNCTION_TYPES_TOOL

    def _sync_data_types(self, func_ids: list) -> None:
        with self._type_sync_lock:
            self._pending_type_ids.update(int(f) for f in func_ids)
            if self._type_sync_timer is not None:
                self._type_sync_timer.cancel()
            self._type_sync_timer = threading.Timer(
                DATA_TYPES_SYNC_DEBOUNCE_S, self._flush_data_types
            )
            self._type_sync_timer.daemon = True
            self._type_sync_timer.start()

    def _flush_data_types(self) -> None:
        with self._type_sync_lock:
            ids = list(self._pending_type_ids)
            self._pending_type_ids.clear()
            self._type_sync_timer = None
        if not ids:
            return
        func_map = self.app.netstore_service.get_function_mapping()
        if func_map is None:
            return
        matches: dict[int, int] = {}
        for fid in ids:
            ea = func_map.function_map.get(str(fid))
            if ea is not None:
                matches[fid] = ea
        if not matches:
            return
        result = self.app.data_types_service.import_data_types(matches)
        if result.error:
            self.log.warning(f"Failed to sync data types: {result.error}")
            return
        self.refresh_disassembly_view()
        last_ea = next(iter(matches.values()))
        self._refresh_context_chip(last_ea)
        if self._ai_decomp_coord is not None:
            self._ai_decomp_coord.follow_function(last_ea)

    def _sync_functions(self, func_ids: list) -> None:
        def _work() -> None:
            func_map = self.app.netstore_service.get_function_mapping()
            if func_map is None:
                return
            applied = False
            last_ea: Optional[int] = None
            for fid in func_ids:
                ea = func_map.function_map.get(str(fid))
                if ea is None:
                    continue
                res = self.chat_service.get_function_name(fid)
                if not res.success or not res.data:
                    continue
                name = res.data
                if self.chat_service.update_function_name(ea, name):
                    self.chat_service.tag_function_as_renamed(name)
                    applied = True
                self.jump_to(ea)
                last_ea = ea
            if applied:
                self.refresh_disassembly_view()
                self._refresh_context_chip(last_ea)
            if last_ea is not None and self._ai_decomp_coord is not None:
                self._ai_decomp_coord.follow_function(last_ea)

        threading.Thread(target=_work, daemon=True).start()

    @execute_ui
    def jump_to(self, ea: int) -> None:
        try:
            ida_kernwin.jumpto(ea)
        except Exception as e:
            self.log.debug(f"jumpto({ea}) failed: {e}")

    def _maybe_open_viewer(self, ev) -> None:
        if self._ai_decomp_coord is None:
            return
        name = (ev.tool_name or "").lower()
        if not any(hint in name for hint in AI_DECOMP_TOOL_HINTS):
            return
        if not self._ai_decomp_coord.is_tracking():
            self._ai_decomp_coord.ensure_tracking()
        func_map = self.app.netstore_service.get_function_mapping()
        if func_map is None:
            return
        target_ids = [i for u in (ev.updated or []) if u.type == "function" for i in u.ids]
        for fid in target_ids:
            ea = func_map.function_map.get(str(fid))
            if ea is not None:
                self._ai_decomp_coord.prefetch_decompilation(ea)

    def _render(self) -> None:
        if self._panel is not None:
            self._panel.request_render(self._state)

    @execute_ui
    def _apply_loaded_state(self, conversation_uuid: str, state: ChatState) -> None:
        self._conversation_id = conversation_uuid
        self._state = state
        self._last_event_id = None
        self._persist_conversation(conversation_uuid)
        self._render()

    @execute_ui
    def _set_history(self, summaries) -> None:
        if self._panel is not None:
            self._panel.set_history(summaries)

    @execute_read
    def _resolve_context(self) -> ConversationContextDTO:
        analysis_id = None
        function_id = None
        try:
            analysis_id = self.app.netstore_service.get_analysis_id()
            func_map = self.app.netstore_service.get_function_mapping()
            func = ida_funcs.get_func(ida_kernwin.get_screen_ea())
            if func_map is not None and func is not None:
                function_id = func_map.inverse_function_map.get(str(func.start_ea))
        except Exception as e:
            self.log.debug(f"Failed to resolve chat context: {e}")
        return ConversationContextDTO(analysis_id=analysis_id, function_id=function_id)

    def _update_context_chip(self, ea: Optional[int] = None) -> None:
        if self._panel is not None:
            self._panel.set_context_chip(self._resolve_context_chip_text(ea))

    @execute_ui
    def _refresh_context_chip(self, ea: Optional[int] = None) -> None:
        self._update_context_chip(ea)

    @execute_read
    def _resolve_context_chip_text(self, ea: Optional[int] = None) -> str:
        try:
            analysis_id = self.app.netstore_service.get_analysis_id()
            if ea is None:
                func = ida_funcs.get_func(ida_kernwin.get_screen_ea())
                ea = func.start_ea if func is not None else None
            name = ida_name.get_ea_name(ea) if ea is not None else None
            bits = []
            if name:
                bits.append(f"fn: {name}")
            if analysis_id is not None:
                bits.append(f"analysis #{analysis_id}")
            return "\n".join(bits) if bits else "No analysis attached"
        except Exception:
            return ""

    def _post_async(self, fn, *args) -> None:
        def _work() -> None:
            try:
                res = fn(*args)
                if res is not None and not res.success and res.error_message:
                    self.show_error_dialog(message=res.error_message)
            except Exception as e:
                self.log.warning(f"Async chat request failed: {e}")

        threading.Thread(target=_work, daemon=True).start()

    def _conversation_key(self, analysis_id: int) -> str:
        return f"chat:last_conversation:{analysis_id}"

    def _persist_conversation(self, conversation_uuid: str) -> None:
        try:
            analysis_id = self.app.netstore_service.get_analysis_id()
            if analysis_id is not None:
                self.app.netstore_service.put_global(
                    self._conversation_key(analysis_id), conversation_uuid
                )
        except Exception as e:
            self.log.debug(f"Failed to persist conversation id: {e}")

    def _get_persisted_conversation(self) -> Optional[str]:
        try:
            analysis_id = self.app.netstore_service.get_analysis_id()
            if analysis_id is None:
                return None
            return self.app.netstore_service.get_global(
                self._conversation_key(analysis_id)
            )
        except Exception:
            return None
