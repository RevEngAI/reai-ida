import json
import os
import sys
import threading
import traceback


def _add_paths() -> None:
    root = os.environ["REAI_UI_ROOT"]
    pyver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    suffixes = [
        "vendor",
        "vendor/site-packages",
        "vendor/Lib/site-packages",
        f"vendor/lib/{pyver}/site-packages",
        f"vendor/{pyver}/site-packages",
    ]
    for base in (root, os.path.join(root, "reai_toolkit")):
        for suffix in suffixes:
            path = os.path.join(base, suffix)
            if os.path.isdir(path) and path not in sys.path:
                sys.path.insert(0, path)
    if root not in sys.path:
        sys.path.insert(0, root)


def _run(report: dict) -> None:
    import time

    from reai_toolkit.app.components.tabs.chat_tab import ChatPanel, ChatStreamWorker
    from reai_toolkit.app.core.qt_compat import QtCore, QtGui, QtWidgets
    from reai_toolkit.app.core.shared_schema import GenericApiReturn
    from reai_toolkit.app.services.chat.reducer import (
        EventAction,
        SendMessage,
        chat_reducer,
        initial_state,
    )
    from reai_toolkit.app.services.chat.schema import ChatEvent

    qapp = QtWidgets.QApplication.instance()

    def pump(rounds: int = 10) -> None:
        if qapp is not None:
            for _ in range(rounds):
                qapp.processEvents()

    def pump_until(predicate, timeout: float = 10.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pump()
            if predicate():
                return True
            time.sleep(0.01)
        return predicate()

    panel = ChatPanel(on_closed=lambda: None)
    panel.Create(ChatPanel.TITLE)
    pump()

    if panel._transcript is None or panel._input is None:
        report["errors"].append("ChatPanel widgets were not created")
        return

    report["panel_created"] = True
    report["bridge_is_a_qobject"] = isinstance(panel._bridge, QtCore.QObject)
    report["relay_is_a_qobject"] = isinstance(panel._relay, QtCore.QObject)
    report["relay_lives_on_the_ui_thread"] = (
        panel._relay.thread() is QtCore.QThread.currentThread()
    )

    fired: list = []
    panel.on_send = lambda text: fired.append(("send", text))
    panel.on_stop = lambda: fired.append(("stop", None))
    panel.on_new_chat = lambda: fired.append(("new_chat", None))
    panel.on_request_history = lambda: fired.append(("history", None))
    panel.on_confirm = lambda cid, ok: fired.append(("confirm", (cid, ok)))
    panel.on_select_conversation = lambda uuid: fired.append(("select", uuid))
    panel.on_jump = lambda ea: fired.append(("jump", ea))

    panel._input.setPlainText("what does this do?")
    panel._send_btn.click()
    pump()
    report["send_button_routes_through_the_bridge"] = fired[-1:] == [
        ("send", "what does this do?")
    ]
    report["send_clears_the_input"] = panel._input.toPlainText() == ""

    fired.clear()
    panel._stop_btn.setEnabled(True)
    panel._stop_btn.click()
    pump()
    report["stop_button_routes_through_the_bridge"] = fired[-1:] == [("stop", None)]

    fired.clear()
    panel._input.setPlainText("   ")
    panel._send_btn.click()
    pump()
    report["blank_input_sends_nothing"] = fired == []
    panel._input.clear()

    fired.clear()
    panel._input.setPlainText("typed")
    panel._input.keyPressEvent(
        QtGui.QKeyEvent(
            QtCore.QEvent.KeyPress, QtCore.Qt.Key_Return, QtCore.Qt.NoModifier
        )
    )
    pump()
    report["enter_submits_through_the_bridge"] = fired[-1:] == [("send", "typed")]

    state = initial_state()
    state = chat_reducer(state, SendMessage(id="u1", content="hello there"))
    state = chat_reducer(
        state, EventAction(ChatEvent(type="TITLE_UPDATED", title="A Conversation"))
    )
    panel.request_render(state)
    report["render_is_deferred_to_the_timer"] = panel._render_timer.isActive()
    pump_until(lambda: not panel._render_timer.isActive())
    report["timer_flush_reaches_the_transcript"] = (
        "hello there" in panel._transcript.toPlainText()
    )
    report["timer_flush_updates_the_title"] = panel._title_label.text() == "A Conversation"

    confirming = chat_reducer(
        state,
        EventAction(
            ChatEvent(
                type="TOOL_CONFIRMATION_REQUIRED",
                tool_call_id="tc1",
                tool_name="rename_functions",
                message="Rename 3 functions?",
            )
        ),
    )
    panel.request_render(confirming)
    pump_until(lambda: not panel._render_timer.isActive())
    report["confirmation_shows_its_bar"] = (
        not panel._confirm_bar.isHidden() and "Rename 3" in panel._confirm_msg.text()
    )

    fired.clear()
    panel._confirm_bar.findChildren(QtWidgets.QPushButton)[0].click()
    pump()
    report["approve_routes_with_the_pending_id"] = fired[-1:] == [
        ("confirm", ("tc1", True))
    ]

    events = [
        ChatEvent(type="TEXT_MESSAGE_START", message_id="m1", role="assistant"),
        ChatEvent(type="TEXT_MESSAGE_CONTENT", message_id="m1", delta="streamed"),
        ChatEvent(type="TEXT_MESSAGE_END", message_id="m1"),
        ChatEvent(type="RUN_FINISHED"),
    ]

    class _FakeService:
        def __init__(self):
            self.closed = False

        def create_conversation(self, context):
            return GenericApiReturn(success=True, data="conv-uuid")

        def send_message(self, conv_id, content, context):
            return GenericApiReturn(success=True)

        def stream(self, conv_id, stop_event, last_event_id=None):
            for event in events:
                if stop_event.is_set():
                    return
                yield event

        def close_active_stream(self):
            self.closed = True

    seen: list = []
    threads: list = []
    created: list = []
    finished: list = []
    panel.on_stream_event = lambda ev: (
        seen.append(ev.type),
        threads.append(threading.current_thread()),
    )
    panel.on_stream_conversation_created = lambda uuid: created.append(uuid)
    panel.on_stream_finished = lambda: finished.append(True)
    panel.on_stream_error = lambda msg: report["errors"].append(f"stream errored: {msg}")

    worker = ChatStreamWorker(_FakeService(), None, "hello", None)
    panel.start_stream_worker(worker)
    report["worker_reports_streaming"] = panel.is_streaming()

    pump_until(lambda: bool(finished))

    report["every_streamed_event_arrives"] = seen == [e.type for e in events]
    report["stream_callbacks_run_on_the_ui_thread"] = bool(threads) and all(
        t is threading.main_thread() for t in threads
    )
    report["conversation_id_reaches_the_panel"] = created == ["conv-uuid"]
    report["stream_finish_clears_streaming"] = not panel.is_streaming()

    class _BlockingService(_FakeService):
        def stream(self, conv_id, stop_event, last_event_id=None):
            while not stop_event.is_set():
                time.sleep(0.01)
            yield from ()

    blocking = _BlockingService()
    panel.start_stream_worker(ChatStreamWorker(blocking, "conv", None, None))
    pump()
    started = time.monotonic()
    panel.stop_stream_worker()
    report["stop_returns_promptly"] = (time.monotonic() - started) < 3.0
    report["stop_closes_the_active_stream"] = blocking.closed
    report["stop_leaves_no_zombie_thread"] = panel._zombies == []

    panel.Close(0)
    pump()
    report["ok"] = not report["errors"]


def main() -> None:
    import ida_auto
    import ida_pro

    report = {
        "ok": False,
        "errors": [],
        "panel_created": False,
        "bridge_is_a_qobject": False,
        "relay_is_a_qobject": False,
        "relay_lives_on_the_ui_thread": False,
        "send_button_routes_through_the_bridge": False,
        "send_clears_the_input": False,
        "stop_button_routes_through_the_bridge": False,
        "blank_input_sends_nothing": False,
        "enter_submits_through_the_bridge": False,
        "render_is_deferred_to_the_timer": False,
        "timer_flush_reaches_the_transcript": False,
        "timer_flush_updates_the_title": False,
        "confirmation_shows_its_bar": False,
        "approve_routes_with_the_pending_id": False,
        "worker_reports_streaming": False,
        "every_streamed_event_arrives": False,
        "stream_callbacks_run_on_the_ui_thread": False,
        "conversation_id_reaches_the_panel": False,
        "stream_finish_clears_streaming": False,
        "stop_returns_promptly": False,
        "stop_closes_the_active_stream": False,
        "stop_leaves_no_zombie_thread": False,
    }
    ida_auto.auto_wait()
    try:
        _add_paths()
        _run(report)
    except Exception:
        report["errors"].append(traceback.format_exc())
    with open(os.environ["REAI_UI_REPORT"], "w") as fh:
        json.dump(report, fh)
    ida_pro.qexit(0)


main()
