import json
import os
import sys
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


CODE = "int f(int a1) {\n    int v5 = a1;\n    return v5;\n}"
TOK = "int @@F@@(int @@A@@) {\n    int @@V@@ = @@A@@;\n    return @@V@@;\n}"


def _run(report: dict) -> None:
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    import ida_kernwin
    import idautils

    from revengai.models.comments_data import CommentsData
    from revengai.models.decompilation_data import DecompilationData
    from revengai.models.get_tokens_response import GetTokensResponse
    from revengai.models.inline_comment import InlineComment
    from revengai.models.rendered_token import RenderedToken

    from revengai.models.summary_data import SummaryData

    from reai_toolkit.app.components.tabs.ai_decomp_tab import AIDecompView, _is_identifier
    from reai_toolkit.app.coordinators.ai_decomp_coordinator import AiDecompCoordinator
    from reai_toolkit.app.coordinators.ai_decomp_render import (
        RENAME_IS_DATA_TYPE,
        RENAME_NOT_CODE_LINE,
        RENAME_UNRESOLVED,
    )
    from reai_toolkit.app.core.qt_compat import QtWidgets
    from reai_toolkit.app.core.shared_schema import GenericApiReturn

    answers = {"str": "count", "text": "hello"}
    ida_kernwin.ask_str = lambda default, hist, prompt: answers["str"]
    ida_kernwin.ask_text = lambda maxsz, default, prompt: answers["text"]

    ea = next(iter(idautils.Functions()), 0x1000)

    decomp = DecompilationData.model_construct(status="COMPLETED", decompilation=CODE)
    def _rt(value, kind, **ids):
        return RenderedToken.model_construct(
            value=value,
            kind=kind,
            vaddr=None,
            data_type_id=ids.get("data_type_id"),
            function_id=ids.get("function_id"),
            imported_function_id=ids.get("imported_function_id"),
        )

    tokenised = GetTokensResponse.model_construct(
        ai_decomp=TOK,
        analysis_id=1,
        placeholder_to_rendered_token={
            "@@A@@": _rt("a1", "param"),
            "@@V@@": _rt("v5", "local"),
        },
        placeholder_to_user_override={},
    )

    typed = GetTokensResponse.model_construct(
        ai_decomp="@@T@@ *x;",
        analysis_id=1,
        placeholder_to_rendered_token={"@@T@@": _rt("Foo", "type", data_type_id=7)},
        placeholder_to_user_override={},
    )
    typed_decomp = DecompilationData.model_construct(
        status="COMPLETED", decompilation="Foo *x;"
    )

    service = MagicMock()
    service.peek_decomp.return_value = None
    factory = SimpleNamespace(
        ai_decomp=lambda on_closed: AIDecompView(on_closed=on_closed)
    )
    coord = AiDecompCoordinator(
        app=MagicMock(), factory=factory, log=MagicMock(), ai_decomp_service=service
    )
    infos: list = []
    coord.show_info_dialog = lambda **kw: infos.append(kw)
    coord.show_error_dialog = lambda **kw: infos.append(kw)

    qapp = QtWidgets.QApplication.instance()

    def pump() -> None:
        if qapp is not None:
            for _ in range(5):
                qapp.processEvents()

    coord.run_dialog()
    pump()
    view = coord._decomp_view
    if view is None or view._editor is None:
        report["errors"].append("AIDecompView editor was not created")
        return
    report["view_created"] = True
    report["editor_read_only"] = view._editor.isReadOnly() is True
    report["only_identifiers_offer_rename"] = (
        _is_identifier("v5")
        and not _is_identifier("   ")
        and not _is_identifier(";")
        and not _is_identifier("")
    )

    def seed_plain() -> None:
        service.reset_mock()
        service.peek_decomp.return_value = None
        coord._current_func_vaddr = ea
        coord._current_summary = None
        coord._current_comments = None
        coord._current_decomp = decomp
        coord._current_tokenised = tokenised
        coord._rerender()
        pump()

    def seed_with_comment() -> None:
        service.reset_mock()
        service.peek_decomp.return_value = None
        coord._current_func_vaddr = ea
        coord._current_summary = None
        coord._current_decomp = decomp
        coord._current_tokenised = tokenised
        coord._on_comments_complete(
            ea,
            GenericApiReturn(
                success=True,
                data=CommentsData.model_construct(
                    inline_comments=[InlineComment.model_construct(comment="hola", line=2)],
                    task_status="COMPLETED",
                ),
            ),
        )
        pump()

    def code_line_row(needle: str) -> int:
        lines = view._editor.toPlainText().split("\n")
        return next(i for i, s in enumerate(lines) if needle in s)

    seed_plain()
    report["render_shows_code"] = CODE in view._editor.toPlainText()

    seed_plain()
    answers["str"] = "count"
    view._editor.renameRequested.emit(code_line_row("int v5"), "v5")
    pump()
    report["rename_double_click_overrides"] = service.apply_overrides.called
    if service.apply_overrides.called:
        report["rename_overrides_correct"] = (
            service.apply_overrides.call_args.kwargs.get("overrides") == {"@@V@@": "count"}
        )

    seed_plain()
    infos.clear()
    view._editor.renameRequested.emit(0, "int")
    pump()
    report["rename_non_token_info"] = not service.apply_overrides.called and len(infos) >= 1
    report["rename_non_token_reason"] = infos[:1] == [
        {"msg": RENAME_UNRESOLVED.format(word="int")}
    ]

    seed_with_comment()
    infos.clear()
    view._editor.renameRequested.emit(code_line_row("// hola"), "hola")
    pump()
    report["rename_comment_line_reason"] = infos[:1] == [{"msg": RENAME_NOT_CODE_LINE}]

    seed_plain()
    coord._current_decomp = typed_decomp
    coord._current_tokenised = typed
    coord._rerender()
    pump()
    infos.clear()
    view._editor.renameRequested.emit(code_line_row("Foo *x;"), "Foo")
    pump()
    report["rename_data_type_reason"] = infos[:1] == [
        {"msg": RENAME_IS_DATA_TYPE.format(word="Foo")}
    ]

    seed_plain()
    report["predicted_hidden_without_a_prediction"] = view._predicted_btn.isHidden()
    coord._on_summary_complete(
        ea,
        GenericApiReturn(
            success=True,
            data=SummaryData.model_construct(
                ai_summary=None,
                summary=None,
                predicted_function_name="do_thing",
                task_status="COMPLETED",
            ),
        ),
    )
    pump()
    report["predicted_shown_with_a_prediction"] = (
        not view._predicted_btn.isHidden()
        and "do_thing" in view._predicted_label.text()
    )

    view._predicted_btn.click()
    pump()
    report["predicted_button_renames"] = (
        service.update_function_name.call_args is not None
        and service.update_function_name.call_args.args == (ea, "do_thing")
    )

    view.set_predicted_name(None)
    pump()
    report["predicted_hidden_when_cleared"] = view._predicted_btn.isHidden()

    seed_plain()
    answers["text"] = "hello"
    view._editor.commentEditRequested.emit(code_line_row("int v5"))
    pump()
    report["comment_add_sets"] = service.set_comment.called
    if service.set_comment.called:
        kw = service.set_comment.call_args.kwargs
        report["comment_add_args_correct"] = kw.get("line") == 2 and kw.get("comment") == "hello"

    seed_with_comment()
    answers["text"] = ""
    view._editor.commentEditRequested.emit(code_line_row("int v5"))
    pump()
    report["comment_edit_empty_removes"] = (
        service.remove_comment.called
        and service.remove_comment.call_args.kwargs.get("line") == 2
    )

    seed_with_comment()
    view._editor.commentRemoveRequested.emit(code_line_row("int v5"))
    pump()
    report["comment_remove_deletes"] = service.remove_comment.called
    if service.remove_comment.called:
        report["comment_remove_args_correct"] = (
            service.remove_comment.call_args.kwargs.get("line") == 2
        )

    service.reset_mock()
    service.peek_decomp.return_value = None
    view._refresh_btn.click()
    pump()
    report["refresh_button_invalidates"] = service.invalidate_ea.called

    report["ok"] = not report["errors"]


def main() -> None:
    import ida_auto
    import ida_pro

    report = {
        "ok": False,
        "errors": [],
        "view_created": False,
        "editor_read_only": False,
        "only_identifiers_offer_rename": False,
        "render_shows_code": False,
        "rename_double_click_overrides": False,
        "rename_overrides_correct": False,
        "rename_non_token_info": False,
        "rename_non_token_reason": False,
        "rename_comment_line_reason": False,
        "rename_data_type_reason": False,
        "predicted_hidden_without_a_prediction": False,
        "predicted_shown_with_a_prediction": False,
        "predicted_button_renames": False,
        "predicted_hidden_when_cleared": False,
        "comment_add_sets": False,
        "comment_add_args_correct": False,
        "comment_edit_empty_removes": False,
        "comment_remove_deletes": False,
        "comment_remove_args_correct": False,
        "refresh_button_invalidates": False,
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
