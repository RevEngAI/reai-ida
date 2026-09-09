import pytest
from revengai.models.comments_data import CommentsData
from revengai.models.decompilation_data import DecompilationData
from revengai.models.get_tokens_response import GetTokensResponse
from revengai.models.inline_comment import InlineComment
from revengai.models.progress_message import ProgressMessage
from revengai.models.rendered_token import RenderedToken
from revengai.models.summary_data import SummaryData
from revengai.models.token import Token
from revengai.models.workflow_progress import WorkflowProgress

from reai_toolkit.app.coordinators.ai_decomp_render import (
    RENAME_IS_DATA_TYPE,
    RENAME_IS_FUNCTION,
    RENAME_IS_IMPORTED_FUNCTION,
    RENAME_NOT_CODE_LINE,
    RENAME_NOT_DECOMP_LINE,
    RENAME_NOT_ON_LINE,
    RENAME_UNRESOLVED,
    effective_values,
    find_token,
    index_of_identifier,
    names_token,
    render_progress,
    render_stream,
    render_view,
    render_view_with_map,
    resolve_rename_target,
    resolve_token,
)
from reai_toolkit.app.services.ai_decomp.stream import PROSE_TAIL, StreamState


CODE = "int f(int a1) {\n    int v5 = a1;\n    return v5;\n}"
TOK = "int @@F1@@(int @@V_a1@@) {\n    int @@V_v5@@ = @@V_a1@@;\n    return @@V_v5@@;\n}"


def _dd(code=CODE):
    return DecompilationData.model_construct(status="COMPLETED", decompilation=code)


def _summary(text):
    return SummaryData.model_construct(ai_summary=text, summary=text, task_status="COMPLETED")


def _comments(pairs):
    items = [InlineComment.model_construct(comment=c, line=ln) for ln, c in pairs]
    return CommentsData.model_construct(inline_comments=items, task_status="COMPLETED")


def _rt(value, kind="local", **ids):
    return RenderedToken.model_construct(
        value=value,
        kind=kind,
        vaddr=None,
        data_type_id=ids.get("data_type_id"),
        function_id=ids.get("function_id"),
        imported_function_id=ids.get("imported_function_id"),
    )


def _tokens(tok=TOK, rendered=None, overrides=None):
    return GetTokensResponse.model_construct(
        ai_decomp=tok,
        analysis_id=1,
        placeholder_to_rendered_token=rendered if rendered is not None else {},
        placeholder_to_user_override={
            placeholder: Token.model_construct(value=value)
            for placeholder, value in (overrides or {}).items()
        },
    )


_VARS = {"@@V_v5@@": _rt("v5"), "@@V_a1@@": _rt("a1", kind="param")}


def test_render_matches_legacy_and_builds_model():
    comments = _comments([(2, "local copy"), (99, "out of range")])
    text, model = render_view_with_map(_dd(), _summary("Adds one."), comments)

    assert render_view(_dd(), _summary("Adds one."), comments) == text
    assert text.splitlines()[0] == "/*"
    assert "    // local copy" in text
    assert model.summary_line_count == 3
    assert model.code_lines == CODE.split("\n")
    assert model.comment_by_source == {2: "local copy"}


def test_display_maps_align_lines_to_source():
    text, model = render_view_with_map(_dd(), _summary("S."), _comments([(2, "note")]))
    lines = text.split("\n")

    assert len(model.display_source) == len(lines)
    assert len(model.display_is_code) == len(lines)

    for i in range(model.summary_line_count):
        assert model.display_source[i] is None
        assert model.display_is_code[i] is False

    comment_rows = [i for i, s in enumerate(lines) if s.strip().startswith("//")]
    code_rows = [i for i, c in enumerate(model.display_is_code) if c]

    assert len(code_rows) == len(CODE.split("\n"))
    for row in comment_rows:
        assert model.display_is_code[row] is False
        assert model.display_source[row] == 2

    v5_row = next(i for i, s in enumerate(lines) if "int v5" in s)
    assert model.display_is_code[v5_row] is True
    assert model.display_source[v5_row] == 2


def test_no_summary_no_comments_is_raw_code():
    text, model = render_view_with_map(_dd(), None, None)
    assert text == CODE
    assert model.summary_line_count == 0
    assert model.comment_by_source == {}
    assert all(model.display_is_code)
    assert model.display_source == [1, 2, 3, 4]


def test_multiline_comment_renders_as_two_comment_lines():
    text, model = render_view_with_map(_dd(), None, _comments([(2, "line one\nline two")]))
    lines = text.split("\n")
    assert "    // line one" in lines
    assert "    // line two" in lines
    assert model.comment_by_source == {2: "line one\nline two"}


def test_index_of_identifier():
    assert index_of_identifier("    int v5 = a1;", "v5") == 1
    assert index_of_identifier("    int v5 = a1;", "a1") == 2
    assert index_of_identifier("    int v5 = a1;", "missing") == -1


def test_resolve_token_positional_variable():
    assert resolve_token(_tokens(rendered=_VARS), 1, 1, "v5") == ("@@V_v5@@", "local")


def test_resolve_token_picks_the_placeholder_at_that_position_not_a_same_valued_twin():
    rendered = {"@@V_a@@": _rt("dup"), "@@V_b@@": _rt("dup")}
    tokens = _tokens(tok="int @@V_a@@ = @@V_b@@;", rendered=rendered)

    assert resolve_token(tokens, 0, 2, "dup") == ("@@V_b@@", "local")


def test_resolve_token_honours_user_override():
    tokens = _tokens(rendered=_VARS, overrides={"@@V_v5@@": "tmp"})

    assert resolve_token(tokens, 1, 1, "tmp") == ("@@V_v5@@", "local")
    assert resolve_token(tokens, 1, 1, "v5") is None


def test_effective_values_merge_overrides_over_rendered():
    tokens = _tokens(rendered=_VARS, overrides={"@@V_v5@@": "tmp"})

    assert effective_values(tokens) == {"@@V_v5@@": "tmp", "@@V_a1@@": "a1"}


def test_resolve_token_unknown_returns_none():
    assert resolve_token(_tokens(rendered=_VARS), 1, 1, "not_a_var") is None


def test_resolve_token_value_fallback_when_line_unaligned():
    tokens = _tokens(tok="", rendered={"@@V_v5@@": _rt("v5")})

    assert resolve_token(tokens, 1, 1, "v5") == ("@@V_v5@@", "local")


def test_resolve_token_ambiguous_value_fallback_resolves_to_nothing():
    rendered = {"@@V_a@@": _rt("dup"), "@@V_b@@": _rt("dup")}

    assert resolve_token(_tokens(tok="", rendered=rendered), 0, 0, "dup") is None


def test_resolve_token_empty_token_map_returns_none():
    assert resolve_token(_tokens(rendered={}), 1, 1, "v5") is None


@pytest.mark.parametrize(
    "value,ident",
    [("lang_start<()>", "lang_start"), ("Foo::bar", "bar"), ("Foo::bar", "Foo")],
)
def test_identifier_inside_a_qualified_rendered_value_still_resolves(value, ident):
    tokens = _tokens(tok="@@F@@();", rendered={"@@F@@": _rt(value)})

    assert names_token(ident, value)
    assert resolve_token(tokens, 0, 0, ident) == ("@@F@@", "local")


@pytest.mark.parametrize(
    "field", ["data_type_id", "function_id", "imported_function_id"]
)
def test_tokens_renamed_elsewhere_are_declined(field):
    rendered = {"@@X@@": _rt("Foo", kind="type", **{field: 12})}

    assert resolve_token(_tokens(tok="@@X@@ *x;", rendered=rendered), 0, 0, "Foo") is None


@pytest.mark.parametrize(
    "field", ["data_type_id", "function_id", "imported_function_id"]
)
def test_id_zero_is_a_real_id_and_still_declines(field):
    rendered = {"@@X@@": _rt("Foo", kind="type", **{field: 0})}

    assert resolve_token(_tokens(tok="@@X@@ *x;", rendered=rendered), 0, 0, "Foo") is None


def test_find_token_returns_tokens_renamed_elsewhere_even_though_resolve_declines():
    rendered = {"@@X@@": _rt("Foo", kind="type", data_type_id=12)}
    tokens = _tokens(tok="@@X@@ *x;", rendered=rendered)

    placeholder, token = find_token(tokens, 0, 0, "Foo")
    assert placeholder == "@@X@@"
    assert token.data_type_id == 12


def _model(code=CODE, summary=None, comments=None):
    _, model = render_view_with_map(_dd(code), summary, comments)
    return model


def test_rename_target_resolves_a_variable_on_a_code_line():
    target = resolve_rename_target(_model(), _tokens(rendered=_VARS), 1, "v5")

    assert target.placeholder == "@@V_v5@@"
    assert target.kind == "local"
    assert target.reason is None


def test_rename_target_declines_a_line_outside_the_view():
    for display_line in (-1, 99):
        target = resolve_rename_target(_model(), _tokens(rendered=_VARS), display_line, "v5")
        assert target.placeholder is None
        assert target.reason == RENAME_NOT_DECOMP_LINE


def test_rename_target_declines_an_inline_comment_line():
    model = _model(comments=_comments([(2, "note")]))
    target = resolve_rename_target(model, _tokens(rendered=_VARS), 1, "note")

    assert target.reason == RENAME_NOT_CODE_LINE


def test_rename_target_declines_a_summary_line():
    model = _model(summary=_summary("Adds one."))
    target = resolve_rename_target(model, _tokens(rendered=_VARS), 0, "Adds")

    assert target.reason == RENAME_NOT_CODE_LINE


def test_rename_target_declines_a_word_that_is_not_on_that_source_line():
    target = resolve_rename_target(_model(), _tokens(rendered=_VARS), 2, "a1")

    assert target.reason == RENAME_NOT_ON_LINE.format(word="a1")


def test_rename_target_declines_an_identifier_with_no_token():
    target = resolve_rename_target(_model(), _tokens(rendered=_VARS), 1, "int")

    assert target.reason == RENAME_UNRESOLVED.format(word="int")


@pytest.mark.parametrize(
    "field,reason",
    [
        ("data_type_id", RENAME_IS_DATA_TYPE),
        ("function_id", RENAME_IS_FUNCTION),
        ("imported_function_id", RENAME_IS_IMPORTED_FUNCTION),
    ],
)
def test_rename_target_says_where_a_token_renamed_elsewhere_belongs(field, reason):
    tokens = _tokens(tok="@@X@@ *x;", rendered={"@@X@@": _rt("Foo", kind="type", **{field: 12})})
    target = resolve_rename_target(_model(code="Foo *x;"), tokens, 0, "Foo")

    assert target.placeholder is None
    assert target.reason == reason.format(word="Foo")


def test_every_declined_rename_carries_a_reason():
    model = _model(summary=_summary("S."), comments=_comments([(2, "note")]))
    tokens = _tokens(rendered=_VARS)

    declines = [
        resolve_rename_target(model, tokens, line, word)
        for line, word in [(-1, "v5"), (0, "S"), (99, "v5"), (5, "int"), (5, "nope")]
    ]

    assert all(t.placeholder is None and t.reason for t in declines)


def _pm(text, level="INFO", step="DECOMPILING", timestamp=None):
    return ProgressMessage.model_construct(
        level=level, step=step, text=text, timestamp=timestamp
    )


def _wp(status="RUNNING", step="DECOMPILING", step_index=1, steps_total=3, messages=None):
    return WorkflowProgress.model_construct(
        status=status,
        step=step,
        step_index=step_index,
        steps_total=steps_total,
        messages=messages or [],
    )


def test_render_progress_shows_step_and_status():
    text = render_progress(_wp())
    lines = text.split("\n")
    assert lines[0].startswith("// RevEng.AI")
    assert "// Step 2/3: DECOMPILING [RUNNING]" in lines


def test_render_progress_lists_messages_as_comment_lines():
    text = render_progress(_wp(messages=[_pm("fetching bytes"), _pm("done", level="WARN")]))
    assert "// [INFO] fetching bytes" in text
    assert "// [WARN] done" in text
    assert all(line.startswith("//") for line in text.split("\n"))


def _state(**kw):
    return StreamState(**kw)


def test_render_stream_shows_the_source_as_it_arrives():
    text = render_stream(_state(attempt=1, source="int main(void) {"))

    assert text.startswith("// RevEng.AI — decompiling…")
    assert text.endswith("int main(void) {")


def test_render_stream_shows_prose_only_until_source_starts():
    with_prose = _state(attempt=1, prose=["reading the bytes", "spotting a loop"])
    assert "// spotting a loop" in render_stream(with_prose)

    with_source = _state(attempt=1, prose=["reading the bytes"], source="int x;")
    assert "reading the bytes" not in render_stream(with_source)


def test_render_stream_caps_the_prose_it_shows():
    state = _state(attempt=1, prose=[f"line {i}" for i in range(20)])

    body = [line for line in render_stream(state).split("\n") if line.startswith("// line")]
    assert len(body) == PROSE_TAIL


def test_render_stream_names_the_post_decompilation_naming_stage():
    text = render_stream(_state(attempt=1, source="int x;", decomp_finished=True))

    assert "naming identifiers" in text


def test_render_stream_shows_the_attempt_only_after_a_retry():
    assert "attempt" not in render_stream(_state(attempt=1))
    assert "(attempt 2)" in render_stream(_state(attempt=2))


def test_render_stream_reports_failure_with_its_error():
    text = render_stream(_state(failed=True, error="model unavailable"))

    assert "failed" in text
    assert "// model unavailable" in text


def test_render_stream_of_a_finished_run_keeps_the_source():
    text = render_stream(_state(finished=True, source="int main(void) {}"))

    assert "complete" in text
    assert text.endswith("int main(void) {}")


def test_render_progress_without_steps_falls_back_to_status():
    text = render_progress(_wp(step="", step_index=0, steps_total=0, status="PENDING"))
    assert "// PENDING" in text.split("\n")
