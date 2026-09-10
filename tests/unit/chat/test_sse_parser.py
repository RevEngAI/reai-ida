"""SSE frame parser tests — feed fake byte chunks, no network."""

from reai_toolkit.app.services.chat.schema import (
    EVENT_TYPE_NAMES,
    ROLE_ASSISTANT,
    ROLE_DEVELOPER,
    ROLE_SYSTEM,
    ROLE_TOOL,
    ROLE_UNSPECIFIED,
    ROLE_USER,
    EntityRef,
    normalize_event,
    resolve_type,
)
from reai_toolkit.app.services.chat.sse import (
    event_from_frame,
    iter_sse_events,
    parse_sse_data,
)


def _frame(obj_json: str, event: str | None = None) -> bytes:
    head = f"event: {event}\n" if event else ""
    return f"{head}data: {obj_json}\n\n".encode()


def test_parse_data_ignores_empty_and_done():
    assert parse_sse_data("") is None
    assert parse_sse_data("[DONE]") is None
    assert parse_sse_data("{not json}") is None
    assert parse_sse_data("[1, 2]") is None


def test_parse_data_decodes_json():
    assert parse_sse_data('{"type": 1}') == {"type": 1}


def test_event_from_frame_tracks_event_id():
    ev = event_from_frame({"type": 7, "event_id": 9, "data": {"message_id": "m", "delta": "x"}})
    assert ev is not None
    assert ev.type == "TEXT_MESSAGE_CONTENT"
    assert ev.event_id == 9
    assert ev.delta == "x"


def test_integer_type_is_decoded():
    events = list(iter_sse_events([_frame('{"type": 6, "data": {"message_id": "m1"}}')]))
    assert [e.type for e in events] == ["TEXT_MESSAGE_START"]
    assert events[0].role == "assistant"


def test_string_type_passthrough():
    events = list(iter_sse_events([_frame('{"type": "TITLE_UPDATED", "data": {"title": "T"}}')]))
    assert events[0].type == "TITLE_UPDATED"
    assert events[0].title == "T"


def test_snake_case_leaf_normalization():
    frame = _frame('{"type": 9, "data": {"tool_call_id": "t1", "tool_name": "read_fn"}}')
    ev = list(iter_sse_events([frame]))[0]
    assert ev.tool_call_id == "t1"
    assert ev.tool_name == "read_fn"


def test_frames_split_across_chunk_boundaries():
    whole = _frame('{"type": 7, "data": {"message_id": "m", "delta": "hello"}}')
    mid = len(whole) // 2
    chunks = [whole[:mid], whole[mid:]]
    events = list(iter_sse_events(chunks))
    assert len(events) == 1
    assert events[0].delta == "hello"


def test_crlf_line_endings():
    frame = b'data: {"type": "TITLE_UPDATED", "data": {"title": "T"}}\r\n\r\n'
    events = list(iter_sse_events([frame]))
    assert events[0].title == "T"


def test_multiple_frames_in_one_chunk():
    chunk = (
        _frame('{"type": 1}')
        + _frame('{"type": 7, "data": {"message_id": "m", "delta": "a"}}')
    )
    events = list(iter_sse_events([chunk]))
    assert [e.type for e in events] == ["RUN_STARTED", "TEXT_MESSAGE_CONTENT"]


def test_a_final_frame_without_its_blank_line_is_still_read():
    events = list(iter_sse_events([b'data: {"type": 1}\n']))
    assert [e.type for e in events] == ["RUN_STARTED"]


def test_comment_and_id_lines_are_skipped():
    chunk = b': keep-alive\nid: 3\ndata: {"type": 1}\n\n'
    events = list(iter_sse_events([chunk]))
    assert [e.type for e in events] == ["RUN_STARTED"]


def test_a_named_event_is_read_when_the_envelope_has_no_usable_type():
    chunk = _frame('{"data": {"title": "T"}}', event="TITLE_UPDATED")
    events = list(iter_sse_events([chunk]))
    assert [e.type for e in events] == ["TITLE_UPDATED"]
    assert events[0].title == "T"


def test_a_named_event_rescues_a_number_this_table_does_not_know():
    chunk = _frame('{"type": 999, "data": {"title": "T"}}', event="TITLE_UPDATED")
    events = list(iter_sse_events([chunk]))
    assert [e.type for e in events] == ["TITLE_UPDATED"]


def test_the_envelope_type_wins_over_the_event_line():
    chunk = _frame('{"type": 13, "data": {"title": "T"}}', event="RUN_STARTED")
    events = list(iter_sse_events([chunk]))
    assert [e.type for e in events] == ["TITLE_UPDATED"]


def test_a_frame_carrying_only_an_event_line_yields_nothing():
    events = list(iter_sse_events([b"event: RUN_STARTED\n\n"]))
    assert events == []


def test_multi_line_data_is_joined_before_decoding():
    chunk = b'data: {"type": 1,\ndata:  "event_id": 4}\n\n'
    events = list(iter_sse_events([chunk]))
    assert [(e.type, e.event_id) for e in events] == [("RUN_STARTED", 4)]


def test_done_sentinel_and_blank_lines_skipped():
    chunk = b"\n" + _frame('{"type": 1}') + b"data: [DONE]\n\n"
    events = list(iter_sse_events([chunk]))
    assert [e.type for e in events] == ["RUN_STARTED"]


def test_terminal_event_stops_iteration():
    chunk = _frame('{"type": 2}') + _frame('{"type": 1}')
    events = list(iter_sse_events([chunk]))
    assert [e.type for e in events] == ["RUN_FINISHED"]


def test_stop_callback_short_circuits():
    calls = {"n": 0}

    def stop():
        calls["n"] += 1
        return True

    events = list(iter_sse_events([_frame('{"type": 1}')], stop=stop))
    assert events == []


def test_bad_json_frame_is_skipped():
    chunk = _frame("{not json}") + _frame('{"type": 1}')
    events = list(iter_sse_events([chunk]))
    assert [e.type for e in events] == ["RUN_STARTED"]


def test_unknown_int_type_is_dropped():
    assert normalize_event(999, {}) is None
    events = list(iter_sse_events([_frame('{"type": 999, "data": {}}')]))
    assert events == []


def test_run_error_defaults_message():
    ev = list(iter_sse_events([_frame('{"type": 3, "data": {}}')]))[0]
    assert ev.type == "RUN_ERROR"
    assert ev.message == "Unknown error"


def test_run_error_uses_error_key_as_message():
    ev = list(iter_sse_events([_frame('{"type": 3, "data": {"error": "kaboom"}}')]))[0]
    assert ev.message == "kaboom"


def test_tool_result_entity_updates_parsed():
    frame = _frame(
        '{"type": 12, "data": {"tool_call_id": "t", "tool_name": "d", '
        '"updated": [{"type": "function", "ids": [1, 2]}]}}'
    )
    ev = list(iter_sse_events([frame]))[0]
    assert ev.updated is not None
    assert ev.updated[0].type == "function"
    assert ev.updated[0].ids == [1, 2]
    assert ev.updated[0].refs == []


def test_tool_result_entity_refs_parsed():
    frame = _frame(
        '{"type": 12, "data": {"tool_call_id": "t", "tool_name": "rename_functions", '
        '"updated": [{"type": "function", "ids": [2015699787], '
        '"refs": [{"id": 2015699787, "name": "region_position", "vaddr": 4198416}]}]}}'
    )
    ev = list(iter_sse_events([frame]))[0]
    assert ev.updated is not None
    assert ev.updated[0].refs == [
        EntityRef(id=2015699787, name="region_position", vaddr=4198416)
    ]


def test_the_numeric_table_matches_the_persisted_backend_enum():
    assert EVENT_TYPE_NAMES == {
        1: "RUN_STARTED",
        2: "RUN_FINISHED",
        3: "RUN_ERROR",
        4: "STEP_STARTED",
        5: "STEP_FINISHED",
        6: "TEXT_MESSAGE_START",
        7: "TEXT_MESSAGE_CONTENT",
        8: "TEXT_MESSAGE_END",
        9: "TOOL_CALL_START",
        10: "TOOL_CALL_ARGS_DELTA",
        11: "TOOL_CALL_END",
        12: "TOOL_CALL_RESULT",
        13: "TITLE_UPDATED",
        14: "RUN_CANCELLED",
        15: "CONTEXT_COMPACTED",
        16: "TOOL_CONFIRMATION_REQUIRED",
        17: "QUESTION_ASKED",
        18: "USER_ANSWERED",
        19: "TOOL_CALL_PROGRESS",
    }


def test_replayed_question_asked_is_not_mistaken_for_tool_call_progress():
    assert resolve_type(17) == "QUESTION_ASKED"
    assert resolve_type(19) == "TOOL_CALL_PROGRESS"


def test_event_type_zero_stays_undecodable():
    assert resolve_type(0) is None


def test_the_role_table_matches_the_persisted_backend_enum():
    assert (
        ROLE_UNSPECIFIED,
        ROLE_SYSTEM,
        ROLE_USER,
        ROLE_ASSISTANT,
        ROLE_TOOL,
        ROLE_DEVELOPER,
    ) == (0, 1, 2, 3, 4, 5)
