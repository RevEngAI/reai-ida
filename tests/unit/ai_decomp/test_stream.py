import json

import pytest

from reai_toolkit.app.services.ai_decomp.stream import (
    EVENT_ATTEMPT_FAILED,
    EVENT_ATTEMPT_STARTED,
    EVENT_DECOMP_FAILED,
    EVENT_DECOMP_FINISHED,
    EVENT_NAMES_FINISHED,
    EVENT_PROSE,
    EVENT_RENAME_APPLIED,
    EVENT_SOURCE_DELTA,
    EVENT_SOURCE_RESET,
    EVENT_TYPES_SUGGESTED,
    EVENT_WARNING,
    DecompEvent,
    StreamState,
    iter_sse_frames,
    iter_stream_events,
    normalize_event,
    reduce_stream,
)


def _frame(event_type, **payload):
    body = {"type": event_type, "attempt": 1, "seq": payload.pop("seq", 0)}
    body.update(payload)
    return f"event: {event_type}\ndata: {json.dumps(body)}\n\n".encode()


def _ev(event_type, **kw):
    kw.setdefault("attempt", 1)
    return DecompEvent(type=event_type, **kw)


def test_frames_split_on_blank_lines_and_keep_the_event_name():
    chunks = [_frame(EVENT_SOURCE_DELTA, content="int "), _frame(EVENT_DECOMP_FINISHED)]

    frames = list(iter_sse_frames(chunks))

    assert [name for name, _ in frames] == [EVENT_SOURCE_DELTA, EVENT_DECOMP_FINISHED]


def test_frames_survive_being_split_across_chunk_boundaries():
    raw = _frame(EVENT_SOURCE_DELTA, content="int main(void)")
    chunks = [raw[:7], raw[7:20], raw[20:]]

    events = list(iter_stream_events(chunks))

    assert [e.content for e in events] == ["int main(void)"]


def test_multiline_data_lines_are_joined_with_newlines():
    payload = json.dumps({"type": EVENT_PROSE, "attempt": 1, "seq": 1, "text": "hi"})
    half = len(payload) // 2
    raw = f"data: {payload[:half]}\ndata: {payload[half:]}\n\n".encode()

    frames = list(iter_sse_frames([raw]))

    assert frames == [(None, f"{payload[:half]}\n{payload[half:]}")]


def test_comment_lines_and_unparseable_frames_are_skipped():
    chunks = [
        b": keep-alive\n\n",
        b"data: not json\n\n",
        b"data: [1, 2, 3]\n\n",
        _frame(EVENT_SOURCE_DELTA, content="ok"),
    ]

    events = list(iter_stream_events(chunks))

    assert [e.content for e in events] == ["ok"]


def test_done_sentinel_ends_the_stream():
    chunks = [_frame(EVENT_SOURCE_DELTA, content="a"), b"data: [DONE]\n\n", _frame(EVENT_PROSE, text="never")]

    events = list(iter_stream_events(chunks))

    assert [e.type for e in events] == [EVENT_SOURCE_DELTA]


def test_a_trailing_frame_without_its_blank_line_is_still_yielded():
    raw = _frame(EVENT_SOURCE_DELTA, content="tail")[:-2]

    events = list(iter_stream_events([raw]))

    assert [e.content for e in events] == ["tail"]


@pytest.mark.parametrize("terminal", [EVENT_NAMES_FINISHED, EVENT_DECOMP_FAILED])
def test_iteration_stops_after_a_terminal_event(terminal):
    chunks = [_frame(terminal, error="boom"), _frame(EVENT_PROSE, text="after the end")]

    events = list(iter_stream_events(chunks))

    assert [e.type for e in events] == [terminal]


def test_decomp_finished_is_not_terminal():
    chunks = [_frame(EVENT_DECOMP_FINISHED), _frame(EVENT_NAMES_FINISHED, applied=3)]

    events = list(iter_stream_events(chunks))

    assert [e.type for e in events] == [EVENT_DECOMP_FINISHED, EVENT_NAMES_FINISHED]


def test_stop_callback_halts_iteration():
    calls = {"n": 0}

    def chunks():
        for _ in range(5):
            yield _frame(EVENT_SOURCE_DELTA, content="x")

    def stop():
        calls["n"] += 1
        return calls["n"] > 2

    assert len(list(iter_stream_events(chunks(), stop=stop))) == 2


def test_type_falls_back_to_the_sse_event_line():
    event = normalize_event(EVENT_SOURCE_DELTA, {"content": "x", "attempt": 1})

    assert event.type == EVENT_SOURCE_DELTA
    assert event.content == "x"


def test_payload_type_wins_over_the_event_line():
    event = normalize_event("stale", {"type": EVENT_PROSE, "text": "x"})

    assert event.type == EVENT_PROSE


def test_an_event_with_no_type_anywhere_is_dropped():
    assert normalize_event(None, {"content": "x"}) is None


def test_unknown_event_types_survive_normalisation():
    event = normalize_event(None, {"type": "invented_later", "attempt": 2})

    assert event.type == "invented_later"
    assert event.attempt == 2


def test_wrongly_typed_fields_do_not_crash_normalisation():
    event = normalize_event(None, {"type": EVENT_SOURCE_DELTA, "content": 5, "attempt": "x"})

    assert event.content == ""
    assert event.attempt == 0


def test_source_deltas_accumulate():
    state = reduce_stream(
        [
            _ev(EVENT_SOURCE_DELTA, content="int main"),
            _ev(EVENT_SOURCE_DELTA, content="(void) {}"),
        ]
    )

    assert state.source == "int main(void) {}"


def test_source_reset_clears_the_buffer_without_touching_the_attempt():
    state = reduce_stream(
        [
            _ev(EVENT_SOURCE_DELTA, content="discard me"),
            _ev(EVENT_SOURCE_RESET),
            _ev(EVENT_SOURCE_DELTA, content="keep me"),
        ]
    )

    assert state.source == "keep me"
    assert state.attempt == 1


def test_a_new_attempt_discards_everything_from_the_previous_one():
    state = reduce_stream(
        [
            _ev(EVENT_SOURCE_DELTA, content="first try"),
            _ev(EVENT_PROSE, text="thinking"),
            _ev(EVENT_ATTEMPT_FAILED, error="flaky"),
            _ev(EVENT_ATTEMPT_STARTED, attempt=2),
            _ev(EVENT_SOURCE_DELTA, attempt=2, content="second try"),
        ]
    )

    assert state.source == "second try"
    assert state.prose == []
    assert state.error == ""
    assert state.attempt == 2


def test_attempt_failed_is_recorded_but_not_terminal():
    state = reduce_stream([_ev(EVENT_ATTEMPT_FAILED, error="flaky")])

    assert state.error == "flaky"
    assert state.is_terminal is False


def test_decomp_finished_marks_the_naming_stage_not_completion():
    state = reduce_stream([_ev(EVENT_DECOMP_FINISHED)])

    assert state.decomp_finished is True
    assert state.finished is False
    assert state.is_terminal is False


def test_names_finished_completes_the_run():
    state = reduce_stream([_ev(EVENT_DECOMP_FINISHED), _ev(EVENT_NAMES_FINISHED, applied=4)])

    assert state.finished is True
    assert state.is_terminal is True
    assert state.names_applied == 4


def test_decomp_failed_records_the_error_and_terminates():
    state = reduce_stream([_ev(EVENT_DECOMP_FAILED, error="no model", error_code="MODEL_GONE")])

    assert (state.failed, state.error, state.error_code) == (True, "no model", "MODEL_GONE")
    assert state.is_terminal is True


def test_renames_warnings_and_type_suggestions_are_collected():
    state = reduce_stream(
        [
            _ev(EVENT_RENAME_APPLIED, old_name="v1", new_name="count"),
            _ev(EVENT_WARNING, message="truncated output", warning_kind="TRUNCATED"),
            _ev(EVENT_TYPES_SUGGESTED, types=2, members=7),
        ]
    )

    assert state.renames == [("v1", "count")]
    assert state.warnings == ["truncated output"]
    assert (state.types_suggested, state.members_suggested) == (2, 7)


def test_a_warning_with_no_message_falls_back_to_its_kind():
    state = reduce_stream([_ev(EVENT_WARNING, warning_kind="TRUNCATED")])

    assert state.warnings == ["TRUNCATED"]


def test_empty_prose_is_not_recorded():
    state = reduce_stream([_ev(EVENT_PROSE, text="")])

    assert state.prose == []


def test_a_fresh_state_is_not_terminal():
    assert StreamState().is_terminal is False
