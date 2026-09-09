import json
import pathlib
import threading
import time
from unittest.mock import MagicMock

import pytest
from revengai import ApiException
from revengai.models.ai_decompilation_rating import AiDecompilationRating
from revengai.models.comments_data import CommentsData
from revengai.models.decompilation_data import DecompilationData
from revengai.models.inline_comment import InlineComment
from revengai.models.summary_data import SummaryData
from revengai.models.task_status import TaskStatus
from revengai.models.get_tokens_response import GetTokensResponse
from revengai.models.rendered_token import RenderedToken
from revengai.models.token import Token
from revengai.models.workflow_progress import WorkflowProgress

from reai_toolkit.app.services.ai_decomp import ai_decomp_service as svc_mod
from reai_toolkit.app.services.ai_decomp.ai_decomp_service import AiDecompService


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch):
    monkeypatch.setattr(svc_mod, "POLL_INTERVAL_SECONDS", 0.01)


@pytest.fixture
def netstore():
    netstore = MagicMock()
    fm = MagicMock()
    fm.inverse_function_map = {"4096": 42}
    netstore.get_function_mapping.return_value = fm
    return netstore


@pytest.fixture
def service(netstore):
    return AiDecompService(netstore_service=netstore, sdk_config=MagicMock())


@pytest.fixture
def sdk(mocker):
    mocker.patch.object(svc_mod.AiDecompService, "yield_api_client")
    api_class = mocker.patch.object(svc_mod, "FunctionsAIDecompilationApi")
    api_inst = MagicMock()
    api_class.return_value = api_inst
    api_inst.get_ai_decompilation_summary.return_value = _summary()
    api_inst.get_ai_decompilation_inline_comments.return_value = _comments(
        status=TaskStatus.COMPLETED.value
    )
    return api_inst


def _wp(status, messages=None) -> WorkflowProgress:
    return WorkflowProgress.model_construct(
        status=status if isinstance(status, str) else status.value,
        step="x",
        step_index=0,
        steps_total=1,
        messages=messages or [],
    )


def _dd(status=TaskStatus.COMPLETED.value, code: str | None = "code") -> DecompilationData:
    return DecompilationData.model_construct(status=status, decompilation=code)


def _summary(ai="", raw="", status=TaskStatus.COMPLETED.value) -> SummaryData:
    return SummaryData.model_construct(ai_summary=ai, summary=raw, task_status=status)


def _comments(items=None, status=TaskStatus.COMPLETED.value) -> CommentsData:
    return CommentsData.model_construct(inline_comments=items or [], task_status=status)


def _tokd(source="int @@F@@(void) {}") -> GetTokensResponse:
    return GetTokensResponse.model_construct(
        ai_decomp=source,
        analysis_id=1,
        placeholder_to_rendered_token={
            "@@F@@": RenderedToken.model_construct(
                value="f",
                kind="own_function",
                vaddr=None,
                data_type_id=None,
                function_id=None,
                imported_function_id=None,
            )
        },
        placeholder_to_user_override={},
    )


def _wait_mock(mock: MagicMock, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not mock.called and time.monotonic() < deadline:
        time.sleep(0.005)
    assert mock.called, "callback was not invoked"


def _wait(service, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while service.is_worker_running() and time.monotonic() < deadline:
        time.sleep(0.005)
    assert not service.is_worker_running(), "worker did not go idle"


def _run(service, ea: int = 4096):
    on_decomp, on_summary, on_comments = MagicMock(), MagicMock(), MagicMock()
    service.start_ai_decomp_task(
        ea=ea,
        on_decomp=on_decomp,
        on_summary=on_summary,
        on_comments=on_comments,
    )
    _wait(service)
    return on_decomp, on_summary, on_comments


def test_fast_path_completed_on_first_get(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(code="resolved code")

    on_decomp, _, _ = _run(service)

    on_decomp.assert_called_once()
    result = on_decomp.call_args[0][0]
    assert result.success is True
    assert result.data.decompilation == "resolved code"
    sdk.get_ai_decompilation.assert_called_once_with(function_id=42)
    sdk.create_ai_decompilation.assert_not_called()
    sdk.get_ai_decompilation_status.assert_not_called()
    assert service._decomp_cache[42] is result.data


def test_uninitialised_triggers_queue_then_poll(service, sdk):
    sdk.get_ai_decompilation.side_effect = [
        _dd(status=TaskStatus.UNINITIALISED.value, code=None),
        _dd(code="ready"),
    ]
    sdk.create_ai_decompilation.return_value = MagicMock(status=True)
    sdk.get_ai_decompilation_status.side_effect = [
        _wp(TaskStatus.RUNNING),
        _wp(TaskStatus.COMPLETED),
    ]

    on_decomp, _, _ = _run(service)

    result = on_decomp.call_args[0][0]
    assert result.success is True
    assert result.data.decompilation == "ready"
    sdk.create_ai_decompilation.assert_called_once()
    assert sdk.get_ai_decompilation.call_count == 2


def test_pending_polls_without_queuing(service, sdk):
    sdk.get_ai_decompilation.side_effect = [
        _dd(status=TaskStatus.PENDING.value, code=None),
        _dd(code="done"),
    ]
    sdk.get_ai_decompilation_status.side_effect = [
        _wp(TaskStatus.RUNNING),
        _wp(TaskStatus.COMPLETED),
    ]

    on_decomp, _, _ = _run(service)

    assert on_decomp.call_args[0][0].success is True
    sdk.create_ai_decompilation.assert_not_called()
    sdk.get_ai_decompilation_status.assert_called()


def test_409_on_create_treated_as_already_queued(service, sdk):
    sdk.get_ai_decompilation.side_effect = [
        _dd(status=TaskStatus.UNINITIALISED.value, code=None),
        _dd(code="ready"),
    ]
    sdk.create_ai_decompilation.side_effect = ApiException(status=409)
    sdk.get_ai_decompilation_status.side_effect = [
        _wp(TaskStatus.RUNNING),
        _wp(TaskStatus.COMPLETED),
    ]

    on_decomp, _, _ = _run(service)

    assert on_decomp.call_args[0][0].success is True


def test_failed_status_surfaces_message(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(
        status=TaskStatus.PENDING.value, code=None
    )
    msg = MagicMock()
    msg.text = "model exploded"
    sdk.get_ai_decompilation_status.side_effect = [
        _wp(TaskStatus.RUNNING),
        _wp(TaskStatus.FAILED, messages=[msg]),
    ]

    on_decomp, _, _ = _run(service)

    result = on_decomp.call_args[0][0]
    assert result.success is False
    assert "model exploded" in result.error_message


def test_uninitialised_loop_bounded_by_max_requeues(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(
        status=TaskStatus.UNINITIALISED.value, code=None
    )
    sdk.create_ai_decompilation.return_value = MagicMock(status=True)
    sdk.get_ai_decompilation_status.return_value = _wp(TaskStatus.UNINITIALISED)

    on_decomp, _, _ = _run(service)

    result = on_decomp.call_args[0][0]
    assert result.success is False
    assert "uninitialised" in result.error_message.lower()
    assert sdk.create_ai_decompilation.call_count == 1 + svc_mod.MAX_REQUEUE_ATTEMPTS


def test_unknown_function_id_returns_empty_success(service, sdk, netstore):
    netstore.get_function_mapping.return_value.inverse_function_map = {}

    on_decomp, on_summary, on_comments = _run(service)

    on_decomp.assert_called_once()
    result = on_decomp.call_args[0][0]
    assert result.success is True
    assert result.data is None
    sdk.get_ai_decompilation.assert_not_called()
    sdk.create_ai_decompilation.assert_not_called()
    on_summary.assert_not_called()
    on_comments.assert_not_called()


def test_first_get_api_exception_surfaces_error(service, sdk):
    sdk.get_ai_decompilation.side_effect = ApiException(status=500, reason="boom")

    on_decomp, _, _ = _run(service)

    result = on_decomp.call_args[0][0]
    assert result.success is False
    assert "API Exception" in result.error_message or result.error_message
    sdk.create_ai_decompilation.assert_not_called()


def test_cache_hit_skips_all_network_calls(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(code="first run")

    on_decomp_1, _, _ = _run(service)
    first = on_decomp_1.call_args[0][0].data

    sdk.reset_mock()
    sdk.get_ai_decompilation_summary.return_value = _summary()
    sdk.get_ai_decompilation_inline_comments.return_value = _comments()

    on_decomp_2, _, _ = _run(service)
    second = on_decomp_2.call_args[0][0].data

    assert first is second
    sdk.get_ai_decompilation.assert_not_called()
    sdk.create_ai_decompilation.assert_not_called()


def test_summary_phase_dispatches_on_completed_decomp(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(code="ok")
    sdk.get_ai_decompilation_summary.return_value = _summary(ai="It does X.")

    _, on_summary, _ = _run(service)

    on_summary.assert_called_once()
    assert on_summary.call_args[0][0].data.ai_summary == "It does X."
    sdk.regenerate_ai_decompilation_summary.assert_not_called()
    sdk.get_ai_decompilation_summary_status.assert_not_called()


def test_summary_phase_regenerates_when_uninitialised(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(code="ok")
    sdk.get_ai_decompilation_summary.side_effect = [
        _summary(status=TaskStatus.UNINITIALISED.value),
        _summary(ai="ready"),
    ]
    sdk.regenerate_ai_decompilation_summary.return_value = MagicMock(status=True)
    sdk.get_ai_decompilation_summary_status.side_effect = [
        _wp(TaskStatus.RUNNING),
        _wp(TaskStatus.COMPLETED),
    ]

    _, on_summary, _ = _run(service)

    sdk.regenerate_ai_decompilation_summary.assert_called_once()
    on_summary.assert_called_once()
    payload = on_summary.call_args[0][0]
    assert payload.success is True
    assert payload.data.ai_summary == "ready"


def test_comments_phase_skips_regenerate_when_completed(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(code="ok")
    sdk.get_ai_decompilation_inline_comments.return_value = _comments(
        status=TaskStatus.COMPLETED.value
    )

    _, _, on_comments = _run(service)

    on_comments.assert_called_once()
    sdk.regenerate_ai_decompilation_inline_comments.assert_not_called()
    sdk.get_ai_decompilation_inline_comments_status.assert_not_called()


def test_comments_phase_regenerates_when_uninitialised(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(code="ok")
    sdk.get_ai_decompilation_inline_comments.side_effect = [
        _comments(status=TaskStatus.UNINITIALISED.value),
        _comments(status=TaskStatus.COMPLETED.value),
    ]
    sdk.regenerate_ai_decompilation_inline_comments.return_value = MagicMock(status=True)
    sdk.get_ai_decompilation_inline_comments_status.side_effect = [
        _wp(TaskStatus.RUNNING),
        _wp(TaskStatus.COMPLETED),
    ]

    _, _, on_comments = _run(service)

    sdk.regenerate_ai_decompilation_inline_comments.assert_called_once()
    on_comments.assert_called_once()
    assert on_comments.call_args[0][0].success is True


def test_safe_dispatch_suppresses_when_stop_set():
    cb = MagicMock()
    evt = threading.Event()
    evt.set()
    AiDecompService._safe_dispatch(evt, cb, "payload")
    cb.assert_not_called()


def test_safe_dispatch_fires_when_stop_not_set():
    cb = MagicMock()
    evt = threading.Event()
    AiDecompService._safe_dispatch(evt, cb, "payload")
    cb.assert_called_once_with("payload")


def test_safe_dispatch_no_op_when_callback_none():
    evt = threading.Event()
    AiDecompService._safe_dispatch(evt, None, "payload")


def test_stop_mid_poll_drops_callback(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(
        status=TaskStatus.PENDING.value, code=None
    )

    started = threading.Event()
    release = threading.Event()

    def stall_status(*a, **kw):
        started.set()
        release.wait(timeout=2.0)
        return _wp(TaskStatus.COMPLETED)

    sdk.get_ai_decompilation_status.side_effect = stall_status

    on_decomp = MagicMock()
    service.start_ai_decomp_task(
        ea=4096,
        on_decomp=on_decomp,
        on_summary=MagicMock(),
        on_comments=MagicMock(),
    )
    assert started.wait(timeout=2.0)

    service.stop_worker()
    release.set()
    time.sleep(0.2)
    on_decomp.assert_not_called()


def test_tokenised_phase_caches_and_dispatches_on_completed(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(code="ok")
    sdk.v3_get_ai_decompilation_tokens.return_value = _tokd()

    on_tokenised = MagicMock()
    service.start_ai_decomp_task(
        ea=4096,
        on_decomp=MagicMock(),
        on_summary=MagicMock(),
        on_comments=MagicMock(),
        on_tokenised=on_tokenised,
    )
    _wait(service)

    on_tokenised.assert_called_once()
    assert on_tokenised.call_args[0][0].success is True
    assert service._tokenised_cache[42] is sdk.v3_get_ai_decompilation_tokens.return_value


def test_tokenised_phase_treats_an_empty_source_as_not_ready(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(code="ok")
    sdk.v3_get_ai_decompilation_tokens.return_value = GetTokensResponse.model_construct(
        ai_decomp="",
        analysis_id=1,
        placeholder_to_rendered_token={},
        placeholder_to_user_override={},
    )

    on_tokenised = MagicMock()
    service.start_ai_decomp_task(
        ea=4096,
        on_decomp=MagicMock(),
        on_summary=MagicMock(),
        on_comments=MagicMock(),
        on_tokenised=on_tokenised,
    )
    _wait(service)

    assert on_tokenised.call_args[0][0].success is False
    assert 42 not in service._tokenised_cache


def test_tokenised_phase_skipped_when_no_callback(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(code="ok")
    _run(service)
    sdk.v3_get_ai_decompilation_tokens.assert_not_called()


def test_apply_overrides_sends_body_refetches_and_caches(service, sdk):
    sdk.v3_upsert_ai_decompilation_overrides.return_value = MagicMock()
    sdk.get_ai_decompilation.return_value = _dd(code="renamed")
    sdk.v3_get_ai_decompilation_tokens.return_value = _tokd()

    on_decomp, on_tokenised = MagicMock(), MagicMock()
    service.apply_overrides(
        ea=4096,
        overrides={"@@V_v5@@": "buf"},
        on_decomp=on_decomp,
        on_tokenised=on_tokenised,
    )
    _wait_mock(on_decomp)
    _wait_mock(on_tokenised)

    _, kwargs = sdk.v3_upsert_ai_decompilation_overrides.call_args
    assert kwargs["function_id"] == 42
    assert kwargs["upsert_overrides_input_body"].overrides == {"@@V_v5@@": Token(value="buf")}

    payload = on_decomp.call_args[0][0]
    assert payload.success is True
    assert payload.data.decompilation == "renamed"
    assert service._decomp_cache[42].decompilation == "renamed"
    assert service._tokenised_cache[42] is sdk.v3_get_ai_decompilation_tokens.return_value


def test_apply_overrides_api_error_surfaces(service, sdk):
    sdk.v3_upsert_ai_decompilation_overrides.side_effect = ApiException(status=500, reason="x")

    on_decomp, on_tokenised = MagicMock(), MagicMock()
    service.apply_overrides(
        ea=4096, overrides={"a": "b"}, on_decomp=on_decomp, on_tokenised=on_tokenised
    )
    _wait_mock(on_decomp)

    assert on_decomp.call_args[0][0].success is False
    sdk.get_ai_decompilation.assert_not_called()


def test_set_comment_calls_patch_and_updates_cache(service, sdk):
    updated = _comments(items=[InlineComment.model_construct(comment="hi", line=3)])
    sdk.patch_ai_decompilation_inline_comment.return_value = updated

    on_result = MagicMock()
    service.set_comment(ea=4096, line=3, comment="hi", on_result=on_result)
    _wait_mock(on_result)

    _, kwargs = sdk.patch_ai_decompilation_inline_comment.call_args
    assert kwargs["function_id"] == 42
    assert kwargs["patch_comment_body"].comment == "hi"
    assert kwargs["patch_comment_body"].line == 3
    assert on_result.call_args[0][0].success is True
    assert service._comments_cache[42] is updated


def test_remove_comment_calls_delete_and_updates_cache(service, sdk):
    updated = _comments(items=[])
    sdk.delete_ai_decompilation_inline_comment.return_value = updated

    on_result = MagicMock()
    service.remove_comment(ea=4096, line=3, on_result=on_result)
    _wait_mock(on_result)

    _, kwargs = sdk.delete_ai_decompilation_inline_comment.call_args
    assert kwargs["function_id"] == 42
    assert kwargs["line"] == 3
    assert on_result.call_args[0][0].success is True
    assert service._comments_cache[42] is updated


def test_comment_mutation_api_error_surfaces(service, sdk):
    sdk.patch_ai_decompilation_inline_comment.side_effect = ApiException(status=403)

    on_result = MagicMock()
    service.set_comment(ea=4096, line=1, comment="x", on_result=on_result)
    _wait_mock(on_result)

    assert on_result.call_args[0][0].success is False


def test_mutation_unknown_function_id_reports_failure(service, sdk, netstore):
    netstore.get_function_mapping.return_value.inverse_function_map = {}
    on_result = MagicMock()
    service.set_comment(ea=4096, line=1, comment="x", on_result=on_result)
    on_result.assert_called_once()
    assert on_result.call_args[0][0].success is False
    sdk.patch_ai_decompilation_inline_comment.assert_not_called()


def test_rate_decomp_calls_upsert_rating(service, sdk):
    sdk.upsert_ai_decompilation_rating.return_value = MagicMock()

    on_result = MagicMock()
    service.rate_decomp(
        ea=4096, rating=AiDecompilationRating.POSITIVE, on_result=on_result
    )
    _wait_mock(on_result)

    _, kwargs = sdk.upsert_ai_decompilation_rating.call_args
    assert kwargs["function_id"] == 42
    body = kwargs["upsert_ai_decomplation_rating_request"]
    assert body.rating == AiDecompilationRating.POSITIVE
    assert body.reason is None
    assert on_result.call_args[0][0].success is True


def test_rate_decomp_api_error_surfaces(service, sdk):
    sdk.upsert_ai_decompilation_rating.side_effect = ApiException(status=422)

    on_result = MagicMock()
    service.rate_decomp(
        ea=4096, rating=AiDecompilationRating.NEGATIVE, on_result=on_result
    )
    _wait_mock(on_result)

    assert on_result.call_args[0][0].success is False


def test_rate_decomp_unknown_function_id_reports_failure(service, sdk, netstore):
    netstore.get_function_mapping.return_value.inverse_function_map = {}

    on_result = MagicMock()
    service.rate_decomp(
        ea=4096, rating=AiDecompilationRating.POSITIVE, on_result=on_result
    )

    on_result.assert_called_once()
    assert on_result.call_args[0][0].success is False
    sdk.upsert_ai_decompilation_rating.assert_not_called()


def test_invalidate_clears_all_caches_and_inflight(service):
    service._decomp_cache[42] = object()
    service._summary_cache[42] = object()
    service._comments_cache[42] = object()
    service._tokenised_cache[42] = object()
    evt = threading.Event()
    service._inflight[42] = evt

    service.invalidate(42)

    assert 42 not in service._decomp_cache
    assert 42 not in service._summary_cache
    assert 42 not in service._comments_cache
    assert 42 not in service._tokenised_cache
    assert 42 not in service._inflight
    assert evt.is_set()


def test_function_id_for_and_invalidate_ea(service):
    assert service.function_id_for(4096) == 42
    assert service.function_id_for(9999) is None

    service._decomp_cache[42] = object()
    service.invalidate_ea(4096)
    assert 42 not in service._decomp_cache


def _sse(event_type, **payload):
    body = {"type": event_type, "attempt": 1, "seq": payload.pop("seq", 0)}
    body.update(payload)
    return f"event: {event_type}\ndata: {json.dumps(body)}\n\n".encode()


def _stream_response(chunks):
    resp = MagicMock()
    resp.stream.return_value = iter(chunks)
    return resp


def _start_streaming(service, on_stream, on_decomp=None):
    service.start_ai_decomp_task(
        ea=4096,
        on_decomp=on_decomp or MagicMock(),
        on_summary=MagicMock(),
        on_comments=MagicMock(),
        on_stream=on_stream,
    )
    _wait(service)


def test_streaming_replaces_polling_and_reports_the_growing_source(service, sdk, monkeypatch):
    monkeypatch.setattr(svc_mod, "STREAM_DISPATCH_INTERVAL", 0.0)
    sdk.get_ai_decompilation.side_effect = [_dd(status=TaskStatus.RUNNING.value, code=None), _dd(code="final")]
    sdk.stream_ai_decompilation_without_preload_content.return_value = _stream_response(
        [
            _sse("source_delta", content="int main"),
            _sse("source_delta", content="(void) {}"),
            _sse("decomp_finished"),
            _sse("names_finished", applied=2),
        ]
    )

    on_stream, on_decomp = MagicMock(), MagicMock()
    _start_streaming(service, on_stream, on_decomp)

    sdk.get_ai_decompilation_status.assert_not_called()
    sources = [call[0][0].source for call in on_stream.call_args_list]
    assert sources[-1] == "int main(void) {}"
    assert on_stream.call_args[0][0].finished is True
    assert on_decomp.call_args[0][0].data.decompilation == "final"


def test_each_dispatched_state_is_an_independent_snapshot(service, sdk, monkeypatch):
    monkeypatch.setattr(svc_mod, "STREAM_DISPATCH_INTERVAL", 0.0)
    sdk.get_ai_decompilation.side_effect = [_dd(status=TaskStatus.RUNNING.value, code=None), _dd(code="final")]
    sdk.stream_ai_decompilation_without_preload_content.return_value = _stream_response(
        [
            _sse("source_delta", content="a"),
            _sse("source_delta", content="b"),
            _sse("names_finished", applied=0),
        ]
    )

    on_stream = MagicMock()
    _start_streaming(service, on_stream)

    states = [call[0][0] for call in on_stream.call_args_list]
    assert [s.source for s in states] == ["a", "ab", "ab"]


def test_a_stream_that_ends_without_a_terminal_event_falls_back_to_polling(service, sdk):
    sdk.get_ai_decompilation.side_effect = [_dd(status=TaskStatus.RUNNING.value, code=None), _dd(code="polled")]
    sdk.stream_ai_decompilation_without_preload_content.return_value = _stream_response(
        [_sse("source_delta", content="partial")]
    )
    sdk.get_ai_decompilation_status.return_value = _wp(TaskStatus.COMPLETED)

    on_decomp = MagicMock()
    _start_streaming(service, MagicMock(), on_decomp)

    sdk.get_ai_decompilation_status.assert_called()
    assert on_decomp.call_args[0][0].data.decompilation == "polled"


def test_a_stream_that_raises_falls_back_to_polling(service, sdk):
    sdk.get_ai_decompilation.side_effect = [_dd(status=TaskStatus.RUNNING.value, code=None), _dd(code="polled")]
    sdk.stream_ai_decompilation_without_preload_content.side_effect = ApiException(
        status=502, reason="bad gateway"
    )
    sdk.get_ai_decompilation_status.return_value = _wp(TaskStatus.COMPLETED)

    on_decomp = MagicMock()
    _start_streaming(service, MagicMock(), on_decomp)

    sdk.get_ai_decompilation_status.assert_called()
    assert on_decomp.call_args[0][0].data.decompilation == "polled"


def test_decomp_failed_surfaces_the_error_without_polling(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(status=TaskStatus.RUNNING.value, code=None)
    sdk.stream_ai_decompilation_without_preload_content.return_value = _stream_response(
        [_sse("decomp_failed", error="model unavailable", error_code="MODEL_GONE")]
    )

    on_decomp = MagicMock()
    _start_streaming(service, MagicMock(), on_decomp)

    sdk.get_ai_decompilation_status.assert_not_called()
    payload = on_decomp.call_args[0][0]
    assert payload.success is False
    assert payload.error_message == "model unavailable"


def test_no_stream_callback_keeps_the_polling_path(service, sdk):
    sdk.get_ai_decompilation.side_effect = [_dd(status=TaskStatus.RUNNING.value, code=None), _dd(code="polled")]
    sdk.get_ai_decompilation_status.return_value = _wp(TaskStatus.COMPLETED)

    _run(service)

    sdk.stream_ai_decompilation_without_preload_content.assert_not_called()
    sdk.get_ai_decompilation_status.assert_called()


def test_dispatches_are_throttled_between_terminal_events(service, sdk, monkeypatch):
    monkeypatch.setattr(svc_mod, "STREAM_DISPATCH_INTERVAL", 60.0)
    sdk.get_ai_decompilation.side_effect = [_dd(status=TaskStatus.RUNNING.value, code=None), _dd(code="final")]
    sdk.stream_ai_decompilation_without_preload_content.return_value = _stream_response(
        [_sse("source_delta", content=str(i)) for i in range(10)]
        + [_sse("names_finished", applied=0)]
    )

    on_stream = MagicMock()
    _start_streaming(service, on_stream)

    assert on_stream.call_count == 2
    assert on_stream.call_args[0][0].finished is True


def test_invalidate_closes_a_live_stream(service):
    resp = MagicMock()
    service._active_streams[42] = resp

    service.invalidate(42)

    resp.close.assert_called_once()
    assert 42 not in service._active_streams


def test_streaming_never_dispatches_on_the_main_thread(service, sdk, monkeypatch):
    monkeypatch.setattr(svc_mod, "STREAM_DISPATCH_INTERVAL", 0.0)
    sdk.get_ai_decompilation.side_effect = [_dd(status=TaskStatus.RUNNING.value, code=None), _dd(code="final")]
    sdk.stream_ai_decompilation_without_preload_content.return_value = _stream_response(
        [_sse("source_delta", content="x"), _sse("names_finished", applied=0)]
    )

    threads: list = []
    _start_streaming(service, lambda state: threads.append(threading.current_thread()))

    assert threads
    assert all(t is not threading.main_thread() for t in threads)


@pytest.mark.parametrize("callback", ["_on_stream", "_on_progress"])
def test_view_writing_callbacks_stay_marshalled_onto_the_ui_thread(callback):
    source = pathlib.Path(
        "reai_toolkit/app/coordinators/ai_decomp_coordinator.py"
    ).read_text()

    assert f"    @execute_ui\n    def {callback}(" in source, (
        f"{callback} writes to the Qt view from a stream/poll worker thread, "
        "so it must keep @execute_ui"
    )
