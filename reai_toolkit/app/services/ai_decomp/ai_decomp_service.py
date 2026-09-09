import threading
import time
from typing import Any, Callable

import urllib3
from loguru import logger
from revengai import (
    ApiException,
    Configuration,
    FunctionMapping,
    FunctionsAIDecompilationApi,
)
from revengai.models.ai_decompilation_rating import AiDecompilationRating
from revengai.models.comments_data import CommentsData
from revengai.models.decompilation_data import DecompilationData
from revengai.models.get_tokens_response import GetTokensResponse
from revengai.models.patch_comment_body import PatchCommentBody
from revengai.models.summary_data import SummaryData
from revengai.models.task_status import TaskStatus
from revengai.models.token import Token
from revengai.models.upsert_ai_decomplation_rating_request import (
    UpsertAiDecomplationRatingRequest,
)
from revengai.models.upsert_overrides_input_body import UpsertOverridesInputBody
from revengai.models.workflow_progress import WorkflowProgress

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.core.utils import parse_exception
from reai_toolkit.app.interfaces.thread_service import IThreadService
from reai_toolkit.app.services.ai_decomp.stream import StreamState, iter_stream_events


POLL_INTERVAL_SECONDS: float = 1.5
MAX_REQUEUE_ATTEMPTS = 2

STREAM_CONNECT_TIMEOUT: float = 10.0
STREAM_READ_TIMEOUT: float = 300.0
STREAM_CHUNK_BYTES = 1024
STREAM_DISPATCH_INTERVAL: float = 0.1


class AiDecompService(IThreadService):
    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration) -> None:
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)
        self._decomp_cache: dict[int, DecompilationData] = {}
        self._summary_cache: dict[int, SummaryData] = {}
        self._comments_cache: dict[int, CommentsData] = {}
        self._tokenised_cache: dict[int, GetTokensResponse] = {}
        self._inflight: dict[int, threading.Event] = {}
        self._inflight_lock = threading.Lock()
        self._active_streams: dict[int, urllib3.HTTPResponse] = {}

    def thread_in_progress(self) -> bool:
        return self.is_worker_running()

    def is_worker_running(self) -> bool:
        with self._inflight_lock:
            return bool(self._inflight)

    def stop_worker(self) -> None:
        with self._inflight_lock:
            events = list(self._inflight.values())
            self._inflight.clear()
        for evt in events:
            evt.set()
        for function_id in list(self._active_streams):
            self._close_stream(function_id)
        self._decomp_cache.clear()
        self._summary_cache.clear()
        self._comments_cache.clear()
        self._tokenised_cache.clear()

    def peek_decomp(self, ea: int) -> DecompilationData | None:
        function_id = self._get_function_id(start_ea=ea)
        if function_id is None:
            return None
        return self._decomp_cache.get(function_id)

    def function_id_for(self, ea: int) -> int | None:
        return self._get_function_id(start_ea=ea)

    def invalidate(self, function_id: int) -> None:
        self._decomp_cache.pop(function_id, None)
        self._summary_cache.pop(function_id, None)
        self._comments_cache.pop(function_id, None)
        self._tokenised_cache.pop(function_id, None)
        with self._inflight_lock:
            evt = self._inflight.pop(function_id, None)
        if evt is not None:
            evt.set()
        self._close_stream(function_id)

    def invalidate_ea(self, ea: int) -> None:
        function_id = self._get_function_id(start_ea=ea)
        if function_id is not None:
            self.invalidate(function_id)

    def start_ai_decomp_task(
        self,
        ea: int,
        on_decomp: Callable[[GenericApiReturn[DecompilationData]], None],
        on_summary: Callable[[GenericApiReturn[SummaryData]], None],
        on_comments: Callable[[GenericApiReturn[CommentsData]], None],
        on_tokenised: Callable[[GenericApiReturn[GetTokensResponse]], None] | None = None,
        on_progress: Callable[[WorkflowProgress], None] | None = None,
        on_stream: Callable[[StreamState], None] | None = None,
    ) -> None:
        function_id = self._get_function_id(start_ea=ea)
        if function_id is None:
            on_decomp(GenericApiReturn[DecompilationData](success=True, data=None))
            return

        with self._inflight_lock:
            if function_id in self._inflight:
                return
            stop_event = threading.Event()
            self._inflight[function_id] = stop_event

        worker = threading.Thread(
            target=self._run_task,
            args=(
                function_id,
                stop_event,
                on_decomp,
                on_summary,
                on_comments,
                on_tokenised,
                on_progress,
                on_stream,
            ),
            name=f"reai-aidecomp-{function_id}",
            daemon=True,
        )
        worker.start()

    def apply_overrides(
        self,
        ea: int,
        overrides: dict[str, str],
        on_decomp: Callable[[GenericApiReturn[DecompilationData]], None],
        on_tokenised: Callable[[GenericApiReturn[GetTokensResponse]], None],
    ) -> None:
        function_id = self._get_function_id(start_ea=ea)
        if function_id is None:
            on_decomp(
                GenericApiReturn[DecompilationData](
                    success=False, error_message="Function is not part of the analysis."
                )
            )
            return
        self._spawn(
            self._run_apply_overrides,
            f"reai-aidecomp-overrides-{function_id}",
            (function_id, overrides, on_decomp, on_tokenised),
        )

    def set_comment(
        self,
        ea: int,
        line: int,
        comment: str,
        on_result: Callable[[GenericApiReturn[CommentsData]], None],
    ) -> None:
        function_id = self._get_function_id(start_ea=ea)
        if function_id is None:
            on_result(
                GenericApiReturn[CommentsData](
                    success=False, error_message="Function is not part of the analysis."
                )
            )
            return
        self._spawn(
            self._run_set_comment,
            f"reai-aidecomp-comment-{function_id}",
            (function_id, line, comment, on_result),
        )

    def remove_comment(
        self,
        ea: int,
        line: int,
        on_result: Callable[[GenericApiReturn[CommentsData]], None],
    ) -> None:
        function_id = self._get_function_id(start_ea=ea)
        if function_id is None:
            on_result(
                GenericApiReturn[CommentsData](
                    success=False, error_message="Function is not part of the analysis."
                )
            )
            return
        self._spawn(
            self._run_remove_comment,
            f"reai-aidecomp-comment-del-{function_id}",
            (function_id, line, on_result),
        )

    def rate_decomp(
        self,
        ea: int,
        rating: AiDecompilationRating,
        on_result: Callable[[GenericApiReturn[bool]], None],
    ) -> None:
        function_id = self._get_function_id(start_ea=ea)
        if function_id is None:
            on_result(
                GenericApiReturn[bool](
                    success=False, error_message="Function is not part of the analysis."
                )
            )
            return
        self._spawn(
            self._run_rate_decomp,
            f"reai-aidecomp-rating-{function_id}",
            (function_id, rating, on_result),
        )

    @staticmethod
    def _spawn(target: Callable[..., Any], name: str, args: tuple) -> None:
        threading.Thread(target=target, args=args, name=name, daemon=True).start()

    def _run_rate_decomp(
        self,
        function_id: int,
        rating: AiDecompilationRating,
        on_result: Callable[[GenericApiReturn[bool]], None],
    ) -> None:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                FunctionsAIDecompilationApi(api_client).upsert_ai_decompilation_rating(
                    function_id=function_id,
                    upsert_ai_decomplation_rating_request=UpsertAiDecomplationRatingRequest(
                        rating=rating, reason=None
                    ),
                )
        except ApiException as e:
            on_result(
                GenericApiReturn[bool](
                    success=False, error_message=_format_api_error(e)
                )
            )
            return
        except Exception as e:
            on_result(
                GenericApiReturn[bool](
                    success=False, error_message=f"Unexpected error submitting rating: {e}"
                )
            )
            return
        on_result(GenericApiReturn[bool](success=True, data=True))

    def _run_apply_overrides(
        self,
        function_id: int,
        overrides: dict[str, str],
        on_decomp: Callable[[GenericApiReturn[DecompilationData]], None],
        on_tokenised: Callable[[GenericApiReturn[GetTokensResponse]], None],
    ) -> None:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                FunctionsAIDecompilationApi(api_client).v3_upsert_ai_decompilation_overrides(
                    function_id=function_id,
                    upsert_overrides_input_body=UpsertOverridesInputBody(
                        overrides={
                            placeholder: Token(value=value)
                            for placeholder, value in overrides.items()
                        }
                    ),
                )
        except ApiException as e:
            on_decomp(
                GenericApiReturn[DecompilationData](
                    success=False, error_message=_format_api_error(e)
                )
            )
            return
        except Exception as e:
            on_decomp(
                GenericApiReturn[DecompilationData](
                    success=False, error_message=f"Unexpected error applying overrides: {e}"
                )
            )
            return

        self.invalidate(function_id)

        decomp, derr = self._fetch_decompilation(function_id)
        if decomp is not None and decomp.decompilation:
            self._decomp_cache[function_id] = decomp
            on_decomp(GenericApiReturn[DecompilationData](success=True, data=decomp))
        else:
            on_decomp(
                GenericApiReturn[DecompilationData](
                    success=False,
                    error_message=derr or "AI decompilation returned no content.",
                )
            )

        tokenised, _terr = self._fetch_tokenised(function_id)
        if tokenised is not None and _tokens_ready(tokenised):
            self._tokenised_cache[function_id] = tokenised
            on_tokenised(GenericApiReturn[GetTokensResponse](success=True, data=tokenised))

    def _run_set_comment(
        self,
        function_id: int,
        line: int,
        comment: str,
        on_result: Callable[[GenericApiReturn[CommentsData]], None],
    ) -> None:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                data = FunctionsAIDecompilationApi(
                    api_client
                ).patch_ai_decompilation_inline_comment(
                    function_id=function_id,
                    patch_comment_body=PatchCommentBody(comment=comment, line=line),
                )
        except ApiException as e:
            on_result(
                GenericApiReturn[CommentsData](
                    success=False, error_message=_format_api_error(e)
                )
            )
            return
        except Exception as e:
            on_result(
                GenericApiReturn[CommentsData](
                    success=False, error_message=f"Unexpected error updating comment: {e}"
                )
            )
            return
        self._comments_cache[function_id] = data
        on_result(GenericApiReturn[CommentsData](success=True, data=data))

    def _run_remove_comment(
        self,
        function_id: int,
        line: int,
        on_result: Callable[[GenericApiReturn[CommentsData]], None],
    ) -> None:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                data = FunctionsAIDecompilationApi(
                    api_client
                ).delete_ai_decompilation_inline_comment(
                    function_id=function_id,
                    line=line,
                )
        except ApiException as e:
            on_result(
                GenericApiReturn[CommentsData](
                    success=False, error_message=_format_api_error(e)
                )
            )
            return
        except Exception as e:
            on_result(
                GenericApiReturn[CommentsData](
                    success=False, error_message=f"Unexpected error removing comment: {e}"
                )
            )
            return
        self._comments_cache[function_id] = data
        on_result(GenericApiReturn[CommentsData](success=True, data=data))

    def _run_task(
        self,
        function_id: int,
        stop_event: threading.Event,
        on_decomp: Callable[[GenericApiReturn[DecompilationData]], None],
        on_summary: Callable[[GenericApiReturn[SummaryData]], None],
        on_comments: Callable[[GenericApiReturn[CommentsData]], None],
        on_tokenised: Callable[[GenericApiReturn[GetTokensResponse]], None] | None = None,
        on_progress: Callable[[WorkflowProgress], None] | None = None,
        on_stream: Callable[[StreamState], None] | None = None,
    ) -> None:
        try:
            if stop_event.is_set():
                return
            decomp = self._run_decomp_phase(
                function_id, stop_event, on_decomp, on_progress, on_stream
            )
            if decomp is None:
                return
            self._run_summary_phase(function_id, stop_event, on_summary)
            self._run_comments_phase(function_id, stop_event, on_comments)
            if on_tokenised is not None:
                self._run_tokenised_phase(function_id, stop_event, on_tokenised)
        except Exception as e:
            logger.error(f"RevEng.AI: AI decompilation task crashed for {function_id}: {e}")
        finally:
            with self._inflight_lock:
                if self._inflight.get(function_id) is stop_event:
                    self._inflight.pop(function_id, None)

    def _get_function_id(self, start_ea: int) -> int | None:
        function_map: FunctionMapping | None = self.netstore_service.get_function_mapping()
        if function_map is None:
            return None
        return function_map.inverse_function_map.get(str(start_ea))

    @staticmethod
    def _safe_dispatch(
        stop_event: threading.Event,
        callback: Callable[..., Any] | None,
        payload: Any,
    ) -> None:
        if stop_event.is_set() or callback is None:
            return
        callback(payload)

    def _queue_decompilation(self, function_id: int) -> tuple[bool, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                FunctionsAIDecompilationApi(api_client).create_ai_decompilation(
                    function_id=function_id,
                    context_aware=True,
                )
            return True, None
        except ApiException as e:
            if e.status == 409:
                return True, None
            return False, _format_api_error(e)
        except Exception as e:
            return False, f"Unexpected error queuing AI decompilation: {e}"

    def _fetch_decomp_status(
        self, function_id: int
    ) -> tuple[WorkflowProgress | None, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                progress = FunctionsAIDecompilationApi(api_client).get_ai_decompilation_status(
                    function_id=function_id,
                )
            return progress, None
        except ApiException as e:
            return None, _format_api_error(e)
        except Exception as e:
            return None, f"Unexpected error fetching AI decompilation status: {e}"

    def _fetch_decompilation(
        self, function_id: int
    ) -> tuple[DecompilationData | None, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                decomp = FunctionsAIDecompilationApi(
                    api_client
                ).get_ai_decompilation(function_id=function_id)
            return decomp, None
        except ApiException as e:
            return None, _format_api_error(e)
        except Exception as e:
            logger.error(
                f"RevEng.AI: failed to parse AI decompilation response for function {function_id}: {e}"
            )
            return None, f"Unexpected error fetching AI decompilation: {e}"

    def _run_decomp_phase(
        self,
        function_id: int,
        stop_event: threading.Event,
        on_decomp: Callable[[GenericApiReturn[DecompilationData]], None],
        on_progress: Callable[[WorkflowProgress], None] | None = None,
        on_stream: Callable[[StreamState], None] | None = None,
    ) -> DecompilationData | None:
        cached = self._decomp_cache.get(function_id)
        if cached is not None:
            self._safe_dispatch(
                stop_event,
                on_decomp,
                GenericApiReturn[DecompilationData](success=True, data=cached),
            )
            return cached

        decomp, fetch_err = self._fetch_decompilation(function_id)
        if decomp is None:
            self._safe_dispatch(
                stop_event,
                on_decomp,
                GenericApiReturn[DecompilationData](success=False, error_message=fetch_err),
            )
            return None

        status = str(decomp.status)

        if status == TaskStatus.COMPLETED.value and decomp.decompilation:
            self._decomp_cache[function_id] = decomp
            self._safe_dispatch(
                stop_event,
                on_decomp,
                GenericApiReturn[DecompilationData](success=True, data=decomp),
            )
            return decomp

        if status == TaskStatus.UNINITIALISED.value:
            queued_ok, queue_err = self._queue_decompilation(function_id)
            if not queued_ok:
                self._safe_dispatch(
                    stop_event,
                    on_decomp,
                    GenericApiReturn[DecompilationData](
                        success=False, error_message=queue_err
                    ),
                )
                return None

        streamed = (
            self._stream_decomp(function_id, stop_event, on_stream)
            if on_stream is not None and not stop_event.is_set()
            else None
        )

        if streamed is not None and streamed.failed:
            self._safe_dispatch(
                stop_event,
                on_decomp,
                GenericApiReturn[DecompilationData](
                    success=False,
                    error_message=streamed.error or "AI decompilation failed.",
                ),
            )
            return None

        if streamed is None:
            polled_ok, poll_err = self._poll_workflow(
                function_id=function_id,
                stop_event=stop_event,
                status_fn=self._fetch_decomp_status,
                requeue_fn=self._queue_decompilation,
                label="AI Decompilation",
                on_progress=on_progress,
            )
            if not polled_ok:
                if poll_err is not None:
                    self._safe_dispatch(
                        stop_event,
                        on_decomp,
                        GenericApiReturn[DecompilationData](
                            success=False, error_message=poll_err
                        ),
                    )
                return None

        final, final_err = self._fetch_decompilation(function_id)
        if final is None or not final.decompilation:
            self._safe_dispatch(
                stop_event,
                on_decomp,
                GenericApiReturn[DecompilationData](
                    success=False,
                    error_message=final_err or "AI decompilation returned no content.",
                ),
            )
            return None

        self._decomp_cache[function_id] = final
        self._safe_dispatch(
            stop_event,
            on_decomp,
            GenericApiReturn[DecompilationData](success=True, data=final),
        )
        return final

    def _close_stream(self, function_id: int) -> None:
        resp = self._active_streams.pop(function_id, None)
        if resp is None:
            return
        try:
            resp.close()
        except Exception:
            pass

    def _stream_decomp(
        self,
        function_id: int,
        stop_event: threading.Event,
        on_stream: Callable[[StreamState], None],
    ) -> StreamState | None:
        state = StreamState()
        last_dispatch = 0.0
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                resp = FunctionsAIDecompilationApi(
                    api_client
                ).stream_ai_decompilation_without_preload_content(
                    function_id=function_id,
                    _request_timeout=(STREAM_CONNECT_TIMEOUT, STREAM_READ_TIMEOUT),
                )
                self._active_streams[function_id] = resp
                try:
                    events = iter_stream_events(
                        resp.stream(STREAM_CHUNK_BYTES, decode_content=True),
                        stop=stop_event.is_set,
                    )
                    for event in events:
                        state.apply(event)
                        due = time.monotonic() - last_dispatch >= STREAM_DISPATCH_INTERVAL
                        if state.is_terminal or due:
                            self._safe_dispatch(stop_event, on_stream, state.snapshot())
                            last_dispatch = time.monotonic()
                finally:
                    self._active_streams.pop(function_id, None)
                    try:
                        resp.release_conn()
                    except Exception:
                        pass
        except (ApiException, urllib3.exceptions.HTTPError, OSError) as e:
            logger.debug(
                f"RevEng.AI: AI decompilation stream for function {function_id} ended: {e}"
            )
        except Exception as e:
            logger.debug(
                f"RevEng.AI: AI decompilation stream for function {function_id} failed: {e}"
            )

        if state.is_terminal:
            return state
        logger.debug(
            f"RevEng.AI: AI decompilation stream for function {function_id} "
            "ended before a terminal event; falling back to polling"
        )
        return None

    def _queue_summary(self, function_id: int) -> tuple[bool, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                FunctionsAIDecompilationApi(
                    api_client
                ).regenerate_ai_decompilation_summary(function_id=function_id)
            return True, None
        except ApiException as e:
            if e.status == 409:
                return True, None
            return False, _format_api_error(e)
        except Exception as e:
            return False, f"Unexpected error queuing AI decompilation summary: {e}"

    def _fetch_summary_status(
        self, function_id: int
    ) -> tuple[WorkflowProgress | None, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                progress = FunctionsAIDecompilationApi(
                    api_client
                ).get_ai_decompilation_summary_status(function_id=function_id)
            return progress, None
        except ApiException as e:
            return None, _format_api_error(e)
        except Exception as e:
            return None, f"Unexpected error fetching AI decompilation summary status: {e}"

    def _fetch_summary(
        self, function_id: int
    ) -> tuple[SummaryData | None, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                summary = FunctionsAIDecompilationApi(
                    api_client
                ).get_ai_decompilation_summary(function_id=function_id)
            return summary, None
        except ApiException as e:
            return None, _format_api_error(e)
        except Exception as e:
            return None, f"Unexpected error fetching AI decompilation summary: {e}"

    def _run_summary_phase(
        self,
        function_id: int,
        stop_event: threading.Event,
        on_summary: Callable[[GenericApiReturn[SummaryData]], None],
    ) -> None:
        cached = self._summary_cache.get(function_id)
        if cached is not None:
            self._safe_dispatch(
                stop_event,
                on_summary,
                GenericApiReturn[SummaryData](success=True, data=cached),
            )
            return

        summary, err = self._fetch_summary(function_id)
        if summary is None:
            self._safe_dispatch(
                stop_event,
                on_summary,
                GenericApiReturn[SummaryData](success=False, error_message=err),
            )
            return

        status = str(summary.task_status)

        if status == TaskStatus.COMPLETED.value:
            self._summary_cache[function_id] = summary
            self._safe_dispatch(
                stop_event,
                on_summary,
                GenericApiReturn[SummaryData](success=True, data=summary),
            )
            return

        if status == TaskStatus.UNINITIALISED.value:
            queued_ok, queue_err = self._queue_summary(function_id)
            if not queued_ok:
                self._safe_dispatch(
                    stop_event,
                    on_summary,
                    GenericApiReturn[SummaryData](
                        success=False, error_message=queue_err
                    ),
                )
                return

        polled_ok, poll_err = self._poll_workflow(
            function_id=function_id,
            stop_event=stop_event,
            status_fn=self._fetch_summary_status,
            requeue_fn=self._queue_summary,
            label="AI Summary",
        )
        if not polled_ok:
            if poll_err is not None:
                self._safe_dispatch(
                    stop_event,
                    on_summary,
                    GenericApiReturn[SummaryData](
                        success=False, error_message=poll_err
                    ),
                )
            return

        final, final_err = self._fetch_summary(function_id)
        if final is None:
            self._safe_dispatch(
                stop_event,
                on_summary,
                GenericApiReturn[SummaryData](
                    success=False, error_message=final_err
                ),
            )
            return

        self._summary_cache[function_id] = final
        self._safe_dispatch(
            stop_event,
            on_summary,
            GenericApiReturn[SummaryData](success=True, data=final),
        )

    def _queue_comments(self, function_id: int) -> tuple[bool, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                FunctionsAIDecompilationApi(
                    api_client
                ).regenerate_ai_decompilation_inline_comments(function_id=function_id)
            return True, None
        except ApiException as e:
            if e.status == 409:
                return True, None
            return False, _format_api_error(e)
        except Exception as e:
            return False, f"Unexpected error queuing inline comments: {e}"

    def _fetch_comments_status(
        self, function_id: int
    ) -> tuple[WorkflowProgress | None, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                progress = FunctionsAIDecompilationApi(
                    api_client
                ).get_ai_decompilation_inline_comments_status(function_id=function_id)
            return progress, None
        except ApiException as e:
            return None, _format_api_error(e)
        except Exception as e:
            return None, f"Unexpected error fetching inline comments status: {e}"

    def _fetch_comments(
        self, function_id: int
    ) -> tuple[CommentsData | None, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                comments = FunctionsAIDecompilationApi(
                    api_client
                ).get_ai_decompilation_inline_comments(function_id=function_id)
            return comments, None
        except ApiException as e:
            return None, _format_api_error(e)
        except Exception as e:
            return None, f"Unexpected error fetching inline comments: {e}"

    def _run_comments_phase(
        self,
        function_id: int,
        stop_event: threading.Event,
        on_comments: Callable[[GenericApiReturn[CommentsData]], None],
    ) -> None:
        cached = self._comments_cache.get(function_id)
        if cached is not None:
            self._safe_dispatch(
                stop_event,
                on_comments,
                GenericApiReturn[CommentsData](success=True, data=cached),
            )
            return

        comments, err = self._fetch_comments(function_id)
        if comments is None:
            self._safe_dispatch(
                stop_event,
                on_comments,
                GenericApiReturn[CommentsData](success=False, error_message=err),
            )
            return

        status = str(comments.task_status)

        if status == TaskStatus.COMPLETED.value:
            self._comments_cache[function_id] = comments
            self._safe_dispatch(
                stop_event,
                on_comments,
                GenericApiReturn[CommentsData](success=True, data=comments),
            )
            return

        if status == TaskStatus.UNINITIALISED.value:
            queued_ok, queue_err = self._queue_comments(function_id)
            if not queued_ok:
                self._safe_dispatch(
                    stop_event,
                    on_comments,
                    GenericApiReturn[CommentsData](
                        success=False, error_message=queue_err
                    ),
                )
                return

        polled_ok, poll_err = self._poll_workflow(
            function_id=function_id,
            stop_event=stop_event,
            status_fn=self._fetch_comments_status,
            requeue_fn=self._queue_comments,
            label="Inline Comments",
        )
        if not polled_ok:
            if poll_err is not None:
                self._safe_dispatch(
                    stop_event,
                    on_comments,
                    GenericApiReturn[CommentsData](
                        success=False, error_message=poll_err
                    ),
                )
            return

        final, final_err = self._fetch_comments(function_id)
        if final is None:
            self._safe_dispatch(
                stop_event,
                on_comments,
                GenericApiReturn[CommentsData](
                    success=False, error_message=final_err
                ),
            )
            return

        self._comments_cache[function_id] = final
        self._safe_dispatch(
            stop_event,
            on_comments,
            GenericApiReturn[CommentsData](success=True, data=final),
        )

    def _fetch_tokenised(
        self, function_id: int
    ) -> tuple[GetTokensResponse | None, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                tokenised = FunctionsAIDecompilationApi(
                    api_client
                ).v3_get_ai_decompilation_tokens(function_id=function_id)
            return tokenised, None
        except ApiException as e:
            return None, _format_api_error(e)
        except Exception as e:
            return None, f"Unexpected error fetching tokenised data: {e}"

    def _run_tokenised_phase(
        self,
        function_id: int,
        stop_event: threading.Event,
        on_tokenised: Callable[[GenericApiReturn[GetTokensResponse]], None],
    ) -> None:
        cached = self._tokenised_cache.get(function_id)
        if cached is not None:
            self._safe_dispatch(
                stop_event,
                on_tokenised,
                GenericApiReturn[GetTokensResponse](success=True, data=cached),
            )
            return

        tokenised, err = self._fetch_tokenised(function_id)
        if tokenised is None:
            self._safe_dispatch(
                stop_event,
                on_tokenised,
                GenericApiReturn[GetTokensResponse](success=False, error_message=err),
            )
            return

        if _tokens_ready(tokenised):
            self._tokenised_cache[function_id] = tokenised
            self._safe_dispatch(
                stop_event,
                on_tokenised,
                GenericApiReturn[GetTokensResponse](success=True, data=tokenised),
            )
        else:
            self._safe_dispatch(
                stop_event,
                on_tokenised,
                GenericApiReturn[GetTokensResponse](
                    success=False, error_message="Tokenised data not ready."
                ),
            )

    def _poll_workflow(
        self,
        function_id: int,
        stop_event: threading.Event,
        status_fn: Callable[[int], tuple[WorkflowProgress | None, str | None]],
        requeue_fn: Callable[[int], tuple[bool, str | None]],
        label: str,
        on_progress: Callable[[WorkflowProgress], None] | None = None,
    ) -> tuple[bool, str | None]:
        requeue_attempts = 0
        while not stop_event.is_set():
            progress, status_err = status_fn(function_id)
            if status_err is not None or progress is None:
                return False, status_err or f"{label} status fetch returned nothing."

            logger.debug(
                f"RevEng.AI: {label} progress for function id {function_id}: {progress.status}"
            )

            self._safe_dispatch(stop_event, on_progress, progress)

            if progress.status == TaskStatus.COMPLETED:
                return True, None

            if progress.status == TaskStatus.FAILED:
                return False, (
                    _last_message_text(progress.messages)
                    or f"{label} task failed! Please retry."
                )

            if progress.status == TaskStatus.UNINITIALISED:
                if requeue_attempts >= MAX_REQUEUE_ATTEMPTS:
                    return False, (
                        f"{label} task stayed uninitialised; "
                        "backend did not start the workflow."
                    )
                requeue_attempts += 1
                queued_ok, queue_err = requeue_fn(function_id)
                if not queued_ok:
                    return False, queue_err

            if stop_event.wait(POLL_INTERVAL_SECONDS):
                return False, None

        return False, None


def _tokens_ready(tokens: GetTokensResponse) -> bool:
    return bool(tokens.ai_decomp) and bool(tokens.placeholder_to_rendered_token)


def _format_api_error(e: ApiException) -> str:
    error_response = parse_exception(e)
    if error_response and error_response.errors:
        first = error_response.errors[0]
        return f"{first.code}: {first.message}"
    return f"API Exception: {e}"


def _last_message_text(messages: Any) -> str | None:
    if not messages:
        return None
    for msg in reversed(list(messages)):
        text = getattr(msg, "text", None)
        if text:
            return text
    return None
