from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Callable, Iterable, Iterator, Optional

from reai_toolkit.app.services.sse import iter_sse_frames

EVENT_ATTEMPT_FAILED = "attempt_failed"
EVENT_ATTEMPT_STARTED = "attempt_started"
EVENT_DECOMP_FAILED = "decomp_failed"
EVENT_DECOMP_FINISHED = "decomp_finished"
EVENT_NAMES_FINISHED = "names_finished"
EVENT_PROSE = "prose"
EVENT_RENAME_APPLIED = "rename_applied"
EVENT_SOURCE_DELTA = "source_delta"
EVENT_SOURCE_RESET = "source_reset"
EVENT_TYPES_SUGGESTED = "types_suggested"
EVENT_WARNING = "warning"

TERMINAL_EVENTS: frozenset[str] = frozenset(
    {EVENT_NAMES_FINISHED, EVENT_DECOMP_FAILED}
)

PROSE_TAIL = 5


@dataclass
class DecompEvent:
    type: str
    attempt: int = 0
    seq: int = 0
    content: str = ""
    text: str = ""
    error: str = ""
    error_code: Optional[str] = None
    old_name: str = ""
    new_name: str = ""
    warning_kind: str = ""
    message: str = ""
    applied: int = 0
    types: int = 0
    members: int = 0


def _as_int(value) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _as_str(value) -> str:
    return value if isinstance(value, str) else ""


def normalize_event(event_name: Optional[str], payload: dict) -> Optional[DecompEvent]:
    event_type = _as_str(payload.get("type")) or _as_str(event_name)
    if not event_type:
        return None
    error_code = payload.get("error_code")
    return DecompEvent(
        type=event_type,
        attempt=_as_int(payload.get("attempt")),
        seq=_as_int(payload.get("seq")),
        content=_as_str(payload.get("content")),
        text=_as_str(payload.get("text")),
        error=_as_str(payload.get("error")),
        error_code=error_code if isinstance(error_code, str) else None,
        old_name=_as_str(payload.get("old_name")),
        new_name=_as_str(payload.get("new_name")),
        warning_kind=_as_str(payload.get("kind")),
        message=_as_str(payload.get("message")),
        applied=_as_int(payload.get("applied")),
        types=_as_int(payload.get("types")),
        members=_as_int(payload.get("members")),
    )


def iter_stream_events(
    chunks: Iterable[bytes],
    stop: Optional[Callable[[], bool]] = None,
) -> Iterator[DecompEvent]:
    for event_name, data in iter_sse_frames(chunks, stop=stop):
        if data == "[DONE]":
            return
        try:
            payload = json.loads(data)
        except (ValueError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue
        event = normalize_event(event_name, payload)
        if event is None:
            continue
        yield event
        if event.type in TERMINAL_EVENTS:
            return


@dataclass
class StreamState:
    attempt: int = 0
    source: str = ""
    prose: list[str] = field(default_factory=list)
    renames: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    decomp_finished: bool = False
    finished: bool = False
    failed: bool = False
    error: str = ""
    error_code: Optional[str] = None
    names_applied: int = 0
    types_suggested: int = 0
    members_suggested: int = 0

    def reset_attempt(self, attempt: int) -> None:
        self.attempt = attempt
        self.source = ""
        self.prose = []
        self.renames = []
        self.warnings = []
        self.decomp_finished = False
        self.error = ""
        self.error_code = None

    def apply(self, event: DecompEvent) -> None:
        if event.attempt > self.attempt:
            self.reset_attempt(event.attempt)

        if event.type == EVENT_SOURCE_DELTA:
            self.source += event.content
        elif event.type == EVENT_SOURCE_RESET:
            self.source = ""
        elif event.type == EVENT_PROSE:
            if event.text:
                self.prose.append(event.text)
        elif event.type == EVENT_RENAME_APPLIED:
            self.renames.append((event.old_name, event.new_name))
        elif event.type == EVENT_WARNING:
            self.warnings.append(event.message or event.warning_kind)
        elif event.type == EVENT_TYPES_SUGGESTED:
            self.types_suggested = event.types
            self.members_suggested = event.members
        elif event.type == EVENT_DECOMP_FINISHED:
            self.decomp_finished = True
        elif event.type == EVENT_ATTEMPT_FAILED:
            self.error = event.error
        elif event.type == EVENT_DECOMP_FAILED:
            self.error = event.error
            self.error_code = event.error_code
            self.failed = True
        elif event.type == EVENT_NAMES_FINISHED:
            self.names_applied = event.applied
            self.finished = True

    @property
    def is_terminal(self) -> bool:
        return self.finished or self.failed

    def snapshot(self) -> "StreamState":
        return replace(
            self,
            prose=list(self.prose),
            renames=list(self.renames),
            warnings=list(self.warnings),
        )


def reduce_stream(events: Iterable[DecompEvent]) -> StreamState:
    state = StreamState()
    for event in events:
        state.apply(event)
    return state
