"""Pure Server-Sent-Events frame parsing for the Agent Chat stream.

Reads blank-line delimited frames, so both the envelope's ``type`` and the SSE
``event:`` name are available — the backend transmits both, and omits ``event:``
only for the default ``message`` name. No Qt / IDA / SDK imports, so it is
unit-testable against a fake byte-chunk iterator.
"""

from __future__ import annotations

import json
from typing import Callable, Iterable, Iterator, Optional

from reai_toolkit.app.services.chat.schema import (
    TERMINAL_EVENTS,
    ChatEvent,
    normalize_event,
)
from reai_toolkit.app.services.sse import iter_sse_frames


def parse_sse_data(data: str) -> Optional[dict]:
    data = data.strip()
    if not data or data == "[DONE]":
        return None
    try:
        obj = json.loads(data)
    except (ValueError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


def event_from_frame(obj: dict, event_name: Optional[str] = None) -> Optional[ChatEvent]:
    """Turn a decoded ``{type, event_id, data}`` envelope into a ChatEvent."""
    ev = normalize_event(obj.get("type"), obj.get("data"), event_name)
    if ev is None:
        return None
    eid = obj.get("event_id")
    if isinstance(eid, int) and not isinstance(eid, bool):
        ev.event_id = eid
    return ev


def iter_sse_events(
    chunks: Iterable[bytes],
    stop: Optional[Callable[[], bool]] = None,
) -> Iterator[ChatEvent]:
    """Yield :class:`ChatEvent`\\ s parsed from an iterable of raw byte chunks.

    ``stop`` is polled between chunks for cooperative cancellation. Iteration
    stops after a terminal event (RUN_FINISHED / RUN_ERROR / RUN_CANCELLED).
    """
    for event_name, data in iter_sse_frames(chunks, stop=stop):
        obj = parse_sse_data(data)
        if obj is None:
            continue
        ev = event_from_frame(obj, event_name)
        if ev is None:
            continue
        yield ev
        if ev.type in TERMINAL_EVENTS:
            return
