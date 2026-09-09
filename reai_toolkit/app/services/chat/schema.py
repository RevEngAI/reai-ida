"""Pure data model + event normalization for the Agent Chat feature.

Port of the Dashboard's ``utils/v2/agent/events.ts`` (+ ``agentApi.ts`` event
decoding) and ``components/features/AgentChat/types.ts``. This module has NO Qt /
IDA / SDK imports, so it is unit-testable in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar, Optional, Union

EVENT_TYPE_NAMES: dict[int, str] = {
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

TERMINAL_EVENTS: frozenset[str] = frozenset(
    {"RUN_FINISHED", "RUN_ERROR", "RUN_CANCELLED"}
)

ROLE_UNSPECIFIED = 0
ROLE_SYSTEM = 1
ROLE_USER = 2
ROLE_ASSISTANT = 3
ROLE_TOOL = 4
ROLE_DEVELOPER = 5


@dataclass
class EntityRef:
    id: int
    name: str = ""
    vaddr: int = 0


@dataclass
class EntityUpdate:
    """A backend entity a tool result reports as changed. Drives view refresh."""

    type: str
    ids: list[int]
    refs: list[EntityRef] = field(default_factory=list)


@dataclass
class ChatEvent:
    """A normalized agent event. Fields are a flattened superset of every event
    type; only the fields relevant to ``type`` are populated (mirrors the FE's
    discriminated union after ``parseApiEvent``)."""

    type: str
    message_id: Optional[str] = None
    delta: Optional[str] = None
    tool_call_id: Optional[str] = None
    tool_name: Optional[str] = None
    result: Optional[str] = None
    is_error: bool = False
    updated: Optional[list[EntityUpdate]] = None
    message: Optional[str] = None
    title: Optional[str] = None
    tool_args: str = ""
    role: Optional[str] = None
    event_id: Optional[int] = None


def resolve_type(type_field: Any) -> Optional[str]:
    """Resolve a wire ``type`` (string name or integer 1..16) to its name."""
    if isinstance(type_field, bool):
        return None
    if isinstance(type_field, str):
        return type_field or None
    if isinstance(type_field, int):
        return EVENT_TYPE_NAMES.get(type_field)
    return None


def _parse_refs(raw: Any) -> list[EntityRef]:
    if not isinstance(raw, list):
        return []
    out: list[EntityRef] = []
    for item in raw:
        if not isinstance(item, dict) or "id" not in item:
            continue
        try:
            out.append(
                EntityRef(
                    id=int(item["id"]),
                    name=str(item.get("name") or ""),
                    vaddr=int(item.get("vaddr") or 0),
                )
            )
        except (TypeError, ValueError):
            continue
    return out


def _parse_entity_updates(raw: Any) -> Optional[list[EntityUpdate]]:
    if not isinstance(raw, list):
        return None
    out: list[EntityUpdate] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        etype = item.get("type")
        ids = item.get("ids")
        if etype not in ("function", "analysis", "capabilities"):
            continue
        if not isinstance(ids, list):
            continue
        try:
            out.append(
                EntityUpdate(
                    type=etype,
                    ids=[int(i) for i in ids],
                    refs=_parse_refs(item.get("refs")),
                )
            )
        except (TypeError, ValueError):
            continue
    return out or None


def normalize_event(
    type_field: Any,
    leaf: Optional[dict],
    event_name: Optional[str] = None,
) -> Optional[ChatEvent]:
    """Normalize a raw SSE ``{type, data}`` frame into a :class:`ChatEvent`.

    ``leaf`` is the nested ``data`` object holding snake_case leaf fields.
    ``event_name`` is the SSE ``event:`` field, used when the envelope carries no
    resolvable ``type`` — a named event, or a numeric one this table predates.
    Returns ``None`` for unknown/undecodable event types (mirrors the FE's
    ``parseApiEvent`` returning null on parse failure).
    """
    etype = resolve_type(type_field) or (event_name or None)
    if etype is None:
        return None
    data: dict = leaf if isinstance(leaf, dict) else {}

    ev = ChatEvent(type=etype)
    ev.message_id = data.get("message_id")
    ev.delta = data.get("delta")
    ev.tool_call_id = data.get("tool_call_id")
    ev.tool_name = data.get("tool_name")
    ev.result = data.get("result")
    ev.is_error = bool(data.get("is_error", False))
    ev.updated = _parse_entity_updates(data.get("updated"))
    ev.title = data.get("title")
    ev.tool_args = data.get("tool_args") or ""
    ev.message = data.get("message") or data.get("error")
    if etype == "RUN_ERROR" and not ev.message:
        ev.message = "Unknown error"

    if etype == "TEXT_MESSAGE_START":
        ev.role = "assistant"
    else:
        role = data.get("role")
        ev.role = role if isinstance(role, str) else None
    return ev


@dataclass
class UserMessage:
    kind: ClassVar[str] = "user-message"
    id: str
    content: str


@dataclass
class AssistantMessage:
    kind: ClassVar[str] = "assistant-message"
    id: str
    content: str
    is_streaming: bool


@dataclass
class FunctionRef:
    """A function the agent touched, resolved to a local address for navigation."""

    ea: int
    name: str


@dataclass
class ToolCall:
    kind: ClassVar[str] = "tool-call"
    id: str
    name: str
    status: str
    is_error: bool
    functions: Optional[list[FunctionRef]] = None


@dataclass
class Step:
    kind: ClassVar[str] = "step"
    id: str
    step_name: str
    status: str


@dataclass
class ToolConfirmation:
    kind: ClassVar[str] = "tool-confirmation"
    id: str
    tool_name: str
    message: str
    status: str


@dataclass
class ContextCompacted:
    kind: ClassVar[str] = "context-compacted"
    id: str


ChatItem = Union[
    UserMessage,
    AssistantMessage,
    ToolCall,
    Step,
    ToolConfirmation,
    ContextCompacted,
]


@dataclass
class RunError:
    message: str
    code: Optional[str] = None
    doc_url: Optional[str] = None


@dataclass
class ChatState:
    items: list[ChatItem] = field(default_factory=list)
    title: Optional[str] = None
    run_status: str = "idle"
    run_error: Optional[RunError] = None


@dataclass
class ConversationContextDTO:
    """Plain context passed between coordinator and service (kept SDK-free)."""

    analysis_id: Optional[int] = None
    function_id: Optional[int] = None

    def is_empty(self) -> bool:
        return self.analysis_id is None and self.function_id is None


@dataclass
class UserMessageReplay:
    """Reconstructed user message emitted only during history replay."""

    id: str
    content: str


StoredEvent = Union[ChatEvent, UserMessageReplay]


@dataclass
class ConversationSummary:
    """Lightweight conversation row for the history browser."""

    conversation_uuid: str
    title: Optional[str] = None
    updated_at: Optional[str] = None


@dataclass
class ConversationReplay:
    """A full conversation reloaded from history, normalized for the reducer."""

    conversation_uuid: str
    title: Optional[str]
    events: list[StoredEvent]
