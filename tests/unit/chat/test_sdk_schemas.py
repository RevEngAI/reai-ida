"""Schema-shape assertions: fail loudly if the revengai conversation API drifts."""

import revengai
from revengai import (
    ConfirmToolInputBody,
    Conversation,
    ConversationContext,
    ConversationsApi,
    ConversationWithEvents,
    CreateConversationRequest,
    SendMessageRequest,
)
from revengai.models.event import Event

from reai_toolkit.app.services.chat.schema import EVENT_TYPE_NAMES


def test_conversations_api_has_expected_methods():
    for name in (
        "create_conversation",
        "send_message",
        "confirm_tool",
        "cancel_run",
        "get_conversation",
        "list_conversations",
        "stream_events_without_preload_content",
    ):
        assert hasattr(ConversationsApi, name), name


def test_create_conversation_request_fields():
    assert {"context", "title"} <= set(CreateConversationRequest.model_fields)


def test_send_message_request_fields():
    assert {"content", "context"} <= set(SendMessageRequest.model_fields)


def test_conversation_context_fields():
    assert {"analysis_id", "function_id"} <= set(ConversationContext.model_fields)


def test_confirm_tool_input_body_field():
    assert "approved" in ConfirmToolInputBody.model_fields


def test_conversation_fields():
    assert "conversation_uuid" in Conversation.model_fields


def test_conversation_with_events_fields():
    assert {"conversation_uuid", "events"} <= set(ConversationWithEvents.model_fields)


def test_event_fields():
    assert {"type", "role", "data", "event_id"} <= set(Event.model_fields)


def _sdk_agent_event_names() -> set[str]:
    names = set()
    for attr in dir(revengai):
        if not attr.startswith("Event"):
            continue
        suffix = attr[len("Event"):]
        if suffix and suffix.isupper():
            names.add(suffix)
    return names


def test_every_agent_event_the_sdk_types_can_be_named_by_the_numeric_table():
    known = {name.replace("_", "") for name in EVENT_TYPE_NAMES.values()}
    missing = sorted(_sdk_agent_event_names() - known)

    assert missing == [], (
        "the SDK types agent events this plugin cannot name; a numerically typed "
        f"replay of one would decode as the wrong event: {missing}"
    )


def test_the_replay_type_is_numeric_so_the_table_is_load_bearing():
    assert Event.model_fields["type"].annotation is int
