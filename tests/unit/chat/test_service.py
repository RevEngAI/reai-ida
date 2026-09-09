"""ChatService tests — mock ConversationsApi, assert requests + error mapping."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from revengai import (
    ApiException,
    ConversationContext,
    CreateConversationRequest,
    SendMessageRequest,
)

from reai_toolkit.app.services.chat import chat_service as svc_mod
from reai_toolkit.app.services.chat.chat_service import ChatService
from reai_toolkit.app.services.chat.schema import (
    ConversationContextDTO,
    UserMessageReplay,
)


@pytest.fixture
def service():
    return ChatService(netstore_service=MagicMock(), sdk_config=MagicMock())


@pytest.fixture
def api(mocker):
    mocker.patch.object(svc_mod.ChatService, "yield_api_client")
    api_class = mocker.patch.object(svc_mod, "ConversationsApi")
    inst = MagicMock()
    api_class.return_value = inst
    return inst


def test_create_conversation_returns_uuid_and_sends_context(service, api):
    api.create_conversation.return_value = SimpleNamespace(conversation_uuid="uuid-1")
    ctx = ConversationContextDTO(analysis_id=7, function_id=42)

    res = service.create_conversation(ctx, title="hi")

    assert res.success is True
    assert res.data == "uuid-1"
    req = api.create_conversation.call_args[0][0]
    assert isinstance(req, CreateConversationRequest)
    assert req.title == "hi"
    assert isinstance(req.context, ConversationContext)
    assert req.context.analysis_id == 7
    assert req.context.function_id == 42


def test_create_conversation_error_maps(service, api):
    api.create_conversation.side_effect = ApiException(status=500, reason="boom")
    res = service.create_conversation(None)
    assert res.success is False
    assert res.error_message


def test_send_message_builds_request(service, api):
    cid = "11111111-1111-1111-1111-111111111111"
    res = service.send_message(cid, "hello", ConversationContextDTO(analysis_id=1))
    assert res.success is True
    conv_arg = api.send_message.call_args[0][0]
    req = api.send_message.call_args[0][1]
    assert str(conv_arg) == cid
    assert isinstance(req, SendMessageRequest)
    assert req.content == "hello"
    assert req.context.analysis_id == 1


def test_send_message_409_is_tolerated(service, api):
    api.send_message.side_effect = ApiException(status=409)
    res = service.send_message("11111111-1111-1111-1111-111111111111", "x", None)
    assert res.success is True


def test_send_message_other_error_fails(service, api):
    api.send_message.side_effect = ApiException(status=402, reason="pay up")
    res = service.send_message("11111111-1111-1111-1111-111111111111", "x", None)
    assert res.success is False


def test_confirm_tool_404_is_tolerated(service, api):
    api.confirm_tool.side_effect = ApiException(status=404)
    res = service.confirm_tool("11111111-1111-1111-1111-111111111111", True)
    assert res.success is True


def test_cancel_run_404_is_tolerated(service, api):
    api.cancel_run.side_effect = ApiException(status=404)
    res = service.cancel_run("11111111-1111-1111-1111-111111111111")
    assert res.success is True


def test_list_conversations_maps_summaries(service, api):
    api.list_conversations.return_value = [
        SimpleNamespace(conversation_uuid="a", title="A", updated_at="2026-01-01"),
        SimpleNamespace(conversation_uuid="b", title=None, updated_at=None),
    ]
    res = service.list_conversations()
    assert res.success is True
    assert [s.conversation_uuid for s in res.data] == ["a", "b"]
    assert res.data[0].title == "A"


def test_get_conversation_replays_events(service, api):
    events = [
        SimpleNamespace(type=6, role=2, data={"message_id": "u1"}, event_id=1),
        SimpleNamespace(type=7, role=2, data={"delta": "why?"}, event_id=2),
        SimpleNamespace(type=8, role=2, data={}, event_id=3),
        SimpleNamespace(type=6, role=3, data={"message_id": "a1"}, event_id=4),
        SimpleNamespace(type=7, role=3, data={"delta": "because"}, event_id=5),
        SimpleNamespace(type=8, role=3, data={}, event_id=6),
    ]
    api.get_conversation.return_value = SimpleNamespace(
        conversation_uuid="cid", title="T", events=events
    )
    res = service.get_conversation("11111111-1111-1111-1111-111111111111")
    assert res.success is True
    replay = res.data
    assert replay.title == "T"
    assert isinstance(replay.events[0], UserMessageReplay)
    assert replay.events[0].content == "why?"
    assert any(getattr(e, "type", None) == "TEXT_MESSAGE_CONTENT" for e in replay.events)


def test_get_function_name(service, mocker):
    mocker.patch.object(svc_mod.ChatService, "yield_api_client")
    fapi_class = mocker.patch.object(svc_mod, "FunctionsCoreApi")
    inst = MagicMock()
    fapi_class.return_value = inst
    inst.get_function_details_0.return_value = SimpleNamespace(
        function_name="chat_agent_renamed"
    )

    res = service.get_function_name(408140)

    assert res.success is True
    assert res.data == "chat_agent_renamed"
    inst.get_function_details_0.assert_called_once_with(function_id=408140)


def test_get_function_name_error_maps(service, mocker):
    mocker.patch.object(svc_mod.ChatService, "yield_api_client")
    fapi_class = mocker.patch.object(svc_mod, "FunctionsCoreApi")
    inst = MagicMock()
    fapi_class.return_value = inst
    inst.get_function_details_0.side_effect = ApiException(status=404, reason="gone")

    res = service.get_function_name(1)

    assert res.success is False
    assert res.error_message


def test_to_sdk_context_none_for_empty():
    assert ChatService._to_sdk_context(None) is None
    assert ChatService._to_sdk_context(ConversationContextDTO()) is None
    ctx = ChatService._to_sdk_context(ConversationContextDTO(analysis_id=3))
    assert isinstance(ctx, ConversationContext)
    assert ctx.analysis_id == 3
