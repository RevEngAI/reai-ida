"""
Schema-shape assertions: fail loudly when the revengai SDK shape drifts.
"""

import inspect

from revengai import FunctionsAIDecompilationApi
from revengai.models.comments_data import CommentsData
from revengai.models.create_ai_decomp_output_body import CreateAIDecompOutputBody
from revengai.models.get_tokens_response import GetTokensResponse
from revengai.models.inline_comment import InlineComment
from revengai.models.patch_comment_body import PatchCommentBody
from revengai.models.rendered_token import RenderedToken
from revengai.models.summary_data import SummaryData
from revengai.models.task_status import TaskStatus
from revengai.models.token import Token
from revengai.models.upsert_overrides_data import UpsertOverridesData
from revengai.models.upsert_overrides_input_body import UpsertOverridesInputBody
from revengai.models.workflow_progress import WorkflowProgress


def test_ai_decomp_api_exposes_the_methods_the_plugin_calls():
    for method in (
        "create_ai_decompilation",
        "get_ai_decompilation",
        "get_ai_decompilation_status",
        "get_ai_decompilation_summary",
        "get_ai_decompilation_summary_status",
        "regenerate_ai_decompilation_summary",
        "get_ai_decompilation_inline_comments",
        "get_ai_decompilation_inline_comments_status",
        "regenerate_ai_decompilation_inline_comments",
        "patch_ai_decompilation_inline_comment",
        "delete_ai_decompilation_inline_comment",
        "upsert_ai_decompilation_rating",
        "v3_get_ai_decompilation_tokens",
        "v3_upsert_ai_decompilation_overrides",
    ):
        assert callable(getattr(FunctionsAIDecompilationApi, method))


def test_v3_token_methods_accept_plugin_kwargs():
    tokens = inspect.signature(
        FunctionsAIDecompilationApi.v3_get_ai_decompilation_tokens
    ).parameters
    assert "function_id" in tokens

    overrides = inspect.signature(
        FunctionsAIDecompilationApi.v3_upsert_ai_decompilation_overrides
    ).parameters
    assert {"function_id", "upsert_overrides_input_body"} <= set(overrides)


def test_workflow_progress_has_expected_fields():
    fields = set(WorkflowProgress.model_fields.keys())
    assert {"status", "step", "step_index", "steps_total", "messages"} <= fields


def test_get_tokens_response_carries_source_and_both_token_maps():
    assert {
        "ai_decomp",
        "analysis_id",
        "placeholder_to_rendered_token",
        "placeholder_to_user_override",
    } <= set(GetTokensResponse.model_fields)


def test_get_tokens_response_has_no_status_so_readiness_is_the_empty_source():
    assert "status" not in GetTokensResponse.model_fields


def test_rendered_token_carries_value_kind_and_the_renamed_elsewhere_ids():
    assert {
        "value",
        "kind",
        "data_type_id",
        "function_id",
        "imported_function_id",
    } <= set(RenderedToken.model_fields)


def test_rendered_token_kinds_cover_what_the_panel_offers_to_rename():
    tokens = GetTokensResponse.from_json(
        '{"ai_decomp": "@@V@@;", "analysis_id": 1,'
        ' "placeholder_to_rendered_token": {"@@V@@": {"kind": "local", "value": "v5"}},'
        ' "placeholder_to_user_override": {}}'
    )
    rendered = tokens.placeholder_to_rendered_token["@@V@@"]
    assert rendered.value == "v5"
    assert rendered.data_type_id is None


def test_predicted_function_name_now_rides_on_the_summary():
    assert "predicted_function_name" in SummaryData.model_fields


def test_create_output_body_has_status():
    assert "status" in CreateAIDecompOutputBody.model_fields


def test_task_status_enum_covers_state_machine():
    members = set(TaskStatus.__members__)
    assert {"UNINITIALISED", "PENDING", "RUNNING", "COMPLETED", "FAILED"} <= members


def test_workflow_progress_accepts_uppercase_status_values():
    for status in ("UNINITIALISED", "PENDING", "RUNNING", "COMPLETED", "FAILED"):
        WorkflowProgress.model_construct(
            status=status, step="x", step_index=0, steps_total=1, messages=[]
        )


def test_overrides_are_posted_as_token_objects_not_bare_strings():
    body = UpsertOverridesInputBody.from_json(
        '{"overrides": {"@@V@@": {"value": "buf"}}}'
    )
    assert body.overrides == {"@@V@@": Token(value="buf")}


def test_upsert_overrides_data_returns_the_override_map():
    data = UpsertOverridesData.from_json(
        '{"placeholder_to_user_override": {"@@V@@": {"value": "buf"}}}'
    )
    assert data.placeholder_to_user_override["@@V@@"].value == "buf"


def test_patch_comment_body_round_trips():
    body = PatchCommentBody.from_json('{"comment": "note", "line": 7}')
    assert body.comment == "note"
    assert body.line == 7
    assert {"comment", "line"} <= set(PatchCommentBody.model_fields.keys())


def test_inline_comment_and_comments_data_shapes():
    assert {"comment", "line"} <= set(InlineComment.model_fields.keys())
    assert {"inline_comments", "task_status"} <= set(CommentsData.model_fields.keys())
