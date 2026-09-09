import time
from unittest.mock import MagicMock

import pytest

import idautils
from revengai.models.comments_data import CommentsData
from revengai.models.decompilation_data import DecompilationData
from revengai.models.inline_comment import InlineComment
from revengai.models.summary_data import SummaryData
from revengai.models.task_status import TaskStatus
from revengai.models.get_tokens_response import GetTokensResponse
from revengai.models.rendered_token import RenderedToken

from reai_toolkit.app.services.ai_decomp import ai_decomp_service as svc_mod
from reai_toolkit.app.services.ai_decomp.ai_decomp_service import AiDecompService

pytestmark = pytest.mark.idalib


def test_service_runs_to_completion_under_idalib(loaded_binary, mocker):
    ea = next(iter(idautils.Functions()), None)
    assert ea is not None, "no functions in fixture binary"

    mocker.patch.object(svc_mod.AiDecompService, "yield_api_client")
    api_inst = MagicMock()
    mocker.patch.object(svc_mod, "FunctionsAIDecompilationApi", return_value=api_inst)
    api_inst.get_ai_decompilation.return_value = DecompilationData.model_construct(
        status=TaskStatus.COMPLETED.value, decompilation="int sub() { return 0; }"
    )
    api_inst.get_ai_decompilation_summary.return_value = SummaryData.model_construct(
        ai_summary="recovered summary", summary="", task_status=TaskStatus.COMPLETED.value
    )
    api_inst.get_ai_decompilation_inline_comments.return_value = (
        CommentsData.model_construct(
            inline_comments=[], task_status=TaskStatus.COMPLETED.value
        )
    )

    netstore = MagicMock()
    netstore.get_function_mapping.return_value.inverse_function_map = {str(ea): 7}

    service = AiDecompService(netstore_service=netstore, sdk_config=MagicMock())
    mocker.patch.object(svc_mod, "POLL_INTERVAL_SECONDS", 0.01)

    on_decomp, on_summary, on_comments = MagicMock(), MagicMock(), MagicMock()
    service.start_ai_decomp_task(
        ea=ea, on_decomp=on_decomp, on_summary=on_summary, on_comments=on_comments
    )
    deadline = time.monotonic() + 10.0
    while service.is_worker_running() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not service.is_worker_running(), "worker deadlocked under idalib"

    on_decomp.assert_called_once()
    result = on_decomp.call_args[0][0]
    assert result.success is True
    assert result.data.decompilation == "int sub() { return 0; }"
    api_inst.get_ai_decompilation.assert_called_once_with(function_id=7)


def _wait_mock(mock, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not mock.called and time.monotonic() < deadline:
        time.sleep(0.01)
    assert mock.called, "callback did not fire under idalib"


def test_mutations_and_refresh_under_idalib(loaded_binary, mocker):
    ea = next(iter(idautils.Functions()), None)
    assert ea is not None

    mocker.patch.object(svc_mod.AiDecompService, "yield_api_client")
    api_inst = MagicMock()
    mocker.patch.object(svc_mod, "FunctionsAIDecompilationApi", return_value=api_inst)
    api_inst.get_ai_decompilation.return_value = DecompilationData.model_construct(
        status=TaskStatus.COMPLETED.value, decompilation="int sub(int v1) { return v1; }"
    )
    api_inst.v3_get_ai_decompilation_tokens.return_value = GetTokensResponse.model_construct(
        ai_decomp="int @@F@@(int @@V@@) { return @@V@@; }",
        analysis_id=1,
        placeholder_to_rendered_token={
            "@@V@@": RenderedToken.model_construct(
                value="v1",
                kind="param",
                vaddr=None,
                data_type_id=None,
                function_id=None,
                imported_function_id=None,
            )
        },
        placeholder_to_user_override={},
    )
    api_inst.patch_ai_decompilation_inline_comment.return_value = (
        CommentsData.model_construct(
            inline_comments=[InlineComment.model_construct(comment="note", line=1)],
            task_status=TaskStatus.COMPLETED.value,
        )
    )
    api_inst.delete_ai_decompilation_inline_comment.return_value = (
        CommentsData.model_construct(
            inline_comments=[], task_status=TaskStatus.COMPLETED.value
        )
    )

    netstore = MagicMock()
    netstore.get_function_mapping.return_value.inverse_function_map = {str(ea): 7}
    service = AiDecompService(netstore_service=netstore, sdk_config=MagicMock())

    on_decomp, on_tok = MagicMock(), MagicMock()
    service.apply_overrides(
        ea=ea, overrides={"@@V@@": "count"}, on_decomp=on_decomp, on_tokenised=on_tok
    )
    _wait_mock(on_decomp)
    _wait_mock(on_tok)
    api_inst.v3_upsert_ai_decompilation_overrides.assert_called_once()
    assert on_decomp.call_args[0][0].success is True
    assert service._tokenised_cache[7] is not None

    on_set = MagicMock()
    service.set_comment(ea=ea, line=1, comment="note", on_result=on_set)
    _wait_mock(on_set)
    assert on_set.call_args[0][0].success is True
    assert service._comments_cache[7] is not None

    on_del = MagicMock()
    service.remove_comment(ea=ea, line=1, on_result=on_del)
    _wait_mock(on_del)
    assert on_del.call_args[0][0].success is True

    service.invalidate_ea(ea)
    assert 7 not in service._decomp_cache
    assert 7 not in service._tokenised_cache
    assert 7 not in service._comments_cache


def test_attribution_highlighting_primitives_under_idalib(loaded_binary):
    import ida_kernwin

    from reai_toolkit.hooks.reactive import ATTRIBUTION_BG_COLOR, LineAttributionHooks

    entry = ida_kernwin.line_rendering_output_entry_t(
        ida_kernwin.twinline_t(), ida_kernwin.LROEF_FULL_LINE, ATTRIBUTION_BG_COLOR
    )
    assert entry.is_bg_color_direct(), "a colour key would follow the theme, not our tint"
    assert entry.flags == ida_kernwin.LROEF_FULL_LINE

    hooks = LineAttributionHooks(MagicMock())
    assert not hooks.has_addresses()
    hooks.set_addresses([0x1000, 0x1000, 0x1004])
    assert hooks.has_addresses()
    hooks.unhook()
    assert not hooks.has_addresses()


def test_attribution_phase_resolves_real_addresses_under_idalib(loaded_binary, mocker):
    ea = next(iter(idautils.Functions()), None)
    assert ea is not None

    mocker.patch.object(svc_mod.AiDecompService, "yield_api_client")
    api_inst = MagicMock()
    mocker.patch.object(svc_mod, "FunctionsAIDecompilationApi", return_value=api_inst)
    core_inst = MagicMock()
    mocker.patch.object(svc_mod, "FunctionsCoreApi", return_value=core_inst)

    api_inst.get_ai_decompilation.return_value = DecompilationData.model_construct(
        status=TaskStatus.COMPLETED.value, decompilation="int sub() { return 0; }"
    )
    api_inst.get_ai_decompilation_summary.return_value = SummaryData.model_construct(
        ai_summary="", summary="", task_status=TaskStatus.COMPLETED.value
    )
    api_inst.get_ai_decompilation_inline_comments.return_value = (
        CommentsData.model_construct(
            inline_comments=[], task_status=TaskStatus.COMPLETED.value
        )
    )
    api_inst.v3_get_ai_decompilation_line_attributions.return_value = MagicMock(
        disassembly_line_number_to_ai_decompilation_line_numbers={"0": [1]}
    )
    core_inst.get_function_blocks_0.return_value = MagicMock(
        basic_blocks=[
            {"min_addr": ea, "asm": [f"{ea:#x} first", f"{ea + 1:#x} second"]}
        ]
    )

    netstore = MagicMock()
    netstore.get_function_mapping.return_value.inverse_function_map = {str(ea): 7}
    service = AiDecompService(netstore_service=netstore, sdk_config=MagicMock())

    on_attributions = MagicMock()
    service.start_ai_decomp_task(
        ea=ea,
        on_decomp=MagicMock(),
        on_summary=MagicMock(),
        on_comments=MagicMock(),
        on_attributions=on_attributions,
    )
    _wait_mock(on_attributions)

    mapping = on_attributions.call_args[0][0]
    assert mapping.addresses_for_decomp_line(1) == [ea + 1]
    assert mapping.decomp_lines_for_address(ea + 1) == [1]
