import queue
from unittest.mock import MagicMock

import pytest
from libbs.artifacts import FunctionArgument, FunctionHeader, StackVariable
from revengai import ApiException, Argument, FunctionInfo, FunctionType
from revengai.models.function_header import FunctionHeader as SdkFunctionHeader
from revengai.models.stack_variable import StackVariable as SdkStackVariable

from reai_toolkit.app.services.variable_sync import variable_sync_service as svc_mod
from reai_toolkit.app.services.variable_sync.variable_sync_service import VariableSyncService


@pytest.fixture
def netstore():
    return MagicMock()


@pytest.fixture
def service(netstore):
    svc = VariableSyncService(netstore_service=netstore, sdk_config=MagicMock())
    VariableSyncService._q = queue.Queue()
    VariableSyncService._last_ts = {}
    return svc


@pytest.fixture
def sdk(mocker):
    context = mocker.patch.object(VariableSyncService, "yield_api_client")
    api_client = MagicMock()
    context.return_value.__enter__.return_value = api_client
    return api_client


def _sdk_stack_var(offset: int, name: str, type_: str) -> SdkStackVariable:
    return SdkStackVariable.model_construct(
        last_change=None, offset=offset, name=name, type=type_, size=8, addr=0x1000
    )


def _sdk_arg(offset: int, name: str, type_: str) -> Argument:
    return Argument.model_construct(
        last_change=None, offset=offset, name=name, type=type_, size=8
    )


def _function_info(stack_vars=None, args=None, ret_type="void") -> FunctionInfo:
    header = SdkFunctionHeader.model_construct(
        last_change=None,
        name="f",
        addr=0x1000,
        type=ret_type,
        args=args or {},
    )
    func_types = FunctionType.model_construct(
        last_change=None,
        addr=0x1000,
        size=10,
        header=header,
        stack_vars=stack_vars or {},
        name="f",
        type=ret_type,
        artifact_type="Function",
    )
    return FunctionInfo.model_construct(func_types=func_types, func_deps=[])


def _signature_response(function_id=42):
    return {
        "items": [
            {
                "analysis_id": 7,
                "function_id": function_id,
                "function_name": "f",
                "has_signature": True,
                "parameters": [
                    {"ordinal": 0, "name": "arg", "data_type_id": 1},
                ],
                "return_data_type_id": 1,
            }
        ],
        "data_types": [
            {
                "analysis_id": 7,
                "items": [
                    {"data_type_id": 1, "kind": "BASE", "name": "int", "size": 4},
                ],
            }
        ],
    }


def test_patch_stack_var_matches_by_offset(service):
    info = _function_info(stack_vars={"-0x20": _sdk_stack_var(-32, "local_20", "char")})

    changed = service._patch(
        info,
        StackVariable(stack_offset=-32, name="counter", type_="int", size=4, addr=0x0),
    )

    assert changed is True
    entry = info.func_types.stack_vars["-0x20"]
    assert entry.name == "counter"
    assert entry.type == "int"


def test_patch_header_updates_arg_and_return_type(service):
    info = _function_info(args={"0x0": _sdk_arg(0, "a1", "int")}, ret_type="void")
    fheader = FunctionHeader(
        name="f",
        addr=0x0,
        type_="int",
        args={0: FunctionArgument(offset=0, name="count", type_="size_t", size=8)},
    )

    changed = service._patch(info, fheader)

    assert changed is True
    assert info.func_types.header.args["0x0"].name == "count"
    assert info.func_types.header.args["0x0"].type == "size_t"
    assert info.func_types.header.type == "int"
    assert info.func_types.type == "int"


def test_push_local_types_batch_uses_v3_signature_update(service, sdk, mocker):
    service._deci = MagicMock(binary_base_addr=0x400000)
    build = mocker.patch.object(
        service,
        "_build_function_info",
        return_value=_function_info(args={"0x0": _sdk_arg(0, "arg", "int")}, ret_type="int"),
    )
    mocker.patch.object(
        svc_mod, "list_function_signatures", return_value=_signature_response(1)
    )
    update = mocker.patch.object(svc_mod, "update_function_signature")

    updated = service.push_local_function_types_batch({1: 0x401000}, analysis_id=7)

    assert updated == 1
    build.assert_called_once_with(0x1000)
    update.assert_called_once()
    assert update.call_args.args[1:3] == (7, 1)
    assert update.call_args.args[3] == {
        "parameters": [{"ordinal": 0, "name": "arg", "data_type_id": 1}],
        "return_data_type_id": 1,
    }


def test_push_local_types_batch_noop_without_targets_or_analysis(service, sdk, mocker):
    list_signatures = mocker.patch.object(svc_mod, "list_function_signatures")

    service._deci = MagicMock()
    assert service.push_local_function_types_batch({}, analysis_id=1) == 0
    assert service.push_local_function_types_batch({1: 0x1000}, analysis_id=None) == 0
    list_signatures.assert_not_called()


def test_push_change_updates_function_signature(service, sdk, netstore, mocker):
    netstore.get_analysis_id.return_value = 7
    mocker.patch.object(
        service,
        "_build_function_info",
        return_value=_function_info(args={"0x0": _sdk_arg(0, "arg", "int")}, ret_type="int"),
    )
    mocker.patch.object(
        svc_mod, "list_function_signatures", return_value=_signature_response(42)
    )
    update = mocker.patch.object(svc_mod, "update_function_signature")

    service._push_change(
        42,
        0x2668,
        FunctionHeader(
            name=None,
            addr=0x2668,
            type_=None,
            args={0: FunctionArgument(offset=0, name="arg", type_="int", size=4)},
        ),
    )

    update.assert_called_once()
    assert update.call_args.args[1] == 7
    assert update.call_args.args[2] == 42


def test_push_change_skips_stack_variable_write_because_v3_has_no_endpoint(
    service, sdk, netstore, mocker
):
    netstore.get_analysis_id.return_value = 7
    build = mocker.patch.object(service, "_build_function_info")
    list_signatures = mocker.patch.object(svc_mod, "list_function_signatures")
    update = mocker.patch.object(svc_mod, "update_function_signature")

    service._push_change(
        42,
        0x2668,
        StackVariable(stack_offset=-32, name="n", type_="int", size=4, addr=0x0),
    )

    build.assert_not_called()
    list_signatures.assert_not_called()
    update.assert_not_called()


def test_push_change_swallows_v3_api_error(service, sdk, netstore, mocker):
    netstore.get_analysis_id.return_value = 7
    mocker.patch.object(service, "_build_function_info", return_value=_function_info())
    mocker.patch.object(
        svc_mod,
        "list_function_signatures",
        side_effect=ApiException(status=404, reason="Not Found"),
    )

    service._push_change(
        42,
        0x2668,
        FunctionHeader(name=None, addr=0x2668, type_=None, args={}),
    )


def test_collect_func_deps_resolves_typedef_chain(service, mocker):
    from libbs.artifacts import Typedef

    service.attach_decompiler(MagicMock())
    func_type = _function_info(args={"0x0": _sdk_arg(0, "d", "dev_t")}, ret_type="int").func_types

    chain = {
        "dev_t": Typedef(name="dev_t", type_="__dev_t"),
        "__dev_t": Typedef(name="__dev_t", type_="unsigned long"),
    }
    mocker.patch.object(
        svc_mod, "_read_named_type", side_effect=lambda deci, name: chain.get(name)
    )

    deps = service._collect_func_deps(func_type)

    assert sorted(d.name for d in deps) == ["__dev_t", "dev_t"]


def test_push_change_no_analysis_id_does_nothing(service, sdk, netstore, mocker):
    netstore.get_analysis_id.return_value = None
    list_signatures = mocker.patch.object(svc_mod, "list_function_signatures")

    service._push_change(
        42,
        0x2668,
        StackVariable(stack_offset=-32, name="n", type_="int", size=4, addr=0x0),
    )

    list_signatures.assert_not_called()


def test_enqueue_change_debounces_rapid_duplicates(service, mocker):
    mocker.patch.object(service, "_start_worker_if_needed")
    svar = StackVariable(stack_offset=-32, name="a", type_="int", size=4, addr=0x0)

    service.enqueue_change(42, 0x2668, svar)
    service.enqueue_change(42, 0x2668, svar)

    assert service._q.qsize() == 1
