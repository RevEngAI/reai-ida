import queue
from unittest.mock import MagicMock

import pytest
from libbs.artifacts import (
    Function,
    FunctionArgument,
    FunctionHeader,
    StackVariable,
    Struct,
    StructMember,
    Typedef,
)
from revengai.exceptions import NotFoundException

from reai_toolkit.app.services.variable_sync import variable_sync_service as svc_mod
from reai_toolkit.app.services.variable_sync.variable_sync_service import (
    VariableSyncService,
)

ANALYSIS = 7


@pytest.fixture
def netstore():
    store = MagicMock()
    store.get_analysis_id.return_value = ANALYSIS
    return store


@pytest.fixture
def catalogue():
    cat = MagicMock()
    cat.ensure.return_value = {}
    cat.resolve.return_value = None
    return cat


@pytest.fixture
def service(netstore, catalogue):
    svc = VariableSyncService(
        netstore_service=netstore,
        sdk_config=MagicMock(),
        data_types_catalogue=catalogue,
    )
    VariableSyncService._q = queue.Queue()
    VariableSyncService._last_ts = {}
    return svc


@pytest.fixture
def sdk(mocker):
    mocker.patch.object(VariableSyncService, "yield_api_client")
    api_class = mocker.patch.object(svc_mod, "DataTypesApi")
    api = MagicMock()
    api_class.return_value = api
    return api


def _function(args=None, ret="int", stack_vars=None):
    return Function(
        addr=0x1000,
        header=FunctionHeader(name="f", addr=0x1000, type_=ret, args=args or {}),
        stack_vars=stack_vars or {},
    )


def _arg(offset, name, type_):
    return FunctionArgument(offset=offset, name=name, type_=type_, size=8)


def _attach(service, mocker, func):
    service.attach_decompiler(MagicMock())
    mocker.patch.object(svc_mod, "_read_decompiler_function", return_value=func)


def test_push_change_no_analysis_id_does_nothing(service, sdk, netstore):
    netstore.get_analysis_id.return_value = None

    service._push_change(1, 0x1000)

    sdk.v3_update_function_signature.assert_not_called()


def test_push_change_skips_when_no_decompiler(service, sdk):
    service._push_change(1, 0x1000)

    sdk.v3_update_function_signature.assert_not_called()


def test_push_change_puts_signature(service, sdk, mocker, catalogue):
    catalogue.resolve.side_effect = lambda _a, name: {"int": 1, "char *": 2}.get(name)
    _attach(service, mocker, _function(args={0: _arg(0, "count", "int")}, ret="int"))

    service._push_change(42, 0x1000)

    call = sdk.v3_update_function_signature.call_args.kwargs
    assert call["analysis_id"] == ANALYSIS
    assert call["function_id"] == 42
    body = call["update_function_signature_input_body"]
    assert body["return_data_type_id"] == 1
    assert body["parameters"] == [{"ordinal": 0, "name": "count", "data_type_id": 1}]


def test_parameter_ordinals_match_list_index(service, sdk, mocker, catalogue):
    catalogue.resolve.return_value = 1
    args = {2: _arg(2, "c", "int"), 0: _arg(0, "a", "int"), 1: _arg(1, "b", "int")}
    _attach(service, mocker, _function(args=args))

    service._push_change(42, 0x1000)

    body = sdk.v3_update_function_signature.call_args.kwargs[
        "update_function_signature_input_body"
    ]
    assert [p["ordinal"] for p in body["parameters"]] == [0, 1, 2]
    assert [p["name"] for p in body["parameters"]] == ["a", "b", "c"]


def test_unresolved_type_is_sent_as_none(service, sdk, mocker, catalogue):
    catalogue.resolve.return_value = None
    _attach(service, mocker, _function(args={0: _arg(0, "x", "MysteryType")}, ret=None))

    service._push_change(42, 0x1000)

    body = sdk.v3_update_function_signature.call_args.kwargs[
        "update_function_signature_input_body"
    ]
    assert body["parameters"][0]["data_type_id"] is None
    assert body["return_data_type_id"] is None


def test_not_found_is_treated_as_nothing_to_edit(service, sdk, mocker, caplog):
    sdk.v3_update_function_signature.side_effect = NotFoundException(
        status=404, reason="Not Found"
    )
    _attach(service, mocker, _function())

    service._push_change(42, 0x1000)

    assert sdk.v3_update_function_signature.called


def test_ensure_is_given_the_local_type_closure(service, sdk, mocker, catalogue):
    node = Struct(
        name="Node",
        size=8,
        members={0: StructMember(name="next", offset=0, type_="Alias", size=8)},
    )
    alias = Typedef(name="Alias", type_="int")
    named = {"Node": node, "Alias": alias}
    mocker.patch.object(
        svc_mod, "_read_named_type", side_effect=lambda _d, name: named.get(name)
    )
    _attach(service, mocker, _function(args={0: _arg(0, "n", "Node *")}, ret="int"))

    service._push_change(42, 0x1000)

    passed = catalogue.ensure.call_args.args[1]
    assert set(passed) == {"Node", "Alias"}


def test_stack_variable_types_reach_the_catalogue(service, sdk, mocker, catalogue):
    local = Struct(name="Local", size=4, members={})
    mocker.patch.object(
        svc_mod, "_read_named_type", side_effect=lambda _d, name: {"Local": local}.get(name)
    )
    stack_vars = {
        0: StackVariable(stack_offset=0, name="v", type_="Local", size=4, addr=0x1000)
    }
    _attach(service, mocker, _function(stack_vars=stack_vars, ret=None))

    service._push_change(42, 0x1000)

    passed = catalogue.ensure.call_args.args[1]
    assert "Local" in passed


def test_type_closure_is_capped(service, sdk, mocker, catalogue):
    def endless(_deci, name):
        index = int(name[1:]) if name[1:].isdigit() else 0
        return Typedef(name=name, type_=f"T{index + 1}")

    mocker.patch.object(svc_mod, "_read_named_type", side_effect=endless)
    _attach(service, mocker, _function(args={0: _arg(0, "x", "T0")}, ret=None))

    service._push_change(42, 0x1000)

    passed = catalogue.ensure.call_args.args[1]
    assert len(passed) == svc_mod.MAX_TYPE_DEPENDENCIES


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Foo *", "Foo"),
        ("const struct Bar *", "Bar"),
        ("unsigned int", "int"),
        ("char[16]", "char"),
        ("", None),
        (None, None),
    ],
)
def test_base_type_name(raw, expected):
    assert VariableSyncService._base_type_name(raw) == expected


def test_push_local_types_batch_noop_without_targets_or_analysis(service, sdk):
    assert service.push_local_function_types_batch({}, ANALYSIS) == 0
    assert service.push_local_function_types_batch({1: 0x1000}, None) == 0
    sdk.v3_update_function_signature.assert_not_called()


def test_push_local_types_batch_counts_successful_puts(service, sdk, mocker, catalogue):
    catalogue.resolve.return_value = 1
    deci = MagicMock()
    deci.binary_base_addr = 0
    service.attach_decompiler(deci)
    mocker.patch.object(svc_mod, "_read_decompiler_function", return_value=_function())

    assert service.push_local_function_types_batch({1: 0x1000, 2: 0x2000}, ANALYSIS) == 2
    assert sdk.v3_update_function_signature.call_count == 2


def test_push_local_types_batch_skips_functions_without_a_stored_signature(
    service, sdk, mocker, catalogue
):
    sdk.v3_update_function_signature.side_effect = [
        None,
        NotFoundException(status=404, reason="Not Found"),
    ]
    deci = MagicMock()
    deci.binary_base_addr = 0
    service.attach_decompiler(deci)
    mocker.patch.object(svc_mod, "_read_decompiler_function", return_value=_function())

    assert service.push_local_function_types_batch({1: 0x1000, 2: 0x2000}, ANALYSIS) == 1


def test_enqueue_change_debounces_rapid_duplicates(service, mocker):
    mocker.patch.object(VariableSyncService, "_start_worker_if_needed")
    header = FunctionHeader(name="f", addr=0x1000)

    service.enqueue_change(1, 0x1000, header)
    service.enqueue_change(1, 0x1000, header)

    assert service._q.qsize() == 1
