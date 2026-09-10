import pytest

import ida_typeinf
import idaapi
import idc
import libbs.artifacts

from reai_toolkit.app.transformations.import_data_types import (
    FunctionSignatures,
    ImportDataTypes,
    _Prototype,
    install_ghidra_primitives,
)

pytestmark = pytest.mark.idalib


@pytest.fixture
def func_ea(loaded_binary):
    ea = idc.get_name_ea_simple("sub_401020")
    assert ea != idaapi.BADADDR
    original = ida_typeinf.tinfo_t()
    had_type = idaapi.get_tinfo(original, ea)
    yield ea
    if had_type:
        ida_typeinf.apply_tinfo(ea, original, ida_typeinf.TINFO_DEFINITE)
    else:
        idc.SetType(ea, "")


def _arg(offset: int, name: str, type_str: str) -> libbs.artifacts.FunctionArgument:
    return libbs.artifacts.FunctionArgument(
        offset=offset, name=name, type_=type_str, size=8
    )


def _proto(function_id: int = 1, ret: str = "int", args: tuple = ()) -> _Prototype:
    return _Prototype(
        function_id=function_id,
        name="reai_test_func",
        return_type=ret,
        args=list(args),
    )


def _signature(function_id: int, parameters, return_id=None):
    return {
        "function_id": function_id,
        "function_name": "reai_test_func",
        "has_signature": True,
        "parameters": parameters,
        "return_data_type_id": return_id,
    }


def _base(data_type_id: int, name: str, size: int = 4):
    return {"data_type_id": data_type_id, "name": name, "kind": "BASE", "size": size}


def test_apply_function_type_sets_prototype_with_named_args(func_ea):
    idt = ImportDataTypes()
    proto = _proto(ret="int", args=(_arg(0, "count", "int"), _arg(1, "buf", "char *")))

    assert idt.apply_function_type(proto, func_ea) is True

    printed = ida_typeinf.print_type(func_ea, ida_typeinf.PRTYPE_1LINE)
    assert "count" in printed
    assert "buf" in printed
    assert "char *" in printed


def test_ghidra_primitive_names_resolve_after_install(loaded_binary):
    install_ghidra_primitives()

    from libbs.decompilers.ida.compat import convert_type_str_to_ida_type

    for name, size in (
        ("byte", 1),
        ("word", 2),
        ("dword", 4),
        ("qword", 8),
        ("sqword", 8),
        ("undefined", 1),
        ("undefined6", 6),
        ("float10", 10),
    ):
        tif = convert_type_str_to_ida_type(name)
        assert tif is not None, f"{name} did not resolve"
        assert tif.get_size() == size, f"{name} resolved at {tif.get_size()}, want {size}"


def test_install_ghidra_primitives_is_idempotent(loaded_binary):
    install_ghidra_primitives()

    assert install_ghidra_primitives() == 0


def test_apply_function_type_accepts_ghidra_primitives(func_ea):
    install_ghidra_primitives()
    idt = ImportDataTypes()
    proto = _proto(ret="uchar", args=(_arg(0, "n", "qword"), _arg(1, "flags", "dword")))

    assert idt.apply_function_type(proto, func_ea) is True

    printed = ida_typeinf.print_type(func_ea, ida_typeinf.PRTYPE_1LINE)
    assert "n" in printed
    assert "flags" in printed


def test_apply_function_type_keeps_args_when_remote_has_none(func_ea):
    idt = ImportDataTypes()
    assert idt.apply_function_type(_proto(ret="int", args=(_arg(0, "count", "int"),)), func_ea)

    assert idt.apply_function_type(_proto(ret="void", args=()), func_ea) is True

    printed = ida_typeinf.print_type(func_ea, ida_typeinf.PRTYPE_1LINE)
    assert "void" in printed
    assert "count" in printed


def test_apply_function_type_rejects_unparseable_arg(func_ea):
    idt = ImportDataTypes()
    proto = _proto(args=(_arg(0, "x", "totally bogus type!!"),))

    assert idt.apply_function_type(proto, func_ea) is False


def test_apply_function_type_missing_function(loaded_binary):
    idt = ImportDataTypes()

    assert idt.apply_function_type(_proto(), 0x1) is False


def test_execute_applies_via_mapping_and_reports_failures(func_ea):
    data_types = [_base(1, "int"), _base(2, "totally bogus type!!")]
    items = [
        _signature(1, [{"ordinal": 0, "name": "count", "data_type_id": 1}], return_id=1),
        _signature(2, [{"ordinal": 0, "name": "x", "data_type_id": 2}], return_id=1),
        _signature(3, [], return_id=1),
        _signature(4, [], return_id=1),
    ]
    signatures = FunctionSignatures(
        items=items,
        data_types={str(e["data_type_id"]): e for e in data_types},
    )
    mapping = {1: func_ea, 2: func_ea, 3: 0x1}

    failed = ImportDataTypes().execute(signatures, matched_function_mapping=mapping)

    assert failed == {2, 3, 4}
    printed = ida_typeinf.print_type(func_ea, ida_typeinf.PRTYPE_1LINE)
    assert "count" in printed
