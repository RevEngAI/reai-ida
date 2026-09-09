from unittest.mock import MagicMock

import pytest

from reai_toolkit.app.transformations import import_data_types as mod
from reai_toolkit.app.transformations.import_data_types import (
    APPLY_CHUNK_SIZE,
    FunctionSignatures,
    ImportDataTypes,
    normalise_type,
)


@pytest.fixture
def deci(mocker):
    instance = MagicMock()
    instance.art_lifter.lift_addr.side_effect = lambda addr: addr
    mocker.patch.object(mod.DecompilerInterface, "discover", return_value=instance)
    mocker.patch.object(ImportDataTypes, "_install_primitives")
    return instance


def _signature(function_id: int, has_signature=True, parameters=None, return_id=None):
    return {
        "function_id": function_id,
        "function_name": f"fn_{function_id}",
        "has_signature": has_signature,
        "parameters": parameters or [],
        "return_data_type_id": return_id,
    }


def _param(ordinal: int, data_type_id: int, name=None):
    return {"ordinal": ordinal, "data_type_id": data_type_id, "name": name}


def _base(data_type_id: int, name: str, size: int = 4):
    return {"data_type_id": data_type_id, "name": name, "kind": "BASE", "size": size}


def _struct(data_type_id: int, name: str, member_type_id: int, size: int = 8):
    return {
        "data_type_id": data_type_id,
        "name": name,
        "kind": "STRUCT",
        "size": size,
        "definition": {
            "members": [
                {"name": "field0", "offset": 0, "size": 8, "data_type_id": member_type_id}
            ]
        },
    }


def _typedef(data_type_id: int, name: str, target_id: int):
    return {
        "data_type_id": data_type_id,
        "name": name,
        "kind": "TYPEDEF",
        "size": 4,
        "definition": {"target_data_type_id": target_id},
    }


def _enum(data_type_id: int, name: str):
    return {
        "data_type_id": data_type_id,
        "name": name,
        "kind": "ENUM",
        "size": 4,
        "definition": {"values": [{"name": "RED", "value": "0"}]},
    }


def _sigs(items, data_types=()):
    return FunctionSignatures(
        items=items,
        data_types={str(entry["data_type_id"]): entry for entry in data_types},
    )


def test_execute_no_items_skips_everything(deci):
    idt = ImportDataTypes()

    assert idt.execute(_sigs([_signature(1, has_signature=False)])) == set()
    mod.DecompilerInterface.discover.assert_not_called()


def test_execute_skips_discover_without_dependencies(deci, mocker):
    apply = mocker.patch.object(ImportDataTypes, "apply_function_type", return_value=True)
    idt = ImportDataTypes()

    failed = idt.execute(_sigs([_signature(1)]), matched_function_mapping={1: 0x1000})

    assert failed == set()
    apply.assert_called_once()
    mod.DecompilerInterface.discover.assert_not_called()


def test_execute_applies_shared_dependency_once(deci, mocker):
    mocker.patch.object(ImportDataTypes, "apply_function_type", return_value=True)
    types = [_base(1, "int"), _struct(2, "SharedStruct", 1)]
    items = [
        _signature(10, parameters=[_param(0, 2)]),
        _signature(11, parameters=[_param(0, 2)]),
    ]

    ImportDataTypes().execute(
        _sigs(items, types), matched_function_mapping={10: 0x1000, 11: 0x2000}
    )

    struct_writes = [c for c in deci.structs.mock_calls if "__setitem__" in str(c)]
    assert len(struct_writes) == 1


def test_execute_applies_subdependency_before_parent(deci, mocker):
    mocker.patch.object(ImportDataTypes, "apply_function_type", return_value=True)
    types = [
        _base(1, "int"),
        _typedef(2, "td_t", 1),
        _struct(3, "Parent", 2),
        _enum(4, "Colors"),
    ]
    items = [_signature(10, parameters=[_param(0, 3), _param(1, 4)])]

    ImportDataTypes().execute(_sigs(items, types), matched_function_mapping={10: 0x1000})

    writes = [c[0] for c in deci.mock_calls if "__setitem__" in c[0]]
    assert writes.index("typedefs.__setitem__") < writes.index("structs.__setitem__")
    assert "enums.__setitem__" in writes


def test_execute_survives_dependency_failure(deci, mocker):
    apply = mocker.patch.object(ImportDataTypes, "apply_function_type", return_value=True)
    deci.enums.__setitem__.side_effect = RuntimeError("til write failed")
    items = [_signature(10, parameters=[_param(0, 4)])]

    failed = ImportDataTypes().execute(
        _sigs(items, [_enum(4, "Colors")]), matched_function_mapping={10: 0x1000}
    )

    assert failed == set()
    apply.assert_called_once()


def test_self_referential_struct_terminates(deci, mocker):
    mocker.patch.object(ImportDataTypes, "apply_function_type", return_value=True)
    pointer = {
        "data_type_id": 2,
        "name": "Node *",
        "kind": "POINTER",
        "size": 8,
        "definition": {"pointee_data_type_id": 1},
    }
    node = _struct(1, "Node", 2)
    items = [_signature(10, parameters=[_param(0, 1)])]

    failed = ImportDataTypes().execute(
        _sigs(items, [node, pointer]), matched_function_mapping={10: 0x1000}
    )

    assert failed == set()
    struct_writes = [c for c in deci.structs.mock_calls if "__setitem__" in str(c)]
    assert len(struct_writes) == 1


def test_execute_chunks_and_aggregates_failures(deci, mocker):
    total = APPLY_CHUNK_SIZE + 5
    apply = mocker.patch.object(
        ImportDataTypes, "apply_function_type", side_effect=lambda proto, ea: ea % 2 == 0
    )
    items = [_signature(fid) for fid in range(total)]
    mapping = {fid: fid for fid in range(total)}

    failed = ImportDataTypes().execute(_sigs(items), matched_function_mapping=mapping)

    assert apply.call_count == total
    assert failed == {fid for fid in range(total) if fid % 2 == 1}


def test_execute_uses_mapping_and_fails_unmapped(deci, mocker):
    seen: list[int] = []

    def record(proto, ea):
        seen.append(ea)
        return True

    mocker.patch.object(ImportDataTypes, "apply_function_type", side_effect=record)
    items = [_signature(1), _signature(2)]

    failed = ImportDataTypes().execute(_sigs(items), matched_function_mapping={1: 0x9000})

    assert seen == [0x9000]
    assert failed == {2}


def test_execute_skips_items_without_signature(deci, mocker):
    apply = mocker.patch.object(ImportDataTypes, "apply_function_type", return_value=True)

    failed = ImportDataTypes().execute(_sigs([_signature(1, has_signature=False)]))

    assert failed == set()
    apply.assert_not_called()


def test_prototype_orders_args_by_ordinal_and_names_unnamed(deci):
    resolver = mod._TypeResolver({str(1): _base(1, "int")})
    item = _signature(
        10, parameters=[_param(1, 1, name="second"), _param(0, 1)], return_id=1
    )

    proto = ImportDataTypes._prototype(item, resolver)

    assert [a.offset for a in proto.args] == [0, 1]
    assert [a.name for a in proto.args] == ["a1", "second"]
    assert proto.return_type == "int"


def test_unresolvable_data_type_id_yields_none():
    resolver = mod._TypeResolver({})

    assert resolver.resolve(99) == (None, None)
    assert resolver.resolve(None) == (None, None)
    assert resolver.artifacts == {}


def test_enum_value_out_of_int64_range_is_kept():
    entry = {
        "data_type_id": 1,
        "name": "Big",
        "kind": "ENUM",
        "size": 8,
        "definition": {
            "values": [
                {"name": "HUGE", "value": "18446744073709551615"},
                {"name": "NEG", "value": "-1"},
                {"name": "BAD", "value": "not-a-number"},
            ]
        },
    }
    resolver = mod._TypeResolver({"1": entry})

    resolver.resolve(1)

    assert resolver.artifacts["Big"].members == {
        "HUGE": 18446744073709551615,
        "NEG": -1,
    }


_HASH = "259156281adba01eb86070f77a039e7054f268c973326adcee5fe4533f14b292"


@pytest.mark.parametrize(
    "raw,expected",
    [
        (f"{_HASH}::Candidate *", "Candidate *"),
        (f"{_HASH}/std::vector<Block_*,std::allocator<Block_*>_>", "std::vector<Block_*,std::allocator<Block_*>_>"),
        (f"{_HASH}::_Tree_node<x>::_Node *", "_Tree_node<x>::_Node *"),
        ("DWARF/stdint.h::uint32_t", "uint32_t"),
        ("std::vector<int>", "std::vector<int>"),
        ("int", "int"),
        ("qword", "qword"),
    ],
)
def test_normalise_type_strips_analysis_scope(raw, expected):
    assert normalise_type(raw) == expected


def test_ghidra_primitive_declarators_are_well_formed():
    names = [
        mod._primitive_name(d) for d in mod._GHIDRA_PRIMITIVE_DECLARATORS
    ]

    assert len(names) == len(set(names))
    assert "qword" in names
    assert "undefined6" in names
    assert all(name.isidentifier() for name in names)
