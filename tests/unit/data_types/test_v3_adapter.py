from types import SimpleNamespace

from revengai import FunctionInfo, FunctionType

from reai_toolkit.app.services.data_types.v3_data_types import (
    build_signature_update,
    normalise_type_text,
    to_legacy_function_data_types,
)


def _response():
    return {
        "items": [
            {
                "analysis_id": 99,
                "function_id": 10,
                "function_name": "target",
                "has_signature": True,
                "parameters": [
                    {"ordinal": 0, "name": "ctx", "data_type_id": 3},
                    {"ordinal": 1, "name": "kind", "data_type_id": 4},
                ],
                "return_data_type_id": 1,
            }
        ],
        "data_types": [
            {
                "analysis_id": 99,
                "items": [
                    {"data_type_id": 1, "kind": "BASE", "name": "int", "size": 4},
                    {
                        "data_type_id": 2,
                        "kind": "STRUCT",
                        "name": "Context",
                        "size": 8,
                        "definition": {
                            "members": [
                                {"offset": 0, "name": "value", "data_type_id": 1, "size": 4}
                            ]
                        },
                    },
                    {
                        "data_type_id": 3,
                        "kind": "POINTER",
                        "name": "Context *",
                        "size": 8,
                        "definition": {"pointee_data_type_id": 2},
                    },
                    {
                        "data_type_id": 4,
                        "kind": "ENUM",
                        "name": "Kind",
                        "size": 4,
                        "definition": {"values": [{"name": "FIRST", "value": "1"}]},
                    },
                ],
            }
        ],
    }


def test_v3_response_is_adapted_to_existing_ida_import_models():
    result = to_legacy_function_data_types(_response())

    item = result.items[0]
    assert item.function_id == 10
    assert item.data_types is not None
    assert item.data_types.func_types.header.type == "int"
    assert item.data_types.func_types.header.args["0x0"].type == "Context *"
    assert item.data_types.func_types.header.args["0x1"].type == "Kind"
    assert len(item.data_types.func_deps) == 2


def test_v3_type_text_normalisation_handles_c_pointer_spelling():
    assert normalise_type_text("const struct Context *") == "Context*"
    assert normalise_type_text("Context*") == "Context*"


def test_v3_signature_update_uses_existing_remote_type_ids():
    function_type = FunctionType.model_construct(
        header=SimpleNamespace(
            type="int",
            args={
                "0x0": SimpleNamespace(offset=0, name="ctx", type="Context *"),
                "0x1": SimpleNamespace(offset=1, name="kind", type="Kind"),
            },
        )
    )
    info = FunctionInfo.model_construct(func_types=function_type, func_deps=[])

    assert build_signature_update(_response(), 10, function_info=info) == {
        "parameters": [
            {"ordinal": 0, "name": "ctx", "data_type_id": 3},
            {"ordinal": 1, "name": "kind", "data_type_id": 4},
        ],
        "return_data_type_id": 1,
    }

