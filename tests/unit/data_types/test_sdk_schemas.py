import inspect

from revengai import (
    ArrayDataType,
    BatchFunctionSignatureEntry,
    DataTypeEnumValueEntry,
    DataTypeMemberEntry,
    DataTypesApi,
    EnumDataType,
    ListFunctionSignaturesOutputBody,
    PointerDataType,
    SignatureParameterEntry,
    StructDataType,
    TypedefDataType,
    UnionDataType,
)


def test_data_types_api_exposes_the_methods_the_plugin_calls():
    for method in (
        "v3_list_function_signatures",
        "v3_list_analysis_data_types",
        "v3_create_analysis_data_types",
        "v3_update_analysis_data_types",
        "v3_update_function_signature",
    ):
        assert callable(getattr(DataTypesApi, method))


def test_list_function_signatures_accepts_plugin_kwargs():
    params = inspect.signature(DataTypesApi.v3_list_function_signatures).parameters

    assert {"function_ids", "include_data_types"} <= set(params)


def test_signatures_response_carries_items_and_data_types():
    assert {"items", "data_types"} <= set(ListFunctionSignaturesOutputBody.model_fields)


def test_signature_entry_fields():
    assert {
        "analysis_id",
        "function_id",
        "function_name",
        "has_signature",
        "parameters",
        "return_data_type_id",
    } <= set(BatchFunctionSignatureEntry.model_fields)


def test_signature_parameter_is_typed_by_id_and_ordered_by_ordinal():
    assert {"ordinal", "name", "data_type_id"} <= set(
        SignatureParameterEntry.model_fields
    )


def test_record_types_expose_members_via_definition():
    for model in (StructDataType, UnionDataType):
        assert {"data_type_id", "name", "kind", "size", "definition"} <= set(
            model.model_fields
        )
    assert {"name", "offset", "size", "data_type_id"} <= set(
        DataTypeMemberEntry.model_fields
    )


def test_indirect_types_reference_their_target_by_id():
    assert "definition" in TypedefDataType.model_fields
    assert "definition" in PointerDataType.model_fields
    assert "definition" in ArrayDataType.model_fields


def test_enum_values_are_strings_to_survive_wide_and_negative_values():
    assert {"name", "value"} <= set(DataTypeEnumValueEntry.model_fields)
    assert "definition" in EnumDataType.model_fields
    assert DataTypeEnumValueEntry.model_fields["value"].annotation is str
