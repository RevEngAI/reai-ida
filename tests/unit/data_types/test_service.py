from unittest.mock import MagicMock

import pytest
from revengai import FunctionDataTypesList
from revengai.exceptions import ForbiddenException, NotFoundException

from reai_toolkit.app.services.data_types import data_types_service as svc_mod
from reai_toolkit.app.services.data_types.data_types_service import ImportDataTypesService


@pytest.fixture
def service():
    return ImportDataTypesService(netstore_service=MagicMock(), sdk_config=MagicMock())


@pytest.fixture
def sdk(mocker):
    context = mocker.patch.object(ImportDataTypesService, "yield_api_client")
    api_client = MagicMock()
    context.return_value.__enter__.return_value = api_client
    return api_client


def _legacy_response(items=None) -> FunctionDataTypesList:
    return FunctionDataTypesList.model_construct(
        total_count=len(items or []),
        total_data_types_count=len(items or []),
        items=items or [],
    )


def test_get_data_types_uses_v3_signatures_and_adapter(service, sdk, mocker):
    raw_response = {"items": [], "data_types": []}
    list_signatures = mocker.patch.object(
        svc_mod, "list_function_signatures", return_value=raw_response
    )
    adapted = _legacy_response()
    adapt = mocker.patch.object(svc_mod, "to_legacy_function_data_types", return_value=adapted)

    result = service._get_data_types([10, 11])

    assert result is adapted
    list_signatures.assert_called_once_with(sdk, [10, 11], include_data_types=True)
    adapt.assert_called_once_with(raw_response)


def test_empty_list_returns_none_without_calling_sdk(service, sdk, mocker):
    list_signatures = mocker.patch.object(svc_mod, "list_function_signatures")

    assert service._get_data_types([]) is None
    list_signatures.assert_not_called()


def test_import_does_not_push_back_missing_v3_signature(service, sdk, mocker):
    list_signatures = mocker.patch.object(
        svc_mod,
        "list_function_signatures",
        return_value={
            "items": [{"analysis_id": 99, "function_id": 1, "has_signature": False}],
            "data_types": [],
        },
    )
    mocker.patch.object(
        svc_mod,
        "to_legacy_function_data_types",
        return_value=_legacy_response(),
    )
    apply = mocker.patch.object(svc_mod.ImportDataTypes, "execute", return_value=set())

    result = service.import_data_types({1: 0x1000})

    list_signatures.assert_called_once()
    apply.assert_called_once()
    assert result.error is None
    assert result.remote_absent_ids == set()
    assert result.apply_failed_ids == set()


def test_import_data_types_marks_apply_failures(service, sdk, mocker):
    mocker.patch.object(
        svc_mod,
        "list_function_signatures",
        return_value={"items": [], "data_types": []},
    )
    mocker.patch.object(
        svc_mod,
        "to_legacy_function_data_types",
        return_value=_legacy_response(),
    )
    mocker.patch.object(svc_mod.ImportDataTypes, "execute", return_value={1})

    result = service.import_data_types({1: 0x1000})

    assert result.remote_absent_ids == set()
    assert result.apply_failed_ids == {1}


def test_import_data_types_empty_matches(service, sdk, mocker):
    list_signatures = mocker.patch.object(svc_mod, "list_function_signatures")

    result = service.import_data_types({})

    assert result.error is None
    assert result.remote_absent_ids == set()
    assert result.apply_failed_ids == set()
    list_signatures.assert_not_called()


def test_import_data_types_returns_error_on_forbidden(service, sdk, mocker):
    mocker.patch.object(
        svc_mod,
        "list_function_signatures",
        side_effect=ForbiddenException(status=403, reason="Forbidden"),
    )
    apply = mocker.patch.object(svc_mod.ImportDataTypes, "execute")

    result = service.import_data_types({1: 0x1000})

    assert result.error is not None
    assert "403" in result.error
    assert "Forbidden" in result.error
    assert result.remote_absent_ids == set()
    apply.assert_not_called()


def test_import_data_types_treats_missing_v3_endpoint_as_absent(service, sdk, mocker):
    mocker.patch.object(
        svc_mod,
        "list_function_signatures",
        side_effect=NotFoundException(status=404, reason="Not Found"),
    )
    apply = mocker.patch.object(svc_mod.ImportDataTypes, "execute")

    result = service.import_data_types({1: 0x1000, 2: 0x2000})

    assert result.error is None
    assert result.remote_absent_ids == {1, 2}
    apply.assert_not_called()


def test_import_data_types_returns_error_on_unexpected_exception(service, sdk, mocker):
    mocker.patch.object(
        svc_mod,
        "list_function_signatures",
        side_effect=RuntimeError("boom"),
    )
    apply = mocker.patch.object(svc_mod.ImportDataTypes, "execute")

    result = service.import_data_types({1: 0x1000})

    assert result.error is not None
    assert "boom" in result.error
    apply.assert_not_called()
