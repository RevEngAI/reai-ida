from unittest.mock import MagicMock

import pytest
from revengai.exceptions import ForbiddenException, NotFoundException

from reai_toolkit.app.services.data_types import data_types_service as svc_mod
from reai_toolkit.app.services.data_types.data_types_service import (
    FUNCTION_IDS_BATCH_SIZE,
    ImportDataTypesService,
)


@pytest.fixture
def service():
    return ImportDataTypesService(netstore_service=MagicMock(), sdk_config=MagicMock())


@pytest.fixture
def sdk(mocker):
    mocker.patch.object(ImportDataTypesService, "yield_api_client")
    api_class = mocker.patch.object(svc_mod, "DataTypesApi")
    api_inst = MagicMock()
    api_class.return_value = api_inst
    return api_inst


def _response(function_ids, data_types=(), has_signature=True):
    resp = MagicMock()
    resp.to_dict.return_value = {
        "items": [
            {
                "function_id": fid,
                "function_name": f"fn_{fid}",
                "has_signature": has_signature,
                "parameters": [],
                "return_data_type_id": None,
            }
            for fid in function_ids
        ],
        "data_types": [{"analysis_id": 1, "items": list(data_types)}],
    }
    return resp


def test_single_batch_when_under_threshold(service, sdk):
    ids = list(range(1, 11))
    sdk.v3_list_function_signatures.return_value = _response(ids)

    result = service._get_data_types(ids)

    sdk.v3_list_function_signatures.assert_called_once_with(
        function_ids=ids, include_data_types=True
    )
    assert [item["function_id"] for item in result.items] == ids


def test_chunks_large_id_list_to_avoid_uri_too_large(service, sdk):
    total = FUNCTION_IDS_BATCH_SIZE * 2 + 15
    ids = list(range(total))
    sdk.v3_list_function_signatures.side_effect = (
        lambda function_ids, include_data_types: _response(function_ids)
    )

    result = service._get_data_types(ids)

    calls = sdk.v3_list_function_signatures.call_args_list
    assert len(calls) == 3
    assert [len(c.kwargs["function_ids"]) for c in calls] == [
        FUNCTION_IDS_BATCH_SIZE,
        FUNCTION_IDS_BATCH_SIZE,
        15,
    ]
    for c in calls:
        assert len(c.kwargs["function_ids"]) <= FUNCTION_IDS_BATCH_SIZE
    assert [item["function_id"] for item in result.items] == ids


def test_empty_list_returns_none_without_calling_sdk(service, sdk):
    assert service._get_data_types([]) is None
    sdk.v3_list_function_signatures.assert_not_called()


def test_data_types_are_merged_across_chunks_by_id(service, sdk):
    def respond(function_ids, include_data_types):
        return _response(
            function_ids,
            data_types=[
                {"data_type_id": fid, "name": f"t{fid}", "kind": "BASE", "size": 4}
                for fid in function_ids
            ],
        )

    sdk.v3_list_function_signatures.side_effect = respond
    ids = list(range(FUNCTION_IDS_BATCH_SIZE + 5))

    result = service._get_data_types(ids)

    assert set(result.data_types) == {str(i) for i in ids}
    assert result.data_types["3"]["name"] == "t3"


def test_data_types_without_an_id_are_skipped(service, sdk):
    sdk.v3_list_function_signatures.return_value = _response(
        [1], data_types=[{"name": "nameless", "kind": "BASE"}]
    )

    result = service._get_data_types([1])

    assert result.data_types == {}


def test_import_data_types_computes_absent_when_remote_types_missing(service, sdk, mocker):
    sdk.v3_list_function_signatures.return_value = _response([1], has_signature=False)
    apply = mocker.patch.object(svc_mod.ImportDataTypes, "execute", return_value=set())

    result = service.import_data_types({1: 0x1000})

    apply.assert_called_once()
    assert result.error is None
    assert result.remote_absent_ids == {1}
    assert result.apply_failed_ids == set()


def test_import_data_types_marks_apply_failures(service, sdk, mocker):
    sdk.v3_list_function_signatures.return_value = _response([1])
    mocker.patch.object(svc_mod.ImportDataTypes, "execute", return_value={1})

    result = service.import_data_types({1: 0x1000})

    assert result.remote_absent_ids == set()
    assert result.apply_failed_ids == {1}


def test_import_data_types_empty_matches(service, sdk):
    result = service.import_data_types({})

    assert result.error is None
    assert result.remote_absent_ids == set()
    assert result.apply_failed_ids == set()
    sdk.v3_list_function_signatures.assert_not_called()


def test_import_data_types_returns_error_on_forbidden(service, sdk, mocker):
    sdk.v3_list_function_signatures.side_effect = ForbiddenException(
        status=403, reason="Forbidden"
    )
    apply = mocker.patch.object(svc_mod.ImportDataTypes, "execute")

    matches = {fid: fid * 16 for fid in range(FUNCTION_IDS_BATCH_SIZE * 3)}
    result = service.import_data_types(matches)

    assert result.error is not None
    assert "403" in result.error
    assert "Forbidden" in result.error
    assert result.remote_absent_ids == set()
    apply.assert_not_called()
    assert sdk.v3_list_function_signatures.call_count == 1


def test_import_data_types_treats_not_found_as_all_absent(service, sdk, mocker):
    sdk.v3_list_function_signatures.side_effect = NotFoundException(
        status=404, reason="Not Found"
    )
    apply = mocker.patch.object(svc_mod.ImportDataTypes, "execute")

    result = service.import_data_types({1: 0x1000, 2: 0x2000})

    assert result.error is None
    assert result.remote_absent_ids == {1, 2}
    apply.assert_not_called()


def test_import_data_types_returns_error_on_unexpected_exception(service, sdk, mocker):
    sdk.v3_list_function_signatures.side_effect = RuntimeError("boom")
    apply = mocker.patch.object(svc_mod.ImportDataTypes, "execute")

    result = service.import_data_types({1: 0x1000})

    assert result.error is not None
    assert "boom" in result.error
    apply.assert_not_called()
