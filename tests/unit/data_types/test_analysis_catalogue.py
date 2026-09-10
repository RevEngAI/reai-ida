from unittest.mock import MagicMock

import pytest
from libbs.artifacts import Enum, Struct, StructMember, Typedef

from reai_toolkit.app.services.data_types import analysis_catalogue as mod
from reai_toolkit.app.services.data_types.analysis_catalogue import (
    MAX_PAGES,
    PAGE_SIZE,
    WRITE_BATCH_SIZE,
    AnalysisDataTypesService,
    Catalogue,
)

ANALYSIS = 7


@pytest.fixture
def service():
    return AnalysisDataTypesService(netstore_service=MagicMock(), sdk_config=MagicMock())


@pytest.fixture
def sdk(mocker):
    mocker.patch.object(AnalysisDataTypesService, "yield_api_client")
    api_class = mocker.patch.object(mod, "DataTypesApi")
    api = MagicMock()
    api_class.return_value = api
    return api


def _entry(data_type_id, name, kind="STRUCT", namespace="", size=8):
    return {
        "data_type_id": data_type_id,
        "name": name,
        "kind": kind,
        "namespace": namespace,
        "size": size,
    }


def _page(items):
    resp = MagicMock()
    resp.to_dict.return_value = {"items": items, "total_count": len(items)}
    return resp


def _written(items):
    resp = MagicMock()
    resp.to_dict.return_value = {"data_types": items}
    return resp


def test_catalogue_indexes_by_key_and_name():
    catalogue = Catalogue.of([_entry(1, "Foo"), _entry(2, "Bar", kind="ENUM")])

    assert catalogue.id_of(("", "Foo", "STRUCT")) == 1
    assert catalogue.id_of(("", "Bar", "ENUM")) == 2
    assert catalogue.id_of(("", "Foo", "ENUM")) is None
    assert catalogue.id_of_name("Foo") == 1


def test_catalogue_keeps_data_type_id_zero():
    catalogue = Catalogue.of([_entry(0, "Zero")])

    assert catalogue.id_of_name("Zero") == 0
    assert len(catalogue) == 1


def test_sync_pages_until_short_page(service, sdk):
    first = [_entry(i, f"T{i}") for i in range(PAGE_SIZE)]
    second = [_entry(PAGE_SIZE, "Last")]
    sdk.v3_list_analysis_data_types.side_effect = [_page(first), _page(second)]

    catalogue = service.sync(ANALYSIS)

    assert len(catalogue) == PAGE_SIZE + 1
    offsets = [c.kwargs["offset"] for c in sdk.v3_list_analysis_data_types.call_args_list]
    assert offsets == [0, PAGE_SIZE]


def test_sync_stops_at_max_pages_when_server_never_shortens(service, sdk):
    sdk.v3_list_analysis_data_types.side_effect = lambda **kw: _page(
        [_entry(kw["offset"] + i, f"T{kw['offset'] + i}") for i in range(PAGE_SIZE)]
    )

    service.sync(ANALYSIS)

    assert sdk.v3_list_analysis_data_types.call_count == MAX_PAGES


def test_catalogue_is_cached_until_invalidated(service, sdk):
    sdk.v3_list_analysis_data_types.return_value = _page([_entry(1, "Foo")])

    service.catalogue(ANALYSIS)
    service.catalogue(ANALYSIS)
    assert sdk.v3_list_analysis_data_types.call_count == 1

    service.invalidate(ANALYSIS)
    service.catalogue(ANALYSIS)
    assert sdk.v3_list_analysis_data_types.call_count == 2


def test_ensure_resolves_before_creating(service, sdk):
    sdk.v3_list_analysis_data_types.return_value = _page([_entry(11, "Known")])
    known = Struct(name="Known", size=8, members={})

    ids = service.ensure(ANALYSIS, {"Known": known})

    assert ids == {"Known": 11}
    sdk.v3_create_analysis_data_types.assert_not_called()


def test_ensure_creates_only_the_gaps(service, sdk):
    sdk.v3_list_analysis_data_types.return_value = _page([_entry(11, "Known")])
    sdk.v3_create_analysis_data_types.return_value = _written([_entry(12, "New")])
    sdk.v3_update_analysis_data_types.return_value = _written([])

    ids = service.ensure(
        ANALYSIS,
        {
            "Known": Struct(name="Known", size=8, members={}),
            "New": Struct(name="New", size=4, members={}),
        },
    )

    assert ids == {"Known": 11, "New": 12}
    body = sdk.v3_create_analysis_data_types.call_args.kwargs[
        "create_analysis_data_types_input_body"
    ]
    assert [d["name"] for d in body.data_types] == ["New"]


def test_create_bodies_carry_no_data_type_id(service, sdk):
    sdk.v3_list_analysis_data_types.return_value = _page([])
    sdk.v3_create_analysis_data_types.return_value = _written([_entry(1, "New")])
    sdk.v3_update_analysis_data_types.return_value = _written([])

    service.ensure(ANALYSIS, {"New": Struct(name="New", size=4, members={})})

    body = sdk.v3_create_analysis_data_types.call_args.kwargs[
        "create_analysis_data_types_input_body"
    ]
    assert all("data_type_id" not in d for d in body.data_types)


def test_definitions_are_written_after_ids_exist(service, sdk):
    sdk.v3_list_analysis_data_types.return_value = _page([_entry(1, "int", kind="BASE", size=4)])
    sdk.v3_create_analysis_data_types.return_value = _written(
        [_entry(2, "Node"), _entry(3, "NodeRef", kind="TYPEDEF")]
    )
    sdk.v3_update_analysis_data_types.return_value = _written([])

    node = Struct(
        name="Node",
        size=8,
        members={0: StructMember(name="value", offset=0, type_="int", size=4)},
    )
    alias = Typedef(name="NodeRef", type_="Node")

    service.ensure(ANALYSIS, {"Node": node, "NodeRef": alias})

    body = sdk.v3_update_analysis_data_types.call_args.kwargs[
        "update_analysis_data_types_input_body"
    ]
    written = {d["name"]: d for d in body.data_types}
    assert written["Node"]["definition"]["members"][0]["data_type_id"] == 1
    assert written["NodeRef"]["definition"]["target_data_type_id"] == 2
    assert all("data_type_id" in d for d in body.data_types)


def test_self_referential_struct_resolves_to_its_own_new_id(service, sdk):
    sdk.v3_list_analysis_data_types.return_value = _page([])
    sdk.v3_create_analysis_data_types.return_value = _written([_entry(5, "Node")])
    sdk.v3_update_analysis_data_types.return_value = _written([])

    node = Struct(
        name="Node",
        size=8,
        members={0: StructMember(name="next", offset=0, type_="Node", size=8)},
    )

    service.ensure(ANALYSIS, {"Node": node})

    body = sdk.v3_update_analysis_data_types.call_args.kwargs[
        "update_analysis_data_types_input_body"
    ]
    assert body.data_types[0]["definition"]["members"][0]["data_type_id"] == 5


def test_unresolvable_member_type_is_left_unresolved(service, sdk):
    sdk.v3_list_analysis_data_types.return_value = _page([])
    sdk.v3_create_analysis_data_types.return_value = _written([_entry(1, "Foo")])
    sdk.v3_update_analysis_data_types.return_value = _written([])

    foo = Struct(
        name="Foo",
        size=8,
        members={0: StructMember(name="x", offset=0, type_="NoSuchType", size=8)},
    )

    service.ensure(ANALYSIS, {"Foo": foo})

    body = sdk.v3_update_analysis_data_types.call_args.kwargs[
        "update_analysis_data_types_input_body"
    ]
    assert body.data_types[0]["definition"]["members"][0]["data_type_id"] is None


def test_enum_values_are_sent_as_strings(service, sdk):
    sdk.v3_list_analysis_data_types.return_value = _page([])
    sdk.v3_create_analysis_data_types.return_value = _written(
        [_entry(1, "Colors", kind="ENUM", size=4)]
    )
    sdk.v3_update_analysis_data_types.return_value = _written([])

    service.ensure(ANALYSIS, {"Colors": Enum(name="Colors", members={"RED": 0, "BIG": 2**64 - 1})})

    body = sdk.v3_update_analysis_data_types.call_args.kwargs[
        "update_analysis_data_types_input_body"
    ]
    values = body.data_types[0]["definition"]["values"]
    assert {v["name"]: v["value"] for v in values} == {
        "RED": "0",
        "BIG": "18446744073709551615",
    }


def test_writes_are_chunked(service, sdk):
    total = WRITE_BATCH_SIZE + 10
    sdk.v3_list_analysis_data_types.return_value = _page([])
    sdk.v3_create_analysis_data_types.side_effect = lambda **kw: _written(
        [
            _entry(i, d["name"])
            for i, d in enumerate(
                kw["create_analysis_data_types_input_body"].data_types, start=1
            )
        ]
    )
    sdk.v3_update_analysis_data_types.return_value = _written([])

    artifacts = {
        f"S{i}": Struct(name=f"S{i}", size=4, members={}) for i in range(total)
    }
    service.ensure(ANALYSIS, artifacts)

    sizes = [
        len(c.kwargs["create_analysis_data_types_input_body"].data_types)
        for c in sdk.v3_create_analysis_data_types.call_args_list
    ]
    assert sizes == [WRITE_BATCH_SIZE, 10]


def test_ensure_ignores_artifacts_of_unknown_kind(service, sdk):
    sdk.v3_list_analysis_data_types.return_value = _page([])

    assert service.ensure(ANALYSIS, {"weird": object()}) == {}
    sdk.v3_create_analysis_data_types.assert_not_called()


def test_ensure_with_no_artifacts_touches_nothing(service, sdk):
    assert service.ensure(ANALYSIS, {}) == {}
    sdk.v3_list_analysis_data_types.assert_not_called()
