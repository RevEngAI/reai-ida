"""Small compatibility layer for the RevEng.AI v3 data-type API.

The plugin release currently bundles the v2 SDK, while the service no longer
serves ``/v2/functions/data_types``.  Keeping this adapter on top of the
bundled ``ApiClient`` lets the plugin use the v3 endpoints without replacing
the whole SDK (which would otherwise break the rest of the plugin's v2 model
imports).
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from revengai import ApiClient, ApiException
from revengai.models.argument import Argument
from revengai.models.enumeration import Enumeration
from revengai.models.function_data_types_list import FunctionDataTypesList
from revengai.models.function_data_types_list_item import FunctionDataTypesListItem
from revengai.models.structure import Structure
from revengai.models.structure_member import StructureMember
from revengai.models.type_definition import TypeDefinition
from revengai.models.v2_function_header import V2FunctionHeader
from revengai.models.v2_function_info import V2FunctionInfo
from revengai.models.v2_function_info_func_deps_inner import V2FunctionInfoFuncDepsInner
from revengai.models.v2_function_type import V2FunctionType


FUNCTION_IDS_BATCH_SIZE = 50


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _request_json(
    api_client: ApiClient,
    method: str,
    resource_path: str,
    *,
    query_params: Iterable[tuple[str, Any]] = (),
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Call a v3 endpoint using the SDK client shipped with the plugin."""

    headers: dict[str, str] = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"

    request = api_client.param_serialize(
        method=method,
        resource_path=resource_path,
        path_params={},
        query_params=list(query_params),
        header_params=headers,
        body=body,
        post_params=[],
        files={},
        auth_settings=["APIKey", "bearerAuth"],
        collection_formats={"function_ids": "multi"},
        _host=None,
        _request_auth=None,
    )
    response = api_client.call_api(*request)
    response.read()

    raw = response.data or b""
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
    if not 200 <= response.status <= 299:
        data: Any = None
        try:
            data = json.loads(text) if text else None
        except json.JSONDecodeError:
            pass
        raise ApiException.from_response(http_resp=response, body=text, data=data)

    if not text:
        return {}
    decoded = json.loads(text)
    if not isinstance(decoded, dict):
        raise ValueError(f"Unexpected RevEng.AI response shape: {type(decoded).__name__}")
    return decoded


def list_function_signatures(
    api_client: ApiClient,
    function_ids: list[int],
    *,
    include_data_types: bool = True,
) -> dict[str, Any]:
    """Fetch v3 signatures, preserving the endpoint's grouped type data."""

    if not function_ids:
        return {"items": [], "data_types": []}

    all_items: list[dict[str, Any]] = []
    groups: dict[int, dict[str, Any]] = {}
    for start in range(0, len(function_ids), FUNCTION_IDS_BATCH_SIZE):
        chunk = function_ids[start : start + FUNCTION_IDS_BATCH_SIZE]
        response = _request_json(
            api_client,
            "GET",
            "/v3/functions/signatures",
            query_params=[
                ("function_ids", chunk),
                ("include_data_types", include_data_types),
            ],
        )
        all_items.extend(response.get("items") or [])
        for group in response.get("data_types") or []:
            analysis_id = _as_int(group.get("analysis_id"), -1)
            if analysis_id < 0:
                continue
            existing = groups.setdefault(analysis_id, {"analysis_id": analysis_id, "items": []})
            existing["items"].extend(group.get("items") or [])

    return {"items": all_items, "data_types": list(groups.values())}


def update_function_signature(
    api_client: ApiClient,
    analysis_id: int,
    function_id: int,
    body: dict[str, Any],
) -> dict[str, Any]:
    """Update one function signature through the v3 API."""

    return _request_json(
        api_client,
        "PUT",
        f"/v3/analyses/{int(analysis_id)}/functions/{int(function_id)}/signature",
        body=body,
    )


class _TypeResolver:
    """Resolve v3 data-type IDs into the C-like strings the IDA importer uses."""

    def __init__(self, entries: Iterable[dict[str, Any]]) -> None:
        self.entries: dict[int, dict[str, Any]] = {
            _as_int(entry.get("data_type_id"), -1): entry
            for entry in entries
            if entry.get("data_type_id") is not None
        }
        self._cache: dict[int, str] = {}
        self._resolving: set[int] = set()

    @staticmethod
    def _qualified_name(entry: dict[str, Any]) -> str:
        name = str(entry.get("name") or "").strip()
        namespace = str(entry.get("namespace") or "").strip()
        if namespace and name:
            return f"{namespace}::{name}"
        return name

    def size(self, data_type_id: Any) -> int:
        entry = self.entries.get(_as_int(data_type_id, -1))
        return _as_int(entry.get("size"), 0) if entry else 0

    def type_name(self, data_type_id: Any) -> str:
        if data_type_id is None:
            return ""
        type_id = _as_int(data_type_id, -1)
        if type_id < 0:
            return ""
        if type_id in self._cache:
            return self._cache[type_id]

        entry = self.entries.get(type_id)
        if entry is None:
            return ""
        if type_id in self._resolving:
            return self._qualified_name(entry) or "void"

        self._resolving.add(type_id)
        kind = str(entry.get("kind") or "").upper()
        definition = entry.get("definition") or {}
        name = self._qualified_name(entry)

        if kind == "POINTER":
            target = definition.get("pointee_data_type_id")
            target_name = self.type_name(target) or name or "void"
            resolved = f"{target_name} *"
        elif kind == "ARRAY":
            element = self.type_name(definition.get("element_data_type_id")) or name or "void"
            count = definition.get("count")
            resolved = f"{element}[{count}]" if count is not None else f"{element}[]"
        else:
            resolved = name or "void"

        self._resolving.discard(type_id)
        self._cache[type_id] = resolved
        return resolved

    @staticmethod
    def _dependency_name(entry: dict[str, Any]) -> str:
        return _TypeResolver._qualified_name(entry) or "anonymous_type"

    def dependencies(self) -> list[V2FunctionInfoFuncDepsInner]:
        dependencies: list[V2FunctionInfoFuncDepsInner] = []
        for entry in self.entries.values():
            kind = str(entry.get("kind") or "").upper()
            name = self._dependency_name(entry)
            definition = entry.get("definition") or {}

            if kind in {"STRUCT", "UNION"}:
                members: dict[str, StructureMember] = {}
                for index, member in enumerate(definition.get("members") or []):
                    offset = _as_int(member.get("offset"), index)
                    member_name = str(member.get("name") or f"field_{offset:x}")
                    members[str(offset)] = StructureMember.model_construct(
                        name=member_name,
                        offset=offset,
                        type=self.type_name(member.get("data_type_id")),
                        size=_as_int(member.get("size"), 0),
                    )
                dependency = Structure.model_construct(
                    name=name,
                    size=_as_int(entry.get("size"), 0),
                    members=members,
                    artifact_type="Structure",
                )
                dependencies.append(V2FunctionInfoFuncDepsInner.model_construct(actual_instance=dependency))
            elif kind == "ENUM":
                values: dict[str, int] = {}
                for value in definition.get("values") or []:
                    value_name = str(value.get("name") or "")
                    if not value_name:
                        continue
                    values[value_name] = _as_int(value.get("value"), 0)
                dependency = Enumeration.model_construct(
                    name=name,
                    members=values,
                    artifact_type="Enumeration",
                )
                dependencies.append(V2FunctionInfoFuncDepsInner.model_construct(actual_instance=dependency))
            elif kind == "TYPEDEF":
                dependency = TypeDefinition.model_construct(
                    name=name,
                    type=self.type_name(definition.get("target_data_type_id")),
                    artifact_type="Typedef",
                )
                dependencies.append(V2FunctionInfoFuncDepsInner.model_construct(actual_instance=dependency))

        return dependencies

    def ids_by_name(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for type_id, entry in self.entries.items():
            names = {
                self._qualified_name(entry),
                str(entry.get("name") or "").strip(),
                self.type_name(type_id),
            }
            for name in names:
                if name:
                    result[name] = type_id
        return result


def _legacy_function_info(
    item: dict[str, Any],
    resolver: _TypeResolver,
    local_address: int = 0,
) -> V2FunctionInfo:
    function_id = _as_int(item.get("function_id"))
    function_name = str(item.get("function_name") or f"sub_{function_id:x}")
    return_type = resolver.type_name(item.get("return_data_type_id")) or "void"

    args: dict[str, Argument] = {}
    for parameter in item.get("parameters") or []:
        ordinal = _as_int(parameter.get("ordinal"), len(args))
        data_type_id = parameter.get("data_type_id")
        args[hex(ordinal)] = Argument.model_construct(
            offset=ordinal,
            name=str(parameter.get("name") or f"arg_{ordinal}"),
            type=resolver.type_name(data_type_id),
            size=resolver.size(data_type_id),
        )

    header = V2FunctionHeader.model_construct(
        name=function_name,
        addr=local_address,
        type=return_type,
        args=args,
    )
    function_type = V2FunctionType.model_construct(
        addr=local_address,
        size=0,
        header=header,
        stack_vars=None,
        name=function_name,
        type=return_type,
        artifact_type="Function",
    )
    return V2FunctionInfo.model_construct(
        func_types=function_type,
        func_deps=resolver.dependencies(),
    )


def to_legacy_function_data_types(
    response: dict[str, Any],
    *,
    local_addresses: dict[int, int] | None = None,
) -> FunctionDataTypesList:
    """Adapt a v3 signature response to the plugin's existing IDA importer."""

    local_addresses = local_addresses or {}
    type_groups: dict[int, list[dict[str, Any]]] = {
        _as_int(group.get("analysis_id"), -1): group.get("items") or []
        for group in response.get("data_types") or []
    }

    items: list[FunctionDataTypesListItem] = []
    with_types = 0
    for raw_item in response.get("items") or []:
        function_id = _as_int(raw_item.get("function_id"))
        has_signature = bool(raw_item.get("has_signature"))
        analysis_id = _as_int(raw_item.get("analysis_id"), -1)
        entries = type_groups.get(analysis_id, [])
        resolver = _TypeResolver(entries)
        data_types = (
            _legacy_function_info(
                raw_item,
                resolver,
                local_address=_as_int(local_addresses.get(function_id), 0),
            )
            if has_signature
            else None
        )
        if data_types is not None:
            with_types += 1
        items.append(
            FunctionDataTypesListItem.model_construct(
                completed=True,
                status="success" if has_signature else "not_available",
                data_types=data_types,
                data_types_version=None,
                function_id=function_id,
            )
        )

    return FunctionDataTypesList.model_construct(
        total_count=len(items),
        total_data_types_count=with_types,
        items=items,
    )


def resolver_for_function(response: dict[str, Any], function_id: int) -> tuple[dict[str, Any], _TypeResolver] | None:
    """Return a raw v3 item and its analysis-scoped type resolver."""

    item = next(
        (candidate for candidate in response.get("items") or [] if _as_int(candidate.get("function_id")) == function_id),
        None,
    )
    if item is None:
        return None
    analysis_id = _as_int(item.get("analysis_id"), -1)
    group = next(
        (candidate for candidate in response.get("data_types") or [] if _as_int(candidate.get("analysis_id")) == analysis_id),
        None,
    )
    return item, _TypeResolver((group or {}).get("items") or [])


def normalise_type_text(value: str) -> str:
    """Normalise equivalent C-like type spellings for ID lookup."""

    text = " ".join(str(value or "").replace("*", " * ").split())
    for qualifier in ("const ", "volatile ", "struct ", "union ", "enum "):
        text = text.replace(qualifier, "")
    return text.replace(" *", "*").replace("* ", "*").strip()


def build_signature_update(
    response: dict[str, Any],
    function_id: int,
    *,
    function_info: Any,
) -> dict[str, Any] | None:
    """Build a v3 signature update from the plugin's current local function."""

    resolved = resolver_for_function(response, function_id)
    if resolved is None:
        return None
    remote_item, resolver = resolved
    if not remote_item.get("has_signature"):
        return None

    ids_by_name = resolver.ids_by_name()
    normalised_ids = {normalise_type_text(name): data_type_id for name, data_type_id in ids_by_name.items()}
    function_type = getattr(function_info, "func_types", None)
    header = getattr(function_type, "header", None)
    if header is None:
        return None

    def resolve_id(type_text: str | None) -> int | None:
        normalised = normalise_type_text(type_text or "")
        if not normalised or normalised == "void":
            return None
        return normalised_ids.get(normalised)

    parameters: list[dict[str, Any]] = []
    for index, argument in enumerate((header.args or {}).values()):
        ordinal = _as_int(getattr(argument, "offset", index), index)
        type_id = resolve_id(getattr(argument, "type", ""))
        if type_id is None and getattr(argument, "type", ""):
            return None
        parameter: dict[str, Any] = {"ordinal": ordinal}
        name = str(getattr(argument, "name", "") or "")
        if name:
            parameter["name"] = name
        if type_id is not None:
            parameter["data_type_id"] = type_id
        parameters.append(parameter)

    body: dict[str, Any] = {"parameters": parameters}
    return_type = str(getattr(header, "type", "") or "")
    normalised_return_type = normalise_type_text(return_type)
    if not normalised_return_type:
        return None
    if normalised_return_type != "void":
        return_id = resolve_id(return_type)
        if return_id is None:
            return None
        body["return_data_type_id"] = return_id
    return body
