from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from libbs.artifacts import Enum, Struct, Typedef
from loguru import logger

from revengai import (
    Configuration,
    CreateAnalysisDataTypesInputBody,
    DataTypesApi,
    UpdateAnalysisDataTypesInputBody,
)

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.interfaces.base_service import BaseService

PAGE_SIZE = 500
MAX_PAGES = 200
WRITE_BATCH_SIZE = 100

KIND_STRUCT = "STRUCT"
KIND_ENUM = "ENUM"
KIND_TYPEDEF = "TYPEDEF"

_DEFINED_KINDS = frozenset({KIND_STRUCT, KIND_ENUM, KIND_TYPEDEF})

TypeKey = tuple[str, str, str]


def type_key(namespace: Optional[str], name: str, kind: str) -> TypeKey:
    return (namespace or "", name, (kind or "").upper())


def kind_of(artifact: Any) -> Optional[str]:
    if isinstance(artifact, Struct):
        return KIND_STRUCT
    if isinstance(artifact, Enum):
        return KIND_ENUM
    if isinstance(artifact, Typedef):
        return KIND_TYPEDEF
    return None


@dataclass
class Catalogue:
    by_id: dict[int, dict] = field(default_factory=dict)
    id_by_key: dict[TypeKey, int] = field(default_factory=dict)
    id_by_name: dict[str, int] = field(default_factory=dict)

    @classmethod
    def of(cls, entries: Iterable[dict]) -> "Catalogue":
        catalogue = cls()
        catalogue.absorb(entries)
        return catalogue

    def absorb(self, entries: Iterable[dict]) -> None:
        for entry in entries:
            data_type_id = entry.get("data_type_id")
            name = entry.get("name")
            if data_type_id is None or not name:
                continue
            self.by_id[data_type_id] = entry
            self.id_by_key[type_key(entry.get("namespace"), name, entry.get("kind"))] = data_type_id
            self.id_by_name.setdefault(name, data_type_id)

    def id_of(self, key: TypeKey) -> Optional[int]:
        return self.id_by_key.get(key)

    def id_of_name(self, name: str) -> Optional[int]:
        return self.id_by_name.get(name)

    def __len__(self) -> int:
        return len(self.by_id)


class AnalysisDataTypesService(BaseService):
    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration) -> None:
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)
        self._cache: dict[int, Catalogue] = {}

    def invalidate(self, analysis_id: Optional[int] = None) -> None:
        if analysis_id is None:
            self._cache.clear()
        else:
            self._cache.pop(analysis_id, None)

    def catalogue(self, analysis_id: int) -> Catalogue:
        cached = self._cache.get(analysis_id)
        if cached is None:
            cached = self.sync(analysis_id)
        return cached

    def sync(self, analysis_id: int) -> Catalogue:
        entries: list[dict] = []
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            client = DataTypesApi(api_client)
            offset = 0
            for _ in range(MAX_PAGES):
                page = client.v3_list_analysis_data_types(
                    analysis_id=analysis_id, offset=offset, limit=PAGE_SIZE
                ).to_dict()
                items = page.get("items") or []
                entries.extend(items)
                if len(items) < PAGE_SIZE:
                    break
                offset += len(items)
            else:
                logger.warning(
                    f"RevEng.AI: stopped paging analysis {analysis_id} data types at {MAX_PAGES} pages"
                )

        catalogue = Catalogue.of(entries)
        self._cache[analysis_id] = catalogue
        logger.debug(f"RevEng.AI: analysis {analysis_id} holds {len(catalogue)} data types")
        return catalogue

    def resolve(self, analysis_id: int, type_name: Optional[str]) -> Optional[int]:
        if not type_name:
            return None
        return self.catalogue(analysis_id).id_of_name(type_name)

    def ensure(self, analysis_id: int, artifacts: dict[str, Any]) -> dict[str, int]:
        if not artifacts:
            return {}

        catalogue = self.catalogue(analysis_id)
        ids: dict[str, int] = {}
        missing: dict[str, Any] = {}

        for name, artifact in artifacts.items():
            kind = kind_of(artifact)
            if kind is None:
                continue
            existing = catalogue.id_of(type_key("", name, kind))
            if existing is None:
                missing[name] = artifact
            else:
                ids[name] = existing

        if missing:
            ids.update(self._create_placeholders(analysis_id, missing, catalogue))

        defined = {
            name: artifacts[name]
            for name in ids
            if kind_of(artifacts[name]) in _DEFINED_KINDS
        }
        if defined:
            self._write_definitions(analysis_id, defined, ids, catalogue)

        return ids

    def _create_placeholders(
        self, analysis_id: int, missing: dict[str, Any], catalogue: Catalogue
    ) -> dict[str, int]:
        bodies = [
            {
                "kind": kind_of(artifact),
                "name": name,
                "namespace": "",
                "size": getattr(artifact, "size", None) or 0,
            }
            for name, artifact in missing.items()
        ]

        created: dict[str, int] = {}
        for chunk in _chunks(bodies, WRITE_BATCH_SIZE):
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                client = DataTypesApi(api_client)
                out = client.v3_create_analysis_data_types(
                    analysis_id=analysis_id,
                    create_analysis_data_types_input_body=CreateAnalysisDataTypesInputBody.model_construct(
                        data_types=chunk
                    ),
                ).to_dict()

            entries = out.get("data_types") or []
            catalogue.absorb(entries)
            for entry in entries:
                name = entry.get("name")
                data_type_id = entry.get("data_type_id")
                if name is not None and data_type_id is not None:
                    created[name] = data_type_id

        return created

    def _write_definitions(
        self,
        analysis_id: int,
        artifacts: dict[str, Any],
        ids: dict[str, int],
        catalogue: Catalogue,
    ) -> None:
        bodies = []
        for name, artifact in artifacts.items():
            definition = self._definition(artifact, analysis_id, ids, catalogue)
            if definition is None:
                continue
            bodies.append(
                {
                    "data_type_id": ids[name],
                    "kind": kind_of(artifact),
                    "name": name,
                    "namespace": "",
                    "size": getattr(artifact, "size", None) or 0,
                    "definition": definition,
                }
            )

        for chunk in _chunks(bodies, WRITE_BATCH_SIZE):
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                client = DataTypesApi(api_client)
                out = client.v3_update_analysis_data_types(
                    analysis_id=analysis_id,
                    update_analysis_data_types_input_body=UpdateAnalysisDataTypesInputBody.model_construct(
                        data_types=chunk
                    ),
                ).to_dict()
            catalogue.absorb(out.get("data_types") or [])

    def _definition(
        self,
        artifact: Any,
        analysis_id: int,
        ids: dict[str, int],
        catalogue: Catalogue,
    ) -> Optional[dict]:
        if isinstance(artifact, Struct):
            members = []
            for member in (artifact.members or {}).values():
                members.append(
                    {
                        "name": member.name or "",
                        "offset": member.offset,
                        "size": member.size or 0,
                        "is_bitfield": False,
                        "data_type_id": self._reference(member.type, ids, catalogue),
                    }
                )
            return {"members": members}

        if isinstance(artifact, Enum):
            return {
                "values": [
                    {"name": str(key), "value": str(value)}
                    for key, value in (artifact.members or {}).items()
                ]
            }

        if isinstance(artifact, Typedef):
            return {"target_data_type_id": self._reference(artifact.type, ids, catalogue)}

        return None

    @staticmethod
    def _reference(
        type_name: Optional[str], ids: dict[str, int], catalogue: Catalogue
    ) -> Optional[int]:
        if not type_name:
            return None
        if type_name in ids:
            return ids[type_name]
        return catalogue.id_of_name(type_name)


def _chunks(items: list, size: int):
    for start in range(0, len(items), size):
        yield items[start:start + size]
