import threading
from dataclasses import dataclass, field

from revengai import ApiException, Configuration
from revengai.exceptions import NotFoundException

from loguru import logger

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from revengai import DataTypesApi

from reai_toolkit.app.interfaces.thread_service import IThreadService
from reai_toolkit.app.transformations.import_data_types import (
    FunctionSignatures,
    ImportDataTypes,
)


FUNCTION_IDS_BATCH_SIZE = 50


@dataclass
class DataTypesImportResult:
    error: str | None = None
    remote_absent_ids: set[int] = field(default_factory=set)
    apply_failed_ids: set[int] = field(default_factory=set)


class ImportDataTypesService(IThreadService):
    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration) -> None:
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def import_data_types_async(self, matches: dict[int, int]) -> None:
        self.start_worker(target=self._import_worker, args=(matches,))

    def _import_worker(self, _: threading.Event, matches: dict[int, int]) -> None:
        result: DataTypesImportResult = self.import_data_types(matches)
        if result.error:
            logger.error(f"RevEng.AI: {result.error}")

    def import_data_types(self, matches: dict[int, int]) -> DataTypesImportResult:
        if len(matches) == 0:
            return DataTypesImportResult()

        idt: ImportDataTypes = ImportDataTypes()
        matched_function_ids: list[int] = list(matches.keys())

        try:
            response: FunctionSignatures | None = self._get_data_types(matched_function_ids)
        except NotFoundException as e:
            logger.warning(f"failed to apply data types for {len(matched_function_ids)} functions: {e}")
            return DataTypesImportResult(remote_absent_ids=set(matched_function_ids))
        except ApiException as e:
            logger.error(f"RevEng.AI: failed to sync function data types: HTTP {e.status} {e.reason}")
            return DataTypesImportResult(error=f"Failed to sync function data types: HTTP {e.status} {e.reason}")
        except Exception as e:
            logger.error(f"RevEng.AI: failed to sync function data types: {e}")
            return DataTypesImportResult(error=f"Failed to sync function data types: {e}")

        present_ids: set[int] = (
            {item["function_id"] for item in response.items if item.get("has_signature")}
            if response
            else set()
        )
        remote_absent_ids: set[int] = set(matched_function_ids) - present_ids

        apply_failed_ids: set[int] = set()
        if response:
            apply_failed_ids = idt.execute(
                response, matched_function_mapping=matches
            ) or set()

        return DataTypesImportResult(
            remote_absent_ids=remote_absent_ids,
            apply_failed_ids=apply_failed_ids,
        )

    def _get_data_types(self, function_ids: list[int] | None = None) -> FunctionSignatures | None:
        if not function_ids:
            return None

        signatures = FunctionSignatures()
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            client = DataTypesApi(api_client=api_client)
            for start in range(0, len(function_ids), FUNCTION_IDS_BATCH_SIZE):
                chunk = function_ids[start:start + FUNCTION_IDS_BATCH_SIZE]
                response = client.v3_list_function_signatures(
                    function_ids=chunk, include_data_types=True
                ).to_dict()

                signatures.items.extend(response.get("items") or [])
                for group in response.get("data_types") or []:
                    for entry in group.get("items") or []:
                        data_type_id = entry.get("data_type_id")
                        if data_type_id is None:
                            continue
                        signatures.data_types[str(data_type_id)] = entry

        return signatures
