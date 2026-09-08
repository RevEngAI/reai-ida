import threading
from dataclasses import dataclass, field

from revengai import ApiException, Configuration
from revengai.exceptions import NotFoundException

from loguru import logger

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from revengai import FunctionDataTypesList

from reai_toolkit.app.interfaces.thread_service import IThreadService
from reai_toolkit.app.services.data_types.v3_data_types import (
    list_function_signatures,
    to_legacy_function_data_types,
)
from reai_toolkit.app.transformations.import_data_types import ImportDataTypes

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

    def import_data_types(
        self, matches: dict[int, int], apply_stack_vars: bool = False
    ) -> DataTypesImportResult:
        if len(matches) == 0:
            return DataTypesImportResult()

        idt: ImportDataTypes = ImportDataTypes()
        matched_function_ids: list[int] = list(matches.keys())

        try:
            response: FunctionDataTypesList | None = self._get_data_types(matched_function_ids)
        except NotFoundException as e:
            logger.warning(f"failed to apply data types for {len(matched_function_ids)} functions: {e}")
            return DataTypesImportResult(remote_absent_ids=set(matched_function_ids))
        except ApiException as e:
            logger.error(f"RevEng.AI: failed to sync function data types: HTTP {e.status} {e.reason}")
            return DataTypesImportResult(error=f"Failed to sync function data types: HTTP {e.status} {e.reason}")
        except Exception as e:
            logger.error(f"RevEng.AI: failed to sync function data types: {e}")
            return DataTypesImportResult(error=f"Failed to sync function data types: {e}")

        # The v3 API distinguishes "no extracted signature" from a missing
        # function.  A missing signature is not a reason to send the old v2
        # data-type blob back to the server, so do not turn it into a local
        # push candidate.
        remote_absent_ids: set[int] = set()

        apply_failed_ids: set[int] = set()
        if response:
            apply_failed_ids = idt.execute(
                response, matched_function_mapping=matches, apply_stack_vars=apply_stack_vars
            ) or set()

        return DataTypesImportResult(
            remote_absent_ids=remote_absent_ids,
            apply_failed_ids=apply_failed_ids,
        )

    def _get_data_types(self, function_ids: list[int] | None = None) -> FunctionDataTypesList | None:
        if not function_ids:
            return None

        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            response = list_function_signatures(
                api_client,
                function_ids,
                include_data_types=True,
            )

        return to_legacy_function_data_types(response)
