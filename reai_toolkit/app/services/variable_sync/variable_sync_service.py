import queue
import re
import threading
import time
from typing import Any, Optional, Tuple

from libbs.artifacts import Enum, StackVariable, Struct, Typedef
from libbs.decompilers.ida.compat import DummyIDACodeView, execute_read
from libbs.decompilers.ida.compat import function as read_ida_function
from loguru import logger

from revengai import ApiException, Configuration, DataTypesApi
from revengai.exceptions import NotFoundException

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.interfaces.thread_service import IThreadService
from reai_toolkit.app.services.data_types.analysis_catalogue import (
    AnalysisDataTypesService,
)

MAX_TYPE_DEPENDENCIES = 200

_ARRAY_SUFFIX_RE = re.compile(r"\[[^\]]*\]")


@execute_read
def _read_decompiler_function(deci, func_addr: int):
    lowered: int = deci.art_lifter.lower_addr(func_addr)
    try:
        if deci.decompiler_available:
            code_view = DummyIDACodeView(lowered)
            if code_view.cfunc is None:
                return None
            func = read_ida_function(lowered, ida_code_view=code_view)
        else:
            func = read_ida_function(lowered, decompiler_available=False)
    except Exception as e:
        logger.debug(f"RevEng.AI: could not read function at 0x{lowered:x}: {e}")
        return None

    return deci.art_lifter.lift(func) if func is not None else None


@execute_read
def _read_named_type(deci, name: str):
    for store in (deci.typedefs, deci.structs, deci.enums):
        try:
            artifact = store.get(name)
        except Exception:
            artifact = None
        if artifact is not None:
            return artifact
    return None


class VariableSyncService(IThreadService):
    _q: queue.Queue[Tuple[int, int, object]] = queue.Queue()
    _last_ts: dict[tuple, float] = {}
    _debounce_ms: int = 400

    def __init__(
        self,
        netstore_service: SimpleNetStore,
        sdk_config: Configuration,
        data_types_catalogue: Optional[AnalysisDataTypesService] = None,
    ):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)
        self._deci = None
        self._catalogue = data_types_catalogue or AnalysisDataTypesService(
            netstore_service=netstore_service, sdk_config=sdk_config
        )

    def attach_decompiler(self, deci) -> None:
        self._deci = deci

    def enqueue_change(self, function_id: int, func_addr: int, artifact: object) -> None:
        key = self._debounce_key(function_id, artifact)
        now = time.time()
        last = self._last_ts.get(key, 0.0)
        self._last_ts[key] = now
        if (now - last) * 1000.0 <= self._debounce_ms:
            logger.debug(f"RevEng.AI: debounced data types change for function {function_id}")
            return
        logger.debug(f"RevEng.AI: queued data types change for function {function_id}")
        self._q.put((function_id, func_addr, artifact))
        self._start_worker_if_needed()

    @staticmethod
    def _debounce_key(function_id: int, artifact: object) -> tuple:
        if isinstance(artifact, StackVariable):
            return (function_id, "sv", artifact.offset)
        return (function_id, "hdr")

    def _start_worker_if_needed(self) -> None:
        if self._worker_thread and self._worker_thread.is_alive():
            return
        self.stop_worker()
        self.start_worker(target=self._worker)

    def _worker(self, stop_event: Optional[threading.Event] = None) -> None:
        while not (stop_event and stop_event.is_set()):
            try:
                function_id, func_addr, artifact = self._q.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                self._push_change(function_id, func_addr)
            except ApiException as e:
                logger.error(f"RevEng.AI: failed to push data types: HTTP {e.status} {e.reason}")
            except Exception as e:
                logger.error(f"RevEng.AI: failed to push data types: {e}")
            finally:
                self._q.task_done()

    def _push_change(self, function_id: int, func_addr: int) -> None:
        logger.debug(f"RevEng.AI: processing data types change for function {function_id}")
        analysis_id: int | None = self.netstore_service.get_analysis_id()
        if analysis_id is None:
            logger.debug("RevEng.AI: no analysis id; skipping data types push")
            return

        signature = self._build_signature(analysis_id, func_addr)
        if signature is None:
            logger.debug(
                f"RevEng.AI: could not build a signature for function {function_id}; skipping push"
            )
            return

        if self._put_signature(analysis_id, function_id, signature):
            logger.info(f"RevEng.AI: pushed data types for function {function_id}")

    def _build_signature(self, analysis_id: int, func_addr: int) -> Optional[dict]:
        if self._deci is None:
            return None

        func = _read_decompiler_function(self._deci, func_addr)
        if func is None or func.header is None:
            return None

        header = func.header
        artifacts = self._collect_type_artifacts(func)
        ids = self._catalogue.ensure(analysis_id, artifacts) if artifacts else {}

        parameters = []
        for ordinal, (_, arg) in enumerate(sorted((header.args or {}).items())):
            parameters.append(
                {
                    "ordinal": ordinal,
                    "name": arg.name or None,
                    "data_type_id": self._type_id(analysis_id, arg.type, ids),
                }
            )

        return {
            "parameters": parameters,
            "return_data_type_id": self._type_id(analysis_id, header.type, ids),
        }

    def _type_id(
        self, analysis_id: int, type_name: Optional[str], ids: dict[str, int]
    ) -> Optional[int]:
        if not type_name:
            return None
        if type_name in ids:
            return ids[type_name]
        return self._catalogue.resolve(analysis_id, type_name)

    def _collect_type_artifacts(self, func: Any) -> dict[str, Any]:
        header = func.header
        pending: list[Optional[str]] = [header.type]
        pending.extend(arg.type for arg in (header.args or {}).values())
        pending.extend(svar.type for svar in (func.stack_vars or {}).values())

        artifacts: dict[str, Any] = {}
        seen: set[str] = set()
        while pending and len(artifacts) < MAX_TYPE_DEPENDENCIES:
            name = self._base_type_name(pending.pop())
            if not name or name in seen:
                continue
            seen.add(name)

            artifact = _read_named_type(self._deci, name)
            if artifact is None:
                continue
            artifacts[name] = artifact
            pending.extend(self._referenced_types(artifact))

        return artifacts

    @staticmethod
    def _referenced_types(artifact: Any) -> list:
        if isinstance(artifact, Typedef):
            return [artifact.type]
        if isinstance(artifact, Struct):
            return [member.type for member in (artifact.members or {}).values()]
        if isinstance(artifact, Enum):
            return []
        return []

    @staticmethod
    def _base_type_name(type_str: Optional[str]) -> Optional[str]:
        if not type_str:
            return None
        cleaned = _ARRAY_SUFFIX_RE.sub(" ", type_str).replace("*", " ")
        keywords = {"const", "volatile", "struct", "union", "enum", "unsigned", "signed"}
        tokens = [tok for tok in cleaned.split() if tok not in keywords]
        return tokens[-1] if tokens else None

    def _put_signature(self, analysis_id: int, function_id: int, signature: dict) -> bool:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                DataTypesApi(api_client).v3_update_function_signature(
                    analysis_id=analysis_id,
                    function_id=function_id,
                    update_function_signature_input_body=signature,
                )
        except NotFoundException:
            logger.debug(
                f"RevEng.AI: no extracted signature for function {function_id}; nothing to edit"
            )
            return False
        return True

    def push_local_function_types_batch(self, targets: dict[int, int], analysis_id: int | None) -> int:
        if not targets or analysis_id is None:
            return 0

        if self._deci is None:
            try:
                from libbs.api import DecompilerInterface

                self.attach_decompiler(DecompilerInterface.discover(force_decompiler="ida"))
            except Exception as e:
                logger.error(f"RevEng.AI: could not attach decompiler for type push-back: {e}")
                return 0

        base: int = self._deci.binary_base_addr
        updated: int = 0
        for function_id, ea in targets.items():
            try:
                signature = self._build_signature(analysis_id, ea - base)
            except Exception as e:
                logger.debug(f"RevEng.AI: could not build local types for function {function_id}: {e}")
                continue
            if signature is None:
                continue

            try:
                if self._put_signature(analysis_id, function_id, signature):
                    updated += 1
            except ApiException as e:
                logger.warning(
                    f"RevEng.AI: type push for function {function_id} failed: HTTP {e.status} {e.reason}"
                )

        return updated
