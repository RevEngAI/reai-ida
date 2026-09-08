import queue
import threading
import time
from typing import Optional, Tuple

from libbs.artifacts import Enum, FunctionHeader, StackVariable, Struct, Typedef
from libbs.decompilers.ida.compat import DummyIDACodeView, execute_read
from libbs.decompilers.ida.compat import function as read_ida_function
from loguru import logger

from revengai import (
    FunctionArgument,
    Configuration,
    FunctionDependency,
    FunctionInfo,
    FunctionType,
)
from revengai import ApiException
from revengai.models.function_header import FunctionHeader as SdkFunctionHeader
from revengai.models.function_stack_variable import FunctionStackVariable as SdkStackVariable

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.interfaces.thread_service import IThreadService
from reai_toolkit.app.services.data_types.v3_data_types import (
    build_signature_update,
    list_function_signatures,
    update_function_signature,
)


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

    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)
        self._deci = None

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
                self._push_change(function_id, func_addr, artifact)
            except ApiException as e:
                logger.error(f"RevEng.AI: failed to push data types: HTTP {e.status} {e.reason}")
            except Exception as e:
                logger.error(f"RevEng.AI: failed to push data types: {e}")
            finally:
                self._q.task_done()

    def _push_change(self, function_id: int, func_addr: int, artifact: object) -> None:
        logger.debug(f"RevEng.AI: processing data types change for function {function_id}")
        analysis_id: int | None = self.netstore_service.get_analysis_id()
        if analysis_id is None:
            logger.debug("RevEng.AI: no analysis id; skipping data types push")
            return

        # The v3 API has no equivalent of the old opaque function-data-types
        # blob or its optimistic version field.  It does support full function
        # signature updates, but stack-variable edits have no v3 write
        # endpoint.  Do not send a false success for those edits.
        if isinstance(artifact, StackVariable):
            logger.debug(
                "RevEng.AI: v3 API has no stack-variable write endpoint; "
                f"skipping local stack variable sync for function {function_id}"
            )
            return

        info = self._build_function_info(func_addr)
        if info is None:
            logger.debug(f"RevEng.AI: could not build signature for function {function_id}; skipping push")
            return

        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                response = list_function_signatures(
                    api_client,
                    [function_id],
                    include_data_types=True,
                )
                body = build_signature_update(response, function_id, function_info=info)
                if body is None:
                    logger.debug(
                        f"RevEng.AI: no v3 signature available for function {function_id}; skipping push"
                    )
                    return
                update_function_signature(api_client, analysis_id, function_id, body)
        except ApiException as e:
            logger.error(f"RevEng.AI: failed to push function signature: HTTP {e.status} {e.reason}")
            return
        except Exception as e:
            logger.error(f"RevEng.AI: failed to push function signature: {e}")
            return

        logger.info(f"RevEng.AI: pushed function signature for function {function_id}")

    def _build_function_info(self, func_addr: int) -> Optional[FunctionInfo]:
        if self._deci is None:
            return None

        func = _read_decompiler_function(self._deci, func_addr)
        if func is None or func.header is None:
            return None

        header = func.header
        args = {
            hex(offset): FunctionArgument(
                offset=offset, name=arg.name or "", type=arg.type or "", size=arg.size or 0
            )
            for offset, arg in (header.args or {}).items()
        }
        stack_vars = {
            hex(offset): SdkStackVariable(
                offset=offset,
                name=svar.name or "",
                type=svar.type or "",
                size=svar.size or 0,
                addr=svar.addr or func.addr,
            )
            for offset, svar in (func.stack_vars or {}).items()
        }
        func_type = FunctionType(
            addr=func.addr,
            size=func.size or 0,
            header=SdkFunctionHeader(
                name=header.name or "", addr=header.addr or func.addr, type=header.type or "", args=args
            ),
            stack_vars=stack_vars,
            name=getattr(func, "name", None) or header.name or "",
            type=header.type or "",
            artifact_type="Function",
        )
        return FunctionInfo(func_types=func_type, func_deps=self._collect_func_deps(func_type))

    def _collect_func_deps(self, func_type: FunctionType) -> list:
        pending: list[str] = [func_type.type]
        pending.extend(arg.type for arg in (func_type.header.args or {}).values())
        pending.extend(svar.type for svar in (func_type.stack_vars or {}).values())

        deps: dict[str, FunctionDependency] = {}
        seen: set[str] = set()
        while pending and len(deps) < 200:
            name = self._base_type_name(pending.pop())
            if not name or name in seen:
                continue
            seen.add(name)
            dep, referenced = self._resolve_type(name)
            if dep is None:
                continue
            deps[name] = dep
            pending.extend(referenced)

        return list(deps.values())

    def _resolve_type(self, name: str) -> Tuple[Optional[FunctionDependency], list]:
        artifact = _read_named_type(self._deci, name)
        if isinstance(artifact, Typedef):
            return (
                FunctionDependency(name=artifact.name, type=artifact.type or "", artifact_type="Typedef"),
                [artifact.type],
            )
        if isinstance(artifact, Struct):
            members = {
                hex(member.offset): {
                    "name": member.name or "",
                    "offset": member.offset,
                    "type": member.type or "",
                    "size": member.size or 0,
                }
                for member in artifact.members.values()
            }
            referenced = [member.type for member in artifact.members.values()]
            return (
                FunctionDependency(name=artifact.name, size=artifact.size, members=members, artifact_type="Struct"),
                referenced,
            )
        if isinstance(artifact, Enum):
            members = {str(key): int(value) for key, value in (artifact.members or {}).items()}
            return (
                FunctionDependency(name=artifact.name, members=members, artifact_type="Enum"),
                [],
            )
        return None, []

    @staticmethod
    def _base_type_name(type_str: Optional[str]) -> Optional[str]:
        if not type_str:
            return None
        cleaned = type_str.replace("*", " ").replace("[", " ").replace("]", " ")
        keywords = {"const", "volatile", "struct", "union", "enum", "unsigned", "signed"}
        tokens = [tok for tok in cleaned.split() if tok not in keywords]
        return tokens[-1] if tokens else None

    def _patch(self, info: FunctionInfo, artifact: object) -> bool:
        ft = info.func_types
        if ft is None:
            return False

        before = ft.to_dict()
        if isinstance(artifact, StackVariable):
            self._patch_stack_var(ft, artifact)
        elif isinstance(artifact, FunctionHeader):
            self._patch_header(ft, artifact)
        # Skip the push when nothing actually changed: pure function renames also
        # raise a header event but are owned by the rename service, and sync-applied
        # edits already match the stored blob.
        return ft.to_dict() != before

    @staticmethod
    def _patch_stack_var(ft: object, svar: StackVariable) -> None:
        if not ft.stack_vars:
            return
        for entry in ft.stack_vars.values():
            if entry.offset == svar.offset:
                if svar.name is not None:
                    entry.name = svar.name
                if svar.type is not None:
                    entry.type = svar.type
                return

    @staticmethod
    def _patch_header(ft: object, fheader: FunctionHeader) -> None:
        header = ft.header
        if header is None:
            return
        if fheader.type:
            header.type = fheader.type
            ft.type = fheader.type
        if header.args and fheader.args:
            for offset, arg in fheader.args.items():
                for entry in header.args.values():
                    if entry.offset == offset:
                        if arg.name is not None:
                            entry.name = arg.name
                        if arg.type is not None:
                            entry.type = arg.type
                        break

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
        updated = 0
        for function_id, ea in targets.items():
            try:
                info = self._build_function_info(ea - base)
                if info is None:
                    continue
                with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                    response = list_function_signatures(
                        api_client,
                        [function_id],
                        include_data_types=True,
                    )
                    body = build_signature_update(response, function_id, function_info=info)
                    if body is None:
                        continue
                    update_function_signature(api_client, analysis_id, function_id, body)
                updated += 1
            except ApiException as e:
                logger.warning(
                    f"RevEng.AI: skipped v3 signature push for function {function_id}: "
                    f"HTTP {e.status} {e.reason}"
                )
            except Exception as e:
                logger.warning(
                    f"RevEng.AI: skipped v3 signature push for function {function_id}: {e}"
                )
        return updated
