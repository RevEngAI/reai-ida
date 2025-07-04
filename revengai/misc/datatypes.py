from reait.api import (
    RE_functions_data_types,
    RE_functions_data_types_poll,
)
from revengai.models import SimpleItem
from idaapi import hide_wait_box, show_wait_box
from revengai.misc.qtutils import inmain
from PyQt5.QtCore import Qt
from requests import HTTPError
from libbs.api import DecompilerInterface
from libbs.artifacts import _art_from_dict
from libbs.artifacts import (
    Function,
    FunctionArgument,
    GlobalVariable,
    Enum,
    Struct,
    Typedef,
)
from revengai.misc.utils import IDAUtils

import idaapi
import logging
import time

logger = logging.getLogger("REAI")


def wait_box_decorator(message: str = None):
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            try:
                inmain(show_wait_box, message)
                return func(self, *args, **kwargs)
            except Exception as e:
                import traceback as tb
                logger.error(f"Error: {e} \n{tb.format_exc()}")
            finally:
                inmain(hide_wait_box)

        return wrapper
    return decorator


def wait_box_decorator_noclazz(message: str = None):
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                inmain(show_wait_box, message)
                return func(*args, **kwargs)
            except Exception as e:
                import traceback as tb
                logger.error(f"Error: {e} \n{tb.format_exc()}")
            finally:
                inmain(hide_wait_box)
        return wrapper
    return decorator


def function_arguments(fnc: Function) -> list[str]:
    args = []
    for k in fnc.header.args:
        arg: FunctionArgument = fnc.header.args[k]
        args.append(
            f"{arg.type} {arg.name}"
        )
    return args


def function_to_str(fnc: Function) -> str:
    # convert the signature to a string representation
    return f"{fnc.type} {fnc.name}"\
        f"({', '.join(function_arguments(fnc))})"


def apply_signature(row: int, fnc: Function, deps: list, resultTable):
    # set the selected row of the table and modify the function
    # signature column to show the new signature
    model = resultTable.model()
    index = model.index(row, 3)
    signature = function_to_str(fnc)
    logger.info(
        f"Function signature: {signature}"
    )
    model.setData(index, SimpleItem(
        text=signature,
        data={
            "function": fnc,
            "deps": deps,
        }
    ), Qt.DisplayRole)
    model.dataChanged.emit(index, index)


def apply_type(
    deci: DecompilerInterface,
    artifact,
    soft_skip=False
) -> None | str:
    supported_types = [
        Function,
        GlobalVariable,
        Enum,
        Struct,
        Typedef
    ]

    if not any(isinstance(artifact, t) for t in supported_types):
        return "Unsupported artifact type: " \
            f"{artifact.__class__.__name__}"

    try:

        if isinstance(artifact, Function):
            deci.functions[artifact.addr] = artifact
        elif isinstance(artifact, GlobalVariable):
            deci.global_vars[artifact.addr] = artifact
        elif isinstance(artifact, Enum):
            deci.enums[artifact.name] = artifact
        elif isinstance(artifact, Struct):
            deci.structs[artifact.name] = artifact
        elif isinstance(artifact, Typedef):
            deci.typedefs[artifact.name] = artifact
    except Exception as e:
        logger.error(f"Error while applying artifact '{artifact.name}'"
                     f" of type {artifact.__class__.__name__}: {e}")
        if not soft_skip:
            return f"Error while applying artifact '{artifact.name}'"\
                f" of type {artifact.__class__.__name__}: {e}"

    return None


def apply_types(
        deci: DecompilerInterface,
        artifacts: list
) -> None | str:
    for artifact in artifacts:
        error = inmain(apply_type, deci, artifact, True)
        if error is not None:
            return error
    return None


def _load_many_artifacts_from_list(artifacts: list[dict]) -> list:
    _artifacts = []
    for artifact in artifacts:
        art = _art_from_dict(artifact)
        if art is not None:
            _artifacts.append(art)
    return _artifacts


def apply_multiple_data_types(
        to_process: list[dict],
        deci: DecompilerInterface = None,
        progress_cb: callable = None,
        complete_cb: callable = None,
) -> None | str:
    if not deci:
        logger.error("Libbs: Unable to find a decompiler")
        return "Unable to find a decompiler"

    if not to_process:
        logger.warning("No data types to process.")
        return "No data types to process"

    if not isinstance(to_process, list):
        logger.error("to_process must be a list of dictionaries.")
        return "to_process must be a list of dictionaries"

    if progress_cb is not None and callable(progress_cb):
        progress_cb(0)

    el_count = len(to_process)
    cur_count = 0

    for item in to_process:
        cur_count += 1
        progress = int(
            (cur_count / el_count) * 100
        )
        original_addr = item["original_addr"]
        nnfn = item["nnfn"]
        signature = item["signature"]

        if inmain(IDAUtils.set_name, original_addr, nnfn):
            if signature is not None:
                apply_data_types(
                    original_addr,
                    signature,
                    deci
                )
            if progress_cb is not None and callable(progress_cb):
                progress_cb(progress)

    if progress_cb is not None and callable(progress_cb):
        progress_cb(100)

    if complete_cb is not None and callable(complete_cb):
        complete_cb()


def apply_data_types(
        function_addr: int = 0,
        signature=None,
        deci: DecompilerInterface = None,
):
    # deci = DecompilerInterface.discover(force_decompiler="ida")
    if not deci:
        logger.error("Libbs: Unable to find a decompiler")
        return

    try:
        # get the function signature from the table
        function: Function = signature.get("function")
        deps = signature.get("deps")

        function.addr = function_addr

        # fisrt apply the dependencies
        res = apply_types(deci, _load_many_artifacts_from_list(deps))
        if res is not None:
            logger.error(
                f"Failed to apply function dependencies: {res}")
            return

        # then apply the function signature
        res = inmain(apply_type, deci, function)
        if res is not None:
            logger.error(f"Failed to apply function signature: {res}")
            return

        # show success message
        logger.info(
            "Successfully applied function signature and dependencies"
        )

    except Exception as e:
        import traceback as tb
        logger.error(f"Error: {e} \n{tb.format_exc()}")
        idaapi.warning(
            f"Error: {e}"
        )


def fetch_data_types(
        function_ids: list[int],
        progress_cb: callable = None,
        complete_cb: callable = None,
) -> None:
    try:
        logging.info(
            "Fetching data types for the specified functions..."
            f"({len(function_ids)})"
        )
        # ignore the results
        RE_functions_data_types(
            function_ids=function_ids,
        )

        # poll for data type completition
        res: dict = RE_functions_data_types_poll(
            function_ids=function_ids,
        ).json()

        data = res.get("data", {})
        total_count = data.get("total_count", 0)
        total_data_types = data.get("total_data_types_count", 0)
        items = data.get("items", [])
        # check if all items have completed=True
        completed = all(
            item.get("completed", False) for item in items
        )
        n_items = len(items)
        n_completed = sum(
            1 for item in items if item.get("completed", False)
        )
        percentage = int(
            (n_completed / n_items) * 100
        ) if n_items > 0 else 0

        if progress_cb is not None and callable(progress_cb):
            progress_cb(percentage)

        while total_count != total_data_types or not completed:
            time.sleep(0.1)
            res = RE_functions_data_types_poll(
                function_ids=function_ids,
            ).json()
            data = res.get("data", {})
            items = data.get("items", [])

            n_items = len(items)
            n_completed = sum(
                1 for item in items if item.get("completed", False)
            )

            percentage = int(
                (n_completed / n_items) * 100
            ) if n_items > 0 else 0

            if progress_cb is not None and callable(progress_cb):
                progress_cb(percentage)

            completed = all(
                item.get("completed", False) for item in items
            )

            if completed:
                logger.info(
                    "All data types have been fetched and processed."
                )
                break

        # notify the callback if provided that the process is done
        if progress_cb is not None and callable(progress_cb):
            progress_cb(100)

        logger.info(
            "Data types generation completed."
        )

        def extract(item: dict) -> dict:
            types = item.get("data_types", {})
            data = {
                "function_id": item.get("function_id", 0),
            }
            if types:
                data["func_types"] = types.get("func_types", {})
                data["func_deps"] = types.get("func_deps", {})
            return data

        completed_items = list(
            map(
                extract,
                filter(
                    lambda item:
                    item.get("status", "not_completed") == "completed" and
                    item.get("completed", False),
                    items
                )
            )
        )

        if complete_cb is not None and callable(complete_cb):
            complete_cb(completed_items)
        else:
            logger.info(
                f"Fetched {len(completed_items)} data types for the "
                f"specified functions."
            )
            return completed_items
    except HTTPError as e:
        resp = e.response.json()
        error = resp.get("message", "Unexpected error occurred.")
        logger.error(
            "Error while fetching data types for the specified function:"
            f"{error}"
        )
        return []


def import_data_types(
        function_ids: list[int],
        # map the function ids to the function addresses
        # this is used to update the function signature
        function_mapper: dict[int, int] = {},
) -> None:
    # get the data types from the server
    data = fetch_data_types(function_ids)
    if not data:
        logger.warning(
            "No data types found for the specified functions."
        )
        return

    deci = DecompilerInterface.discover(force_decompiler="ida")
    if not deci:
        logger.error("Libbs: Unable to find a decompiler")
        return

    try:
        for item in data:
            ftypes = item.get("func_types", {})
            fdeps = item.get("func_deps", [])
            fid = item.get("function_id", 0)
            func_addr = function_mapper.get(fid, 0)

            if func_addr == 0:
                logger.warning(
                    f"Function address not found for function id {fid}."
                )
                continue

            # first apply the dependencies
            res = apply_types(deci, _load_many_artifacts_from_list(fdeps))
            if res is not None:
                logger.error(
                    f"Failed to apply function dependencies: {res}")
                continue

            # then apply the function signature
            func: Function = _art_from_dict(ftypes)
            if func is None:
                logger.warning(
                    f"Function signature not found for function id {fid}."
                )
                continue

            func.addr = func_addr
            logger.info(
                f"Applying function signature for '{func.name}'"
            )
            res = apply_type(deci, func)

            if res is not None:
                logger.error(
                    f"Failed to apply function signature: {res}"
                )
                continue
        # show success message
        logger.info(
            "Successfully applied function signatures and dependencies"
        )
    except Exception as e:
        import traceback as tb
        logger.error(f"Error: {e} \n{tb.format_exc()}")
        idaapi.warning(
            f"Error: {e}"
        )
