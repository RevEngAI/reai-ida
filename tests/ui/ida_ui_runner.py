import json
import os
import sys
import time
import traceback


def _add_paths() -> None:
    root = os.environ["REAI_UI_ROOT"]
    pyver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    suffixes = [
        "vendor",
        "vendor/site-packages",
        "vendor/Lib/site-packages",
        f"vendor/lib/{pyver}/site-packages",
        f"vendor/{pyver}/site-packages",
    ]
    for base in (root, os.path.join(root, "reai_toolkit")):
        for suffix in suffixes:
            path = os.path.join(base, suffix)
            if os.path.isdir(path) and path not in sys.path:
                sys.path.insert(0, path)
    if root not in sys.path:
        sys.path.insert(0, root)


def _run(report: dict) -> None:
    from unittest.mock import MagicMock

    import ida_hexrays
    import ida_segment
    import idautils
    import idc

    from reai_toolkit.app.services.variable_sync.variable_sync_service import (
        _read_decompiler_function,
    )
    from reai_toolkit.app.transformations.import_data_types import (
        FunctionSignatures,
        ImportDataTypes,
    )

    if not ida_hexrays.init_hexrays_plugin():
        report["errors"].append("hexrays unavailable")
        return

    funcs = [
        ea
        for ea in idautils.Functions()
        if ida_segment.getseg(ea) and ida_segment.getseg(ea).type == ida_segment.SEG_CODE
    ]
    if len(funcs) < 3:
        report["errors"].append(f"not enough code functions: {len(funcs)}")
        return

    anchor, targets = funcs[0], funcs[1:41]
    report["target_count"] = len(targets)
    vdui = ida_hexrays.open_pseudocode(anchor, 0)
    report["baseline_ea"] = vdui.cfunc.entry_ea

    class Recorder(ida_hexrays.Hexrays_Hooks):
        def open_pseudocode(self, view) -> int:
            report["pseudocode_opens"].append(view.cfunc.entry_ea)
            return 0

        def switch_pseudocode(self, view) -> int:
            report["pseudocode_switches"].append(view.cfunc.entry_ea)
            return 0

        def refresh_pseudocode(self, view) -> int:
            report["refresh_count"] += 1
            return 0

    recorder = Recorder()
    recorder.hook()
    report["screen_ea_before"] = idc.get_screen_ea()
    try:
        data_types = {
            "1": {"data_type_id": 1, "name": "int", "kind": "BASE", "size": 4},
            "2": {
                "data_type_id": 2,
                "name": "ReaiUiTestStruct",
                "kind": "STRUCT",
                "size": 8,
                "definition": {
                    "members": [
                        {"name": "field0", "offset": 0, "size": 4, "data_type_id": 1}
                    ]
                },
            },
            "3": {
                "data_type_id": 3,
                "name": "ReaiUiTestStruct *",
                "kind": "POINTER",
                "size": 8,
                "definition": {"pointee_data_type_id": 2},
            },
        }
        items = []
        mapping: dict[int, int] = {}
        for fid, ea in enumerate(targets, start=1):
            items.append(
                {
                    "function_id": fid,
                    "function_name": f"reai_ui_{fid}",
                    "has_signature": True,
                    "parameters": [
                        {"ordinal": 0, "name": "a", "data_type_id": 1},
                        {"ordinal": 1, "name": "b", "data_type_id": 3},
                    ],
                    "return_data_type_id": 1,
                }
            )
            mapping[fid] = ea

        started = time.monotonic()
        failed = ImportDataTypes().execute(
            FunctionSignatures(items=items, data_types=data_types),
            matched_function_mapping=mapping,
        )
        report["import_seconds"] = round(time.monotonic() - started, 3)
        report["import_failed_ids"] = sorted(failed)
        report["functions_imported"] = len(targets) - len(failed)

        deci = MagicMock()
        deci.decompiler_available = True
        deci.art_lifter.lower_addr.side_effect = lambda addr: addr
        deci.art_lifter.lift.side_effect = lambda func: func
        started = time.monotonic()
        report["functions_read"] = sum(
            1 for ea in targets if _read_decompiler_function(deci, ea) is not None
        )
        report["read_seconds"] = round(time.monotonic() - started, 3)
    finally:
        recorder.unhook()

    report["final_vdui_ea"] = vdui.cfunc.entry_ea
    report["screen_ea_after"] = idc.get_screen_ea()
    report["ok"] = not report["errors"]


def main() -> None:
    import ida_auto
    import ida_pro

    report = {
        "ok": False,
        "errors": [],
        "pseudocode_opens": [],
        "pseudocode_switches": [],
        "refresh_count": 0,
        "baseline_ea": None,
        "final_vdui_ea": None,
        "screen_ea_before": None,
        "screen_ea_after": None,
        "target_count": 0,
        "import_failed_ids": None,
        "functions_imported": 0,
        "functions_read": 0,
        "import_seconds": None,
        "read_seconds": None,
    }
    ida_auto.auto_wait()
    try:
        _add_paths()
        _run(report)
    except Exception:
        report["errors"].append(traceback.format_exc())
    with open(os.environ["REAI_UI_REPORT"], "w") as fh:
        json.dump(report, fh)
    ida_pro.qexit(0)


main()
