import json
import os
import shutil
import subprocess
import sys

import pytest

pytestmark = pytest.mark.ida_ui

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUNNER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai_decomp_ui_runner.py")
HELLO_ELF = os.path.join(ROOT, "tests", "fixtures", "hello.elf")

CHECKS = [
    "view_created",
    "editor_read_only",
    "only_identifiers_offer_rename",
    "render_shows_code",
    "rename_double_click_overrides",
    "rename_overrides_correct",
    "rename_non_token_info",
    "rename_non_token_reason",
    "rename_comment_line_reason",
    "rename_data_type_reason",
    "predicted_hidden_without_a_prediction",
    "predicted_shown_with_a_prediction",
    "predicted_button_renames",
    "predicted_hidden_when_cleared",
    "comment_add_sets",
    "comment_add_args_correct",
    "comment_edit_empty_removes",
    "comment_remove_deletes",
    "comment_remove_args_correct",
    "refresh_button_invalidates",
]


def _ida_gui_binary() -> str | None:
    path = os.path.join(os.environ.get("IDADIR", ""), "ida")
    return path if os.path.isfile(path) else None


def _ida_gui_running() -> bool:
    for name in ("ida", "ida64", "idat"):
        try:
            if subprocess.run(["pgrep", "-x", name], capture_output=True).returncode == 0:
                return True
        except FileNotFoundError:
            return False
    return False


def _headless_env() -> dict[str, str]:
    if sys.platform == "linux" and not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        return {"QT_QPA_PLATFORM": "offscreen"}
    return {}


@pytest.mark.skipif(
    os.environ.get("REAI_UI_TESTS") != "1",
    reason="GUI IDA test; set REAI_UI_TESTS=1 to enable",
)
def test_ai_decomp_editing_flow_in_gui(tmp_path):
    ida = _ida_gui_binary()
    if ida is None:
        pytest.skip("IDADIR not set or ida binary missing")
    if _ida_gui_running():
        pytest.skip("an IDA instance is already running (license seat busy)")
    if not os.path.isfile(HELLO_ELF):
        pytest.skip(f"missing fixture {HELLO_ELF}")

    binary = tmp_path / "hello.elf"
    shutil.copy(HELLO_ELF, binary)
    report_path = tmp_path / "report.json"
    log_path = tmp_path / "ida.log"
    env = dict(
        os.environ,
        REAI_UI_REPORT=str(report_path),
        REAI_UI_ROOT=ROOT,
        **_headless_env(),
    )

    proc = subprocess.run(
        [ida, "-A", f"-S{RUNNER}", f"-L{log_path}", str(binary)],
        env=env,
        capture_output=True,
        timeout=300,
    )

    if not report_path.is_file():
        log = log_path.read_text() if log_path.is_file() else ""
        stderr = proc.stderr.decode(errors="replace")
        stdout = proc.stdout.decode(errors="replace")
        if "license" in log.lower() or "license" in stderr.lower():
            pytest.skip("IDA license unavailable")
        pytest.fail(
            f"IDA produced no report (rc={proc.returncode});"
            f"\nstderr tail:\n{stderr[-2000:]}"
            f"\nstdout tail:\n{stdout[-2000:]}"
            f"\nlog tail:\n{log[-2000:]}"
        )

    report = json.loads(report_path.read_text())

    assert report["errors"] == [], report["errors"]
    assert report["ok"] is True
    for check in CHECKS:
        assert report.get(check) is True, f"{check} failed: {report}"
