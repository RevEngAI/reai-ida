"""Guards the PySide6 6.8 abort: signals must target a QObject, never a PluginForm."""

import ast
import pathlib

import pytest

PANELS = [
    "reai_toolkit/app/components/tabs/chat_tab.py",
    "reai_toolkit/app/components/tabs/ai_decomp_tab.py",
]

QOBJECT_RECEIVERS = ("_bridge", "_relay")


def _connect_calls(tree):
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "connect"
            and node.args
        ):
            yield node


def _describe(arg) -> str:
    return ast.unparse(arg)


def _is_qobject_receiver(arg) -> bool:
    if not isinstance(arg, ast.Attribute):
        return False
    base = arg.value
    if isinstance(base, ast.Name):
        return base.id != "self"
    if (
        isinstance(base, ast.Attribute)
        and isinstance(base.value, ast.Name)
        and base.value.id == "self"
    ):
        return base.attr in QOBJECT_RECEIVERS
    return False


@pytest.mark.parametrize("path", PANELS)
def test_panel_signals_are_delivered_to_a_qobject(path):
    source = pathlib.Path(path).read_text()
    tree = ast.parse(source)

    offenders = [
        f"line {call.lineno}: connect({_describe(call.args[0])})"
        for call in _connect_calls(tree)
        if not _is_qobject_receiver(call.args[0])
    ]

    assert offenders == [], (
        "PySide6 6.8 aborts building a global receiver when a signal is wired to a "
        "callable on a non-QObject PluginForm; route it through a @Slot on a QObject "
        f"bridge instead ({path}): {offenders}"
    )


@pytest.mark.parametrize("path", PANELS)
def test_each_panel_actually_owns_a_qobject_bridge(path):
    tree = ast.parse(pathlib.Path(path).read_text())

    bridges = [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        and any(
            isinstance(base, ast.Attribute) and base.attr == "QObject"
            for base in node.bases
        )
    ]

    assert bridges, f"{path} connects signals but defines no QObject receiver"
