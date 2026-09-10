"""Every SDK endpoint the plugin calls must be covered by a configured auth scheme.

A request whose declared scheme the plugin never configures goes out with no
Authorization header at all and the server answers 401 — which is what happened
to the bearerAuth-only /v2/iam/me.
"""

import ast
import collections
import inspect
import pathlib
import re

import pytest
import revengai
from unittest.mock import MagicMock

from reai_toolkit.app.services.auth.auth_service import AuthService

PLUGIN_ROOT = pathlib.Path("reai_toolkit/app")


@pytest.fixture
def service():
    cfg = MagicMock()
    cfg.api_url = "https://api.reveng.ai"
    cfg.api_key = "secret-key"
    return AuthService(cfg=cfg, ida_version="9.3", plugin_version="1.2.3")


_AUTH_RE = re.compile(r"_auth_settings:\s*List\[str\]\s*=\s*\[([^\]]*)\]", re.S)
_VARIANT_SUFFIXES = ("_without_preload_content", "_with_http_info")


def _api_calls() -> dict[str, set[str]]:
    calls: dict[str, set[str]] = collections.defaultdict(set)
    for path in PLUGIN_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text())
        aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                func = node.value.func
                if isinstance(func, ast.Name) and func.id.endswith("Api"):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            aliases[target.id] = func.id
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            receiver = node.func.value
            api = None
            if (
                isinstance(receiver, ast.Call)
                and isinstance(receiver.func, ast.Name)
                and receiver.func.id.endswith("Api")
            ):
                api = receiver.func.id
            elif isinstance(receiver, ast.Name) and receiver.id in aliases:
                api = aliases[receiver.id]
            if api is not None:
                calls[api].add(node.func.attr)
    return calls


def _declared_schemes(api_name: str, method: str) -> set[str] | None:
    api = getattr(revengai, api_name, None)
    if api is None:
        return None
    for suffix in _VARIANT_SUFFIXES:
        if method.endswith(suffix):
            method = method[: -len(suffix)]
            break
    serialize = getattr(api, f"_{method}_serialize", None)
    if serialize is None:
        return None
    match = _AUTH_RE.search(inspect.getsource(serialize))
    if match is None:
        return None
    return {s.strip().strip("'\"") for s in match.group(1).split(",") if s.strip()}


def test_the_call_discovery_actually_finds_the_plugins_endpoints():
    calls = _api_calls()

    assert "get_me" in calls.get("IAMUsersApi", set())
    assert "get_config" in calls.get("ConfigApi", set())
    assert sum(len(v) for v in calls.values()) > 40


def test_every_endpoint_the_plugin_calls_carries_credentials(service):
    configured = set(service.build_sdk_config().auth_settings())

    unauthenticated = [
        f"{api}.{method} declares {sorted(declared)}"
        for api, methods in sorted(_api_calls().items())
        for method in sorted(methods)
        if (declared := _declared_schemes(api, method)) and not declared & configured
    ]

    assert unauthenticated == [], (
        f"the plugin configures {sorted(configured)}; these endpoints declare none "
        f"of them, so their requests are sent unauthenticated: {unauthenticated}"
    )


def test_bearer_auth_is_load_bearing(service):
    without_bearer = set(service.build_sdk_config().auth_settings()) - {"bearerAuth"}

    stranded = [
        f"{api}.{method}"
        for api, methods in _api_calls().items()
        for method in methods
        if (declared := _declared_schemes(api, method)) and not declared & without_bearer
    ]

    assert stranded, (
        "nothing requires bearerAuth any more, so the coverage test above proves "
        "nothing; either access_token can be dropped or the discovery has broken"
    )
