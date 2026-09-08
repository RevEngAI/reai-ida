from unittest.mock import MagicMock

import pytest
from revengai import ApiException

from reai_toolkit.app.services.auth import auth_service as svc_mod
from reai_toolkit.app.services.auth.auth_service import AuthService


@pytest.fixture
def cfg():
    c = MagicMock()
    c.api_url = "https://api.reveng.ai"
    c.api_key = "secret-key"
    return c


@pytest.fixture
def service(cfg):
    return AuthService(cfg=cfg, ida_version="9.3", plugin_version="1.2.3")


@pytest.fixture
def config_api(mocker):
    mocker.patch.object(svc_mod, "ApiClient")
    api_class = mocker.patch.object(svc_mod, "ConfigApi")
    inst = MagicMock()
    api_class.return_value = inst
    return inst


@pytest.fixture
def iam_api(mocker):
    mocker.patch.object(svc_mod, "ApiClient")
    api_class = mocker.patch.object(svc_mod, "IAMUsersApi")
    inst = MagicMock()
    api_class.return_value = inst
    return inst


def _user(tier):
    user = MagicMock()
    user.tier = tier
    return user


def test_build_sdk_config_sets_host_key_and_user_agent(service):
    cfg = service.build_sdk_config()

    assert cfg.host == "https://api.reveng.ai"
    assert cfg.api_key == {"APIKey": "secret-key"}
    assert cfg.user_agent == "IDA/9.3 RevEng.AI_Plugin/1.2.3"


def test_get_sdk_config_builds_once_and_mutates_in_place(service):
    first = service.get_sdk_config()
    service.config_service.api_url = "https://other.host"
    service.config_service.api_key = "new-key"

    second = service.build_sdk_config()

    assert first is second
    assert second.host == "https://other.host"
    assert second.api_key == {"APIKey": "new-key"}


def test_verify_success(service, config_api):
    config_api.get_config.return_value = MagicMock()

    ok, msg = service.verify()

    assert ok is True
    assert msg == ""
    assert service.is_authenticated() is True


def test_verify_api_exception_with_parsed_errors(service, config_api, mocker):
    config_api.get_config.side_effect = ApiException(status=401)
    mocker.patch.object(
        svc_mod,
        "parse_exception",
        return_value=MagicMock(errors=[MagicMock(code="401", message="bad key")]),
    )

    ok, msg = service.verify()

    assert ok is False
    assert msg == "401: bad key"
    assert service.is_authenticated() is False


def test_verify_api_exception_without_parsed_body(service, config_api, mocker):
    config_api.get_config.side_effect = ApiException(status=500, reason="boom")
    mocker.patch.object(svc_mod, "parse_exception", return_value=None)

    ok, msg = service.verify()

    assert ok is False
    assert msg.startswith("API Exception:")
    assert service.is_authenticated() is False


def test_verify_unexpected_exception(service, config_api):
    config_api.get_config.side_effect = RuntimeError("network down")

    ok, msg = service.verify()

    assert ok is False
    assert "network down" in msg
    assert service.is_authenticated() is False


def test_get_me_returns_user_and_caches(service, iam_api):
    iam_api.get_me.return_value = _user("ENTHUSIAST")

    first = service.get_me()
    second = service.get_me()

    assert first.tier == "ENTHUSIAST"
    assert first is second
    iam_api.get_me.assert_called_once()


def test_get_me_uses_configured_api_key_auth(service, iam_api):
    iam_api.get_me.return_value = _user("ENTHUSIAST")

    service.get_me()

    iam_api.get_me.assert_called_once_with(
        _request_auth=service.sdk_config.auth_settings()["APIKey"]
    )


def test_get_me_force_refresh_refetches(service, iam_api):
    iam_api.get_me.side_effect = [_user("ENTHUSIAST"), _user("REVERSER")]

    first = service.get_me()
    second = service.get_me(force_refresh=True)

    assert first.tier == "ENTHUSIAST"
    assert second.tier == "REVERSER"
    assert iam_api.get_me.call_count == 2


def test_get_me_returns_none_on_error(service, iam_api):
    iam_api.get_me.side_effect = RuntimeError("network down")

    assert service.get_me() is None


def test_is_enthusiast_true_for_enthusiast_tier(service, iam_api):
    iam_api.get_me.return_value = _user("ENTHUSIAST")

    assert service.is_enthusiast() is True


@pytest.mark.parametrize(
    "tier",
    ["REVERSER", "BUG_HUNTER", "MALWARE_ANALYST", "SECURITY_RESEARCHER", None],
)
def test_is_enthusiast_false_for_other_tiers(service, iam_api, tier):
    iam_api.get_me.return_value = _user(tier)

    assert service.is_enthusiast() is False


def test_is_enthusiast_false_when_user_unavailable(service, iam_api):
    iam_api.get_me.side_effect = RuntimeError("boom")

    assert service.is_enthusiast() is False


def test_verify_success_warms_user_cache(service, config_api, iam_api):
    config_api.get_config.return_value = MagicMock()
    iam_api.get_me.return_value = _user("ENTHUSIAST")

    ok, _ = service.verify()

    assert ok is True
    iam_api.get_me.assert_called_once()
    assert service.is_enthusiast() is True
