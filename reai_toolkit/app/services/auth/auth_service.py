from typing import Tuple

from loguru import logger
from revengai import ApiClient, ApiException, ConfigApi, Configuration, IAMUsersApi, User

from reai_toolkit.app.core.config_service import ConfigService
from reai_toolkit.app.core.utils import parse_exception

ENTHUSIAST_TIER = "ENTHUSIAST"


class AuthService:
    _ida_version: str = "UNKNOWN"
    _plugin_version: str = "UNKNOWN"

    def __init__(
        self,
        cfg: ConfigService,
        ida_version: str = "UNKNOWN",
        plugin_version: str = "UNKNOWN",
    ):
        self.config_service = cfg
        self.sdk_config: Configuration = None
        self._ida_version = ida_version
        self._plugin_version = plugin_version
        self._is_authed: bool = False
        self._user: User | None = None

    def get_sdk_config(self) -> Configuration | None:
        """
        Return a valid SDK config object or None.
        1. If we already have a valid one, return it.
        2. Otherwise, create it and verify it.
        Returns Configuration|None.

        No exceptions are raised.

        Configuration|None: The config object if valid, else None.
        """

        if self.sdk_config is None:
            self.build_sdk_config()

        return self.sdk_config

    def build_sdk_config(self) -> Configuration:
        """
        Build and return the SDK Configuration object.
        Does not verify it.
        Returns Configuration.
        """

        # First call - full object creation
        if self.sdk_config is None:
            self.sdk_config = Configuration(
                host=self.config_service.api_url,
                api_key={"APIKey": self.config_service.api_key},
                access_token=self.config_service.api_key,
            )
        # Other calls must reassign values - do not create new object (mutate existing one, all holders share ref)
        else:
            self.sdk_config.host = self.config_service.api_url
            self.sdk_config.api_key = {"APIKey": self.config_service.api_key}
            self.sdk_config.access_token = self.config_service.api_key

        self.sdk_config.user_agent = (
            f"IDA/{self._ida_version} RevEng.AI_Plugin/{self._plugin_version}"
        )

        return self.sdk_config

    def verify(self) -> Tuple[bool, str]:
        """
        Call User Info to validate apikey and return (Bool, Str).
        No exceptions are raised.
        Returns True if authenticated, False if not.
        If there is an error, returns (False, response).
        """

        if self.sdk_config is None:
            self.build_sdk_config()

        # Auth Call
        with ApiClient(configuration=self.sdk_config) as api_client:
            if hasattr(self.sdk_config, "user_agent"):
                api_client.user_agent = self.sdk_config.user_agent
            try:
                ConfigApi(api_client).get_config()
                logger.info("RevEng.AI: User authenticated successfully.")
                self._is_authed = True
                self.get_me(force_refresh=True)
                return True, ""

            except ApiException as e:
                self._is_authed = False
                error_response = parse_exception(e)
                if (
                    error_response
                    and error_response.errors
                    and len(error_response.errors) > 0
                ):
                    logger.error(
                        f"RevEng.AI: Authentication failed. API Exception: {error_response.errors[0].code}: {error_response.errors[0].message}"
                    )
                    return (
                        False,
                        f"{error_response.errors[0].code}: {error_response.errors[0].message}",
                    )
                else:
                    logger.error(
                        f"RevEng.AI: Authentication failed. API Exception: {e}"
                    )
                    return False, f"API Exception: {e}"

            except Exception as e:
                self._is_authed = False
                logger.error(f"RevEng.AI: Authentication failed. Unexpected Error: {e}")
                return False, f"Unexpected Error: {e}"

    def is_authenticated(self) -> bool:
        """
        Return whether we are authenticated.
        Returns Bool.
        """

        return self._is_authed

    def get_me(self, force_refresh: bool = False) -> User | None:
        """
        Fetch the authenticated user from /v2/iam/me, or None on failure.
        Result is cached; pass force_refresh=True to re-fetch.
        No exceptions are raised.
        """

        if self._user is not None and not force_refresh:
            return self._user

        if self.sdk_config is None:
            self.build_sdk_config()

        with ApiClient(configuration=self.sdk_config) as api_client:
            if hasattr(self.sdk_config, "user_agent"):
                api_client.user_agent = self.sdk_config.user_agent
            try:
                self._user = IAMUsersApi(api_client).get_me()
            except Exception as e:
                logger.error(f"RevEng.AI: Failed to fetch current user: {e}")
                self._user = None

        return self._user

    def is_enthusiast(self) -> bool:
        """
        Return whether the authenticated user is on the Enthusiast tier.
        Enthusiast-tier users cannot create private analyses.
        """

        user = self.get_me()
        return user is not None and user.tier == ENTHUSIAST_TIER
