"""Config flow for the Network Map integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
import aiohttp

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME, CONF_PORT
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    DOMAIN, DEFAULT_PORT, CONF_API_KEY, BETTERCAP_API_URL,
    CONF_ENABLE_NET_PROBE, CONF_ENABLE_NET_SNIFF, CONF_ENABLE_ARP_SPOOF, CONF_ENABLE_TICKER,
    CONF_ENABLE_NET_RECON, CONF_ENABLE_ZEROGOD,
    DEFAULT_ENABLE_NET_PROBE, DEFAULT_ENABLE_NET_SNIFF, DEFAULT_ENABLE_ARP_SPOOF, DEFAULT_ENABLE_TICKER,
    DEFAULT_ENABLE_NET_RECON, DEFAULT_ENABLE_ZEROGOD,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST, default="localhost"): str,
        vol.Required(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Optional(CONF_USERNAME, default="user"): str,
        vol.Optional(CONF_PASSWORD, default="your_secure_password"): str,
        vol.Optional(CONF_API_KEY, default=""): str,
        vol.Required(CONF_ENABLE_NET_PROBE, default=DEFAULT_ENABLE_NET_PROBE): bool,
        vol.Required(CONF_ENABLE_NET_SNIFF, default=DEFAULT_ENABLE_NET_SNIFF): bool,
        vol.Required(CONF_ENABLE_ARP_SPOOF, default=DEFAULT_ENABLE_ARP_SPOOF): bool,
        vol.Required(CONF_ENABLE_TICKER, default=DEFAULT_ENABLE_TICKER): bool,
        vol.Required(CONF_ENABLE_NET_RECON, default=DEFAULT_ENABLE_NET_RECON): bool,
        vol.Required(CONF_ENABLE_ZEROGOD, default=DEFAULT_ENABLE_ZEROGOD): bool,
    }
)


class BettercapConnector:
    """Class to handle connection to Bettercap API."""

    def __init__(self, host: str, port: int, username: str, password: str, api_key: str) -> None:
        """Initialize."""
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.api_key = api_key
        self.api_url = BETTERCAP_API_URL.format(host=host, port=port)

    async def authenticate(self, hass: HomeAssistant) -> bool:
        """Test if we can authenticate with the Bettercap API."""
        try:
            session = async_get_clientsession(hass)
            auth = aiohttp.BasicAuth(self.username, self.password)
            headers = {"X-API-KEY": self.api_key} if self.api_key else {}

            async with session.get(
                f"{self.api_url}/session",
                auth=auth,
                headers=headers,
                timeout=10
            ) as response:
                if response.status == 200:
                    return True
                else:
                    _LOGGER.error("Failed to authenticate: %s", response.status)
                    return False
        except aiohttp.ClientError as err:
            _LOGGER.error("Error connecting to Bettercap: %s", err)
            return False


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect.

    Data has the keys from STEP_USER_DATA_SCHEMA with values provided by the user.
    """
    hub = BettercapConnector(
        data[CONF_HOST],
        data[CONF_PORT],
        data[CONF_USERNAME],
        data[CONF_PASSWORD],
        data[CONF_API_KEY]
    )

    if not await hub.authenticate(hass):
        raise InvalidAuth

    return {"title": f"Network Map ({data[CONF_HOST]})"}


class ConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Network Map."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                info = await validate_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(title=info["title"], data=user_input)

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
