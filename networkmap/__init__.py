"""The Network Map integration."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from datetime import datetime
import logging
from typing import Any

import json
import aiohttp

import aiooui
from getmac import get_mac_address

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_PORT,
    EVENT_HOMEASSISTANT_STARTED,
)
from homeassistant.core import CoreState, HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv, entity_registry as er
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import format_mac
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.util import dt as dt_util

from .const import (
    DOMAIN,
    PLATFORMS,
    DEFAULT_SCAN_INTERVAL,
    CONF_SCAN_INTERVAL,
    CONF_API_KEY,
    BETTERCAP_API_URL,
    CONF_ENABLE_NET_PROBE,
    CONF_ENABLE_NET_SNIFF,
    CONF_ENABLE_NET_RECON,
    CONF_ENABLE_ZEROGOD,
    BETTERCAP_NET_PROBE_ON,
    BETTERCAP_NET_PROBE_OFF,
    BETTERCAP_NET_SNIFF_ON,
    BETTERCAP_NET_SNIFF_OFF,
    BETTERCAP_NET_RECON_ON,
    BETTERCAP_NET_RECON_OFF,
    BETTERCAP_NET_SHOW_META_ON,
    BETTERCAP_ZEROGOD_DISCOVERY_ON,
    BETTERCAP_ZEROGOD_DISCOVERY_OFF,
    BETTERCAP_NET_CLEAR
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Network Map from a config entry."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    scanner = domain_data[entry.entry_id] = NetworkDeviceScanner(hass, entry)

    if not await scanner.async_setup():
        raise ConfigEntryNotReady

    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Perform initial scan after setup
    hass.async_create_task(scanner._async_scan_devices())

    return True


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        await hass.data[DOMAIN][entry.entry_id].async_shutdown()
        hass.data[DOMAIN].pop(entry.entry_id)
    return unload_ok


def signal_device_new(entry_id: str) -> str:
    """Signal for new device discovery."""
    return f"{DOMAIN}_device_new_{entry_id}"

def signal_device_updated(entry_id: str) -> str:
    """Signal for device data updates."""
    return f"{DOMAIN}_device_updated_{entry_id}"

def signal_device_offline(entry_id: str) -> str:
    """Signal for device going offline."""
    return f"{DOMAIN}_device_offline_{entry_id}"


class NetworkDevice:
    """Class for keeping track of a network device."""
    def __init__(self, mac_address: str):
        """Initialize the device."""
        self.mac_address = mac_address
        self.online: bool = False
        self.first_offline: datetime | None = None
        self.first_seen: datetime = dt_util.now()
        self.last_seen: datetime = dt_util.now()
        # Store the raw data from the last scan
        self.raw_data: dict[str, Any] = {}


class NetworkDeviceScanner:
    """Scanner for network devices using Bettercap API."""
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the scanner."""
        self._hass = hass
        self._entry = entry
        self._config = entry.data
        self._scan_interval = timedelta(seconds=entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL))
        self._devices: dict[str, NetworkDevice] = {}
        self._scan_lock = asyncio.Lock()
        self._session = async_get_clientsession(hass)
        self._api_url = BETTERCAP_API_URL.format(host=self._config[CONF_HOST], port=self._config[CONF_PORT])
        # Set up authentication only if username and password are provided
        self._auth = None
        if self._config.get(CONF_USERNAME) and self._config.get(CONF_PASSWORD):
            self._auth = aiohttp.BasicAuth(self._config[CONF_USERNAME], self._config[CONF_PASSWORD])

        # Set up API key header only if API key is provided
        self._headers = {}
        if self._config.get(CONF_API_KEY):
            self._headers = {"X-API-KEY": self._config[CONF_API_KEY]}
        self._unsub_interval_scan = None
        self._known_mac_addresses: dict[str, str] = {}
        self._existing_mac_entities: dict[str, dict] = {}
        self._existing_hostname_entities: dict[str, dict] = {}

    async def async_setup(self) -> bool:
        """Set up the scanner and start periodic scanning."""
        # Test connection to Bettercap
        try:
            # First try to access the session endpoint
            async with self._session.get(f"{self._api_url}/session", auth=self._auth, headers=self._headers, timeout=10) as response:
                if response.status != 200:
                    _LOGGER.error("Failed to connect to Bettercap session API: %s", response.status)
                    # Try the status endpoint as fallback
                    async with self._session.get(f"{self._api_url}/",
                                                 auth=self._auth,
                                                 headers=self._headers,
                                                 timeout=10) as status_response:
                        if status_response.status != 200:
                            _LOGGER.error("Failed to connect to Bettercap API: %s", status_response.status)
                            return False
        except aiohttp.ClientError as err:
            _LOGGER.error("Error connecting to Bettercap: %s", err)
            return False

        # Enable the appropriate modules based on configuration
        # await self._enable_modules()

        if not aiooui.is_loaded():
            await aiooui.async_load()

        if self._hass.state == CoreState.running:
            await self._async_start_scanner()
        else:
            self._entry.async_on_unload(
                self._hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STARTED, self._async_start_scanner))
        return True

    async def _async_start_scanner(self, _=None) -> None:
        """Start the scanner."""
        self._unsub_interval_scan = async_track_time_interval(
            self._hass,
            self._async_scan_devices,
            self._scan_interval,
        )


    async def _enable_modules(self) -> None:
        """Enable the appropriate Bettercap modules based on configuration."""
        # Define which modules to enable based on config
        modules_to_enable = []

        if self._config.get(CONF_ENABLE_ZEROGOD, False):
            modules_to_enable.append(BETTERCAP_ZEROGOD_DISCOVERY_ON)

        if self._config.get(CONF_ENABLE_NET_PROBE, True):
            modules_to_enable.append(BETTERCAP_NET_PROBE_ON)

        if self._config.get(CONF_ENABLE_NET_RECON, False):
            modules_to_enable.append(BETTERCAP_NET_RECON_ON)
            modules_to_enable.append(BETTERCAP_NET_SHOW_META_ON)

        if self._config.get(CONF_ENABLE_NET_SNIFF, False):
            modules_to_enable.append(BETTERCAP_NET_SNIFF_ON)

        # Enable each module
        for cmd in modules_to_enable:
            try:
                _LOGGER.debug("Sending Bettercap command: %s", cmd)
                cmd_data = {"cmd": cmd}
                async with self._session.post(f"{self._api_url}/session",
                                              auth=self._auth,
                                              headers=self._headers,
                                              json=cmd_data,
                                              timeout=10) as response:
                    if response.status not in (200, 204):
                        _LOGGER.warning("Failed to execute command %s: %s", cmd, response.status)
                    else:
                        _LOGGER.info("Successfully executed command: %s", cmd)
            except aiohttp.ClientError as err:
                _LOGGER.warning("Error executing command %s: %s", cmd, err)

    async def async_shutdown(self) -> None:
        """Stop the scanner and cleanup."""
        if self._unsub_interval_scan:
            self._unsub_interval_scan()
            self._unsub_interval_scan = None


        # Disable modules when shutting down
        modules_to_disable = []

        if self._config.get(CONF_ENABLE_NET_PROBE, True):
            modules_to_disable.append(BETTERCAP_NET_PROBE_OFF)

        if self._config.get(CONF_ENABLE_NET_SNIFF, False):
            modules_to_disable.append(BETTERCAP_NET_SNIFF_OFF)

        if self._config.get(CONF_ENABLE_NET_RECON, False):
            modules_to_disable.append(BETTERCAP_NET_RECON_OFF)

        if self._config.get(CONF_ENABLE_ZEROGOD, False):
            modules_to_disable.append(BETTERCAP_ZEROGOD_DISCOVERY_OFF)

        # Disable each module
        for cmd in modules_to_disable:
            try:
                cmd_data = {"cmd": cmd}
                async with self._session.post(f"{self._api_url}/session",
                                              auth=self._auth,
                                              headers=self._headers,
                                              json=cmd_data,
                                              timeout=10) as response:
                    if response.status not in (200, 204):
                        _LOGGER.warning("Failed to execute command %s: %s", cmd, response.status)
            except aiohttp.ClientError as err:
                _LOGGER.warning("Error executing command %s: %s", cmd, err)

    async def _async_fetch_device_data(self) -> dict[str, Any] | None:
        """Fetch device data from Bettercap API."""
        try:
            # Get the full session data which includes all devices
            devices = {}
            _LOGGER.debug("Fetching device data from Bettercap API: %s", self._api_url)
            async with self._session.get(f"{self._api_url}/session", auth=self._auth, headers=self._headers, timeout=10) as response:
                if response.status == 200:
                    session_data = await response.json()
                    _LOGGER.debug("Bettercap API response status: %s", response.status)

                    # Process LAN hosts
                    if "lan" in session_data and "hosts" in session_data["lan"]:
                        for host in session_data["lan"]["hosts"]:
                            mac = host.get("mac", "").lower()
                            if mac and mac != "--" and mac != "-":
                                # Get metadata
                                meta = host.get("meta", {})
                                if isinstance(meta, dict) and "values" in meta:
                                    meta = meta.get("values", {})
                                # Extract useful metadata for device identification
                                device_model = None
                                device_friendly_name = None

                                # Look for device model/type in metadata
                                if isinstance(meta, dict):
                                    # Check for Google Cast devices
                                    if "mdns:md" in meta:
                                        device_model = meta.get("mdns:md")
                                    if "mdns:fn" in meta:
                                        device_friendly_name = meta.get("mdns:fn")

                                    # Check for ESPHome devices
                                    if "mdns:friendly_name" in meta:
                                        device_friendly_name = meta.get("mdns:friendly_name")
                                    if "mdns:platform" in meta and "mdns:board" in meta:
                                        device_model = f"{meta.get('mdns:platform')} ({meta.get('mdns:board')})"

                                # Get hostname and remove any trailing dots
                                hostname = host.get("hostname", "")
                                while hostname and hostname.endswith("."):
                                    hostname = hostname[:-1]

                                # Create the device data dictionary with all metadata
                                device_data = {
                                    "name": hostname,
                                    "ip": host.get("ipv4", ""),
                                    "vendor": host.get("vendor", ""),
                                    "online": True,
                                    "last_seen": host.get("last_seen", ""),
                                    "first_seen": host.get("first_seen", ""),
                                    "meta": meta,
                                    "device_model": device_model,
                                    "device_friendly_name": device_friendly_name
                                }
                                devices[mac] = device_data
                                _LOGGER.debug("Found device from session/lan/hosts: %s (%s) - %s",
                                              device_data.get("name"), mac, device_data.get("ip"))

            return devices

        except aiohttp.ClientError as err:
            _LOGGER.error("Error fetching device data from Bettercap: %s", err)
            return None
        except Exception as e:
            _LOGGER.error("Unexpected error fetching device data: %s", e)
            return None

    async def _async_scan_devices(self, *_):
        """Scan for devices and update device trackers."""
        if self._scan_lock.locked():
            _LOGGER.debug("Scan already in progress, skipping")
            return

        now = dt_util.now()

        async with self._scan_lock:
            device_data = await self._async_fetch_device_data()
            if device_data:
                found_macs = await self._async_process_device_data(device_data)
                await self._async_process_device_offline(found_macs, now)



    async def _async_process_device_data(self, fetched_devices: dict[str, Any]) -> set[str]:
        """Process fetched device data and update entities."""
        found_macs = set()

        _LOGGER.debug("Processing %d devices from Bettercap", len(fetched_devices))

        for mac_address, raw_device_data in fetched_devices.items():
            formatted_mac = format_mac(mac_address)
            if formatted_mac is None: # Invalid MAC Address
                _LOGGER.warning("Invalid MAC address found: %s", mac_address)
                continue

            name = raw_device_data.get("name", "")
            ip = raw_device_data.get("ip", "")
            vendor = raw_device_data.get("vendor", "")

            _LOGGER.debug("Processing device: MAC=%s, Name=%s, IP=%s, Vendor=%s", formatted_mac, name, ip, vendor)

            # Check if this is a new device
            is_new_device = formatted_mac not in self._devices

            if is_new_device:
                # Create a new device
                device = NetworkDevice(formatted_mac)
                self._devices[formatted_mac] = device

                # Store the raw data
                device.raw_data = raw_device_data

                # Log that we've discovered a new device
                _LOGGER.info("Discovered new device: %s (%s)",
                            name or f"Unknown {formatted_mac[-5:]}", formatted_mac)

                # Signal new device discovery
                async_dispatcher_send(
                    self._hass,
                    signal_device_new(self._entry.entry_id),
                    formatted_mac,
                    raw_device_data
                )
            else:
                # Get the device from our devices dictionary
                device = self._devices[formatted_mac]

                # Store the raw data
                device.raw_data = raw_device_data

                # Signal device update
                async_dispatcher_send(
                    self._hass,
                    signal_device_updated(self._entry.entry_id),
                    formatted_mac,
                    raw_device_data
                )

            # Update timestamps
            device.last_seen = dt_util.now()

            # Explicitly mark as online and reset offline tracking
            device.online = True
            device.first_offline = None

            # Add to found MACs
            found_macs.add(formatted_mac)

        return found_macs




    async def _async_process_device_offline(self, found_macs: set[str], now: datetime):
        """Process devices that are offline or missing in the current scan."""
        devices_to_remove = []
        for mac_address, device in self._devices.items():
            if mac_address not in found_macs:      # Device not in current scan
                if device.online:                  # Device was online before, now missing from scan
                    if not device.first_offline:
                        device.first_offline = now # Mark first offline time

                    # Simply mark as offline immediately
                    device.online = False
                    _LOGGER.debug("Device %s marked offline", mac_address)

                    # Signal device offline
                    async_dispatcher_send(
                        self._hass,
                        signal_device_offline(self._entry.entry_id),
                        mac_address
                    )

        for mac_address in devices_to_remove:
            self._devices.pop(mac_address) # Remove devices offline for extended period
