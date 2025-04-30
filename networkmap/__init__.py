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
    DEVICE_SCAN_INTERVAL,
    MIN_SCAN_INTERVAL,
    CONF_API_KEY,
    BETTERCAP_API_URL,
    CONF_ENABLE_NET_PROBE,
    CONF_ENABLE_NET_SNIFF,
    CONF_ENABLE_ARP_SPOOF,
    CONF_ENABLE_TICKER,
    CONF_ENABLE_NET_RECON,
    CONF_ENABLE_ZEROGOD,
    BETTERCAP_NET_PROBE_ON,
    BETTERCAP_NET_PROBE_OFF,
    BETTERCAP_NET_SNIFF_ON,
    BETTERCAP_NET_SNIFF_OFF,
    BETTERCAP_ARP_SPOOF_ON,
    BETTERCAP_ARP_SPOOF_OFF,
    BETTERCAP_TICKER_ON,
    BETTERCAP_TICKER_OFF,
    BETTERCAP_NET_RECON_ON,
    BETTERCAP_NET_RECON_OFF,
    BETTERCAP_NET_SHOW_META_ON,
    BETTERCAP_ZEROGOD_DISCOVERY_ON,
    BETTERCAP_ZEROGOD_DISCOVERY_OFF,
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


def signal_device_update(mac_address) -> str:
    """Signal specific per networkmap entry to signal updates in device."""
    return f"{DOMAIN}-device-update-{mac_address}"


class NetworkDevice:
    """Class for keeping track of a network device."""

    def __init__(self, mac_address: str):
        """Initialize the device."""
        self.mac_address = mac_address
        self.name: str | None = None
        self.ip: str | None = None
        self.vendor: str | None = None
        self.vendor_class: str | None = None
        self.type: str | None = None
        self.os_type: str | None = None
        self.online: bool = False
        self._2g: bool = False
        self._5g: bool = False
        self.rssi: str | None = None
        self.cur_tx: str | None = None
        self.cur_rx: str | None = None
        self.connection_time: str | None = None
        self.first_seen: str | None = None
        self.last_seen: str | None = None
        self.is_wireless: bool = False
        self.last_update: datetime | None = None
        self.first_offline: datetime | None = None

    @property
    def is_2g(self) -> bool:
        """Return if device is on 2.4 GHz."""
        return self._2g

    @property
    def is_5g(self) -> bool:
        """Return if device is on 5 GHz."""
        return self._5g

    def update_from_data(self, data: dict[str, Any]):
        """Update device data from fetched data."""
        name = data.get("name") or data.get("nickName") or data.get("hostname")
        if name and name != self.name:
            self.name = name

        ip = data.get("ip") or data.get("ipv4")
        if ip and ip != self.ip:
            self.ip = ip

        vendor = data.get("vendor")
        if vendor and vendor != self.vendor:
            self.vendor = vendor

        vendor_class = data.get("vendorclass")
        if vendor_class and vendor_class != self.vendor_class:
            self.vendor_class = vendor_class

        type_ = data.get("type") or data.get("device_type")
        if type_ and type_ != self.type:
            self.type = type_

        os_type = data.get("os_type")
        if os_type and os_type != self.os_type:
            self.os_type = os_type

        online = data.get("online", False)
        if online is not None and online != self.online:
            self.online = online

        _2g = data.get("2G", False)
        if _2g is not None and _2g != self._2g:
            self._2g = _2g

        _5g = data.get("5G", False)
        if _5g is not None and _5g != self._5g:
            self._5g = _5g

        rssi = data.get("rssi")
        if rssi and rssi != self.rssi:
            self.rssi = rssi

        cur_tx = data.get("curTx")
        if cur_tx and cur_tx != self.cur_tx:
            self.cur_tx = cur_tx

        cur_rx = data.get("curRx")
        if cur_rx and cur_rx != self.cur_rx:
            self.cur_rx = cur_rx

        connection_time = data.get("wlConnectTime") or data.get("connection_time")
        if connection_time and connection_time != self.connection_time:
            self.connection_time = connection_time
            
        first_seen = data.get("first_seen")
        if first_seen and first_seen != self.first_seen:
            self.first_seen = first_seen
            
        last_seen = data.get("last_seen")
        if last_seen and last_seen != self.last_seen:
            self.last_seen = last_seen
            
        is_wireless = data.get("is_wireless", False)
        if is_wireless is not None and is_wireless != self.is_wireless:
            self.is_wireless = is_wireless

        self.last_update = dt_util.now()


class NetworkDeviceScanner:
    """Scanner for network devices using Bettercap API."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the scanner."""
        self._hass = hass
        self._entry = entry
        self._config = entry.data
        self._scan_interval = timedelta(
            seconds=entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
        )
        self._devices: dict[str, NetworkDevice] = {}
        self._scan_lock = asyncio.Lock()
        self._session = async_get_clientsession(hass)
        self._api_url = BETTERCAP_API_URL.format(
            host=self._config[CONF_HOST], 
            port=self._config[CONF_PORT]
        )
        self._auth = aiohttp.BasicAuth(
            self._config[CONF_USERNAME], 
            self._config[CONF_PASSWORD]
        )
        self._headers = {"X-API-KEY": self._config.get(CONF_API_KEY, "")} if CONF_API_KEY in self._config else {}
        self._unsub_interval_scan = None
        self._finished_first_scan = False
        self._known_mac_addresses: dict[str, str] = {}

    async def async_setup(self) -> bool:
        """Set up the scanner and start periodic scanning."""
        # Test connection to Bettercap
        try:
            # First try to access the session endpoint
            async with self._session.get(
                f"{self._api_url}/session", 
                auth=self._auth,
                headers=self._headers,
                timeout=10
            ) as response:
                if response.status != 200:
                    _LOGGER.error("Failed to connect to Bettercap session API: %s", response.status)
                    # Try the status endpoint as fallback
                    async with self._session.get(
                        f"{self._api_url}/", 
                        auth=self._auth,
                        headers=self._headers,
                        timeout=10
                    ) as status_response:
                        if status_response.status != 200:
                            _LOGGER.error("Failed to connect to Bettercap API: %s", status_response.status)
                            return False
        except aiohttp.ClientError as err:
            _LOGGER.error("Error connecting to Bettercap: %s", err)
            return False
            
        # Enable the appropriate modules based on configuration
        await self._enable_modules()

        if not aiooui.is_loaded():
            await aiooui.async_load()

        registry = er.async_get(self._hass)
        self._known_mac_addresses = {
            entry.unique_id: entry.original_name
            for entry in registry.entities.get_entries_for_config_entry_id(
                self._entry.entry_id
            )
        }

        if self._hass.state == CoreState.running:
            await self._async_start_scanner()
        else:
            self._entry.async_on_unload(
                self._hass.bus.async_listen_once(
                    EVENT_HOMEASSISTANT_STARTED, self._async_start_scanner
                )
            )
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
        
        if self._config.get(CONF_ENABLE_NET_PROBE, True):
            modules_to_enable.append(BETTERCAP_NET_PROBE_ON)
        
        if self._config.get(CONF_ENABLE_NET_SNIFF, False):
            modules_to_enable.append(BETTERCAP_NET_SNIFF_ON)
            
        if self._config.get(CONF_ENABLE_ARP_SPOOF, False):
            modules_to_enable.append(BETTERCAP_ARP_SPOOF_ON)
            
        if self._config.get(CONF_ENABLE_TICKER, False):
            modules_to_enable.append(BETTERCAP_TICKER_ON)
            
        if self._config.get(CONF_ENABLE_NET_RECON, False):
            modules_to_enable.append(BETTERCAP_NET_RECON_ON)
            modules_to_enable.append(BETTERCAP_NET_SHOW_META_ON)
            
        if self._config.get(CONF_ENABLE_ZEROGOD, False):
            modules_to_enable.append(BETTERCAP_ZEROGOD_DISCOVERY_ON)
        
        # Enable each module
        for cmd in modules_to_enable:
            try:
                _LOGGER.debug("Sending Bettercap command: %s", cmd)
                cmd_data = {"cmd": cmd}
                async with self._session.post(
                    f"{self._api_url}/session",
                    auth=self._auth,
                    headers=self._headers,
                    json=cmd_data,
                    timeout=10
                ) as response:
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
            
        if self._config.get(CONF_ENABLE_ARP_SPOOF, False):
            modules_to_disable.append(BETTERCAP_ARP_SPOOF_OFF)
            
        if self._config.get(CONF_ENABLE_TICKER, False):
            modules_to_disable.append(BETTERCAP_TICKER_OFF)
            
        if self._config.get(CONF_ENABLE_NET_RECON, False):
            modules_to_disable.append(BETTERCAP_NET_RECON_OFF)
            
        if self._config.get(CONF_ENABLE_ZEROGOD, False):
            modules_to_disable.append(BETTERCAP_ZEROGOD_DISCOVERY_OFF)
        
        # Disable each module
        for cmd in modules_to_disable:
            try:
                cmd_data = {"cmd": cmd}
                async with self._session.post(
                    f"{self._api_url}/session",
                    auth=self._auth,
                    headers=self._headers,
                    json=cmd_data,
                    timeout=10
                ) as response:
                    if response.status not in (200, 204):
                        _LOGGER.warning("Failed to execute command %s: %s", cmd, response.status)
            except aiohttp.ClientError as err:
                _LOGGER.warning("Error executing command %s: %s", cmd, err)

    async def _async_fetch_device_data(self) -> dict[str, Any] | None:
        """Fetch device data from Bettercap API."""
        try:
            # Get the full session data which includes all devices
            devices = {}
            async with self._session.get(
                f"{self._api_url}/session", 
                auth=self._auth,
                headers=self._headers,
                timeout=10
            ) as response:
                if response.status == 200:
                    session_data = await response.json()
                    
                    # Process LAN hosts
                    if "lan" in session_data and "hosts" in session_data["lan"]:
                        for host in session_data["lan"]["hosts"]:
                            mac = host.get("mac", "").lower()
                            if mac and mac != "--" and mac != "-":
                                # Get metadata
                                meta = host.get("meta", {})
                                if isinstance(meta, dict) and "values" in meta:
                                    meta = meta.get("values", {})
                                
                                # Determine if device is wireless
                                is_wireless = False
                                if "wireless" in meta or "wifi" in meta:
                                    is_wireless = True
                                
                                # Extract traffic data if available
                                traffic_data = {}
                                if "packets" in session_data and "Traffic" in session_data["packets"]:
                                    ip = host.get("ipv4")
                                    if ip and ip in session_data["packets"]["Traffic"]:
                                        traffic_data = session_data["packets"]["Traffic"][ip]
                                
                                # Extract signal strength if available
                                rssi = None
                                if "rssi" in meta:
                                    rssi = str(meta.get("rssi"))
                                
                                # Determine frequency band if available
                                is_2g = False
                                is_5g = False
                                if "frequency" in meta:
                                    freq = meta.get("frequency", 0)
                                    if isinstance(freq, (int, float)):
                                        is_2g = freq < 5000
                                        is_5g = freq >= 5000
                                
                                devices[mac] = {
                                    "name": host.get("hostname", ""),
                                    "ip": host.get("ipv4", ""),
                                    "vendor": host.get("vendor", ""),
                                    "vendorclass": host.get("vendor", ""),
                                    "online": True,
                                    "is_wireless": is_wireless,
                                    "rssi": rssi,
                                    "last_seen": host.get("last_seen", ""),
                                    "first_seen": host.get("first_seen", ""),
                                    "2G": is_2g,
                                    "5G": is_5g,
                                    "curTx": str(traffic_data.get("Sent", 0)) if traffic_data else None,
                                    "curRx": str(traffic_data.get("Received", 0)) if traffic_data else None,
                                    "wlConnectTime": host.get("first_seen", ""),
                                    "meta": meta
                                }
            
            # If no devices found in session data, try the dedicated LAN endpoint
            if not devices:
                await self._fetch_lan_devices(devices)
            
            return devices
            
        except aiohttp.ClientError as err:
            _LOGGER.error("Error fetching device data from Bettercap: %s", err)
            return None
        except Exception as e:
            _LOGGER.error("Unexpected error fetching device data: %s", e)
            return None
    
    async def _fetch_lan_devices(self, devices: dict) -> None:
        """Fetch LAN devices from dedicated endpoint."""
        try:
            # Try the /session/lan endpoint
            async with self._session.get(
                f"{self._api_url}/session/lan", 
                auth=self._auth,
                headers=self._headers,
                timeout=10
            ) as response:
                if response.status == 200:
                    lan_data = await response.json()
                    for host in lan_data.get("hosts", []):
                        mac = host.get("mac", "").lower()
                        if mac and mac != "--" and mac != "-":
                            meta = host.get("meta", {})
                            if isinstance(meta, dict) and "values" in meta:
                                meta = meta.get("values", {})
                                
                            devices[mac] = {
                                "name": host.get("hostname", ""),
                                "ip": host.get("ipv4", ""),
                                "vendor": host.get("vendor", ""),
                                "vendorclass": host.get("vendor", ""),
                                "online": True,
                                "is_wireless": False,
                                "last_seen": host.get("last_seen", ""),
                                "first_seen": host.get("first_seen", ""),
                                "meta": meta
                            }
        except aiohttp.ClientError as err:
            _LOGGER.error("Error fetching LAN devices: %s", err)

    async def _async_scan_devices(self, *_):
        """Scan for devices and update device trackers."""
        if self._scan_lock.locked():
            _LOGGER.debug("Scan already in progress, skipping")
            return

        async with self._scan_lock:
            device_data = await self._async_fetch_device_data()
            if device_data:
                await self._async_process_device_data(device_data)

        if not self._finished_first_scan:
            self._finished_first_scan = True
            await self._async_mark_missing_devices_as_not_home()

    async def _async_process_device_data(self, fetched_devices: dict[str, Any]) -> None:
        """Process fetched device data and update entities."""
        current_devices = {}
        now = dt_util.now()

        for mac_address, raw_device_data in fetched_devices.items():
            formatted_mac = format_mac(mac_address)
            if formatted_mac is None:  # Invalid MAC Address
                _LOGGER.warning("Invalid MAC address found: %s", mac_address)
                continue

            if (
                self._entry.entry_id
                != self._known_mac_addresses.get(
                    formatted_mac, self._entry.entry_id
                )  # Using entity registry to track ownership, fallback to entry_id for new entities.
            ):
                continue  # Device is not managed by this config entry

            device = self._devices.get(formatted_mac)
            if device is None:
                # New device found, create a NetworkDevice instance but don't add it to _devices yet
                device = NetworkDevice(formatted_mac)
                device.update_from_data(raw_device_data)

                # Check if the device is online and has enough information
                if device.online and device.name and device.ip:
                    self._devices[formatted_mac] = (
                        device  # Add to _devices only if it's online and has basic info
                    )
                    async_dispatcher_send(
                        self._hass,
                        f"{DOMAIN}_device_new_{self._entry.entry_id}",
                        formatted_mac,
                    )  # Signal new device
            else:
                # Existing device, update its information
                device.update_from_data(raw_device_data)

            current_devices[formatted_mac] = device
            # Make sure the device exists in _devices before sending update
            if formatted_mac in self._devices:
                async_dispatcher_send(
                    self._hass, signal_device_update(formatted_mac), device.online
                )  # Signal device update

        await self._async_process_device_offline(current_devices, now)

    async def _async_mark_missing_devices_as_not_home(self):
        """Mark devices not found in the first scan as not_home."""
        now = dt_util.now()
        for mac_address, original_name in self._known_mac_addresses.items():
            if mac_address in self._devices:  # Already tracked in first scan
                continue
            device = NetworkDevice(mac_address)
            device.name = original_name
            device.last_update = now
            device.first_offline = now  # Mark first offline time
            self._devices[mac_address] = device
            async_dispatcher_send(
                self._hass,
                f"{DOMAIN}_device_missing_{self._entry.entry_id}",
                mac_address,
            )  # Signal device missing

    async def _async_process_device_offline(
        self, current_devices: dict[str, NetworkDevice], now: datetime
    ):
        """Process devices that are offline or missing in the current scan."""
        devices_to_remove = []
        for mac_address, device in self._devices.items():
            if mac_address not in current_devices:  # Device not in current scan
                if device.online:  # Device was online before, now offline
                    if not device.first_offline:
                        device.first_offline = now  # Mark first offline time
                    elif (
                        device.first_offline
                        + timedelta(seconds=DEVICE_SCAN_INTERVAL * 3)
                        < now
                    ):  # Consider offline after 3 missed scans (adjust as needed)
                        device.online = False
                        # Make sure the device exists in _devices before sending update
                        if mac_address in self._devices:
                            async_dispatcher_send(
                                self._hass, signal_device_update(mac_address), False
                            )  # Signal offline
                elif (
                    not device.online
                    and device.first_offline
                    and device.first_offline
                    + timedelta(seconds=DEVICE_SCAN_INTERVAL * 6)
                    < now
                ):  # Remove device after longer offline period (adjust as needed)
                    devices_to_remove.append(
                        mac_address
                    )  # Mark for removal if offline for longer duration

        for mac_address in devices_to_remove:
            self._devices.pop(mac_address)  # Remove devices offline for extended period


