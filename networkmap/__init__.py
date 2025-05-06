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
    CONF_ENABLE_NET_RECON,
    CONF_ENABLE_ZEROGOD,
    BETTERCAP_NET_PROBE_ON,
    BETTERCAP_NET_PROBE_OFF,
    BETTERCAP_NET_SNIFF_ON,
    BETTERCAP_NET_SNIFF_OFF,
    BETTERCAP_ARP_SPOOF_ON,
    BETTERCAP_ARP_SPOOF_OFF,
    BETTERCAP_NET_RECON_ON,
    BETTERCAP_NET_RECON_OFF,
    BETTERCAP_NET_SHOW_META_ON,
    BETTERCAP_ZEROGOD_DISCOVERY_ON,
    BETTERCAP_ZEROGOD_DISCOVERY_OFF,
    BETTERCAP_NET_PROBE_TARGET,
    BETTERCAP_ARP_PROBE_TARGET,
    BETTERCAP_PING_TARGET,
    VERIFICATION_ATTEMPTS,
    VERIFICATION_DELAY,
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
        self.first_seen: str | None = None
        self.last_seen: str | None = None
        self.is_wireless: bool = False
        self.first_offline: datetime | None = None
        self.verification_attempts: int = 0
        self.reliability_score: int = 100 # Start with perfect score
        self.offline_frequency: int = 0   # Track how often device goes offline

        # Entity tracking
        self.entity_created: bool = False  # Whether an entity has been created for this device
        self.first_discovered: datetime = dt_util.now()  # When the device was first discovered
        self.consecutive_scans: int = 0  # Number of consecutive scans this device has been seen in

        # Enhanced device identification
        self.device_model: str | None = None
        self.device_friendly_name: str | None = None
        self.device_type: str | None = None
        self.mdns_services: list[str] = []

        # Store all metadata
        self.meta: dict[str, Any] = {}

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
            # Remove any trailing dots from hostname
            while name and name.endswith("."):
                name = name[:-1]
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

        first_seen = data.get("first_seen")
        if first_seen and first_seen != self.first_seen:
            self.first_seen = first_seen

        last_seen = data.get("last_seen")
        if last_seen and last_seen != self.last_seen:
            self.last_seen = last_seen

        is_wireless = data.get("is_wireless", False)
        if is_wireless is not None and is_wireless != self.is_wireless:
            self.is_wireless = is_wireless

        # Update enhanced device identification
        device_model = data.get("device_model")
        if device_model and device_model != self.device_model:
            self.device_model = device_model

        device_friendly_name = data.get("device_friendly_name")
        if device_friendly_name and device_friendly_name != self.device_friendly_name:
            self.device_friendly_name = device_friendly_name

        device_type = data.get("device_type")
        if device_type and device_type != self.device_type:
            self.device_type = device_type

        # Store all metadata
        if "meta" in data and isinstance(data["meta"], dict):
            self.meta = data["meta"]

            # Extract mDNS services from metadata
            services = []
            for key in self.meta.keys():
                if key.startswith("mdns:_") and key.endswith(":name"):
                    service_name = key.split(":")[1]
                    if service_name not in services:
                        services.append(service_name)

            if services:
                self.mdns_services = services


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
        self._finished_first_scan = False
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
        await self._enable_modules()

        if not aiooui.is_loaded():
            await aiooui.async_load()

        # Get entity registry to find existing device_tracker entities
        registry = er.async_get(self._hass)

        # Get entities for this config entry
        self._known_mac_addresses = {
            entry.unique_id: entry.original_name
            for entry in registry.entities.get_entries_for_config_entry_id(self._entry.entry_id)}

        # Find all device_tracker entities in the system to check for MAC address and hostname matches
        self._existing_mac_entities = {}
        self._existing_hostname_entities = {}

        # First pass: collect all device_tracker entities
        all_device_trackers = {}
        for entity_id, entity in registry.entities.items():
            if entity.domain == "device_tracker":
                all_device_trackers[entity_id] = {
                    "entity_id": entity_id, "config_entry_id": entity.config_entry_id, "disabled": entity.disabled,
                    "unique_id": entity.unique_id, "original_name": entity.original_name}

        # Second pass: check for MAC addresses in unique_ids and attributes
        for entity_id, entity_data in all_device_trackers.items():
            # Check if unique_id contains a MAC address
            if entity_data["unique_id"] and ":" in entity_data["unique_id"]:
                mac_parts = entity_data["unique_id"].split("_")
                for part in mac_parts:
                    if ":" in part and len(part) >= 17: # MAC addresses are at least 17 chars with colons
                        self._existing_mac_entities[format_mac(part)] = entity_data

            # Store by hostname (entity ID without domain) for later matching
            hostname = entity_id.split(".", 1)[1]
            self._existing_hostname_entities[hostname.lower()] = entity_data

            # Also store by original name if available
            if entity_data["original_name"]:
                self._existing_hostname_entities[entity_data["original_name"].lower()] = entity_data

        # Third pass: check entity attributes for MAC addresses
        for entity_id in all_device_trackers:
            try:
                state = self._hass.states.get(entity_id)
                if state and state.attributes:
                    # Check for mac_address attribute
                    if "mac_address" in state.attributes:
                        mac = format_mac(state.attributes["mac_address"])
                        if mac:
                            self._existing_mac_entities[mac] = all_device_trackers[entity_id]

                    # Check for MAC in other common attribute names
                    for attr_name in ["mac", "MAC", "hw_addr", "hardware_address"]:
                        if attr_name in state.attributes:
                            mac = format_mac(state.attributes[attr_name])
                            if mac:
                                self._existing_mac_entities[mac] = all_device_trackers[entity_id]

                    # Store hostname from attributes for matching
                    for attr_name in ["hostname", "host_name", "name"]:
                        if attr_name in state.attributes and state.attributes[attr_name]:
                            hostname = state.attributes[attr_name].lower()
                            self._existing_hostname_entities[hostname] = all_device_trackers[entity_id]
            except Exception as ex:
                _LOGGER.warning("Error checking attributes for %s: %s", entity_id, ex)

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

        # Also start a periodic reverification of offline devices
        self._unsub_reverify = async_track_time_interval(
            self._hass,
            self._async_scheduled_reverification,
            timedelta(minutes=15),                        # Try to rediscover offline devices every 15 minutes
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

        if hasattr(self, '_unsub_reverify') and self._unsub_reverify:
            self._unsub_reverify()
            self._unsub_reverify = None

        # Disable modules when shutting down
        modules_to_disable = []

        if self._config.get(CONF_ENABLE_NET_PROBE, True):
            modules_to_disable.append(BETTERCAP_NET_PROBE_OFF)

        if self._config.get(CONF_ENABLE_NET_SNIFF, False):
            modules_to_disable.append(BETTERCAP_NET_SNIFF_OFF)

        if self._config.get(CONF_ENABLE_ARP_SPOOF, False):
            modules_to_disable.append(BETTERCAP_ARP_SPOOF_OFF)

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

                                # Extract useful metadata for device identification
                                device_model = None
                                device_friendly_name = None
                                device_type = None

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

                                    # Determine device type based on services
                                    if any(k.startswith("mdns:_googlecast") for k in meta.keys()):
                                        device_type = "cast"
                                    elif any(k.startswith("mdns:_esphomelib") for k in meta.keys()):
                                        device_type = "esphome"
                                    elif any(k.startswith("mdns:_hap") for k in meta.keys()):
                                        device_type = "homekit"
                                    elif any(k.startswith("mdns:_androidtvremote") for k in meta.keys()):
                                        device_type = "android_tv"

                                # Get hostname and remove any trailing dots
                                hostname = host.get("hostname", "")
                                while hostname and hostname.endswith("."):
                                    hostname = hostname[:-1]

                                # Create the device data dictionary with all metadata
                                device_data = {
                                    "name": hostname, "ip": host.get("ipv4", ""), "vendor": host.get(
                                        "vendor", ""), "vendorclass": host.get("vendor", ""), "online": True, "is_wireless": is_wireless, "rssi": rssi, "last_seen": host.get(
                                            "last_seen", ""), "first_seen": host.get("first_seen", ""), "2G": is_2g, "5G": is_5g, "curTx": str(
                                                traffic_data.get("Sent", 0)) if traffic_data else None, "curRx": str(
                                                    traffic_data.get("Received", 0)) if traffic_data else None, "meta": meta,
                                    "device_model": device_model, "device_friendly_name": device_friendly_name, "device_type": device_type}
                                devices[mac] = device_data
                                _LOGGER.debug("Found device from session/lan/hosts: %s (%s) - %s",
                                              device_data.get("name"), mac, device_data.get("ip"))

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
            async with self._session.get(f"{self._api_url}/session/lan",
                                         auth=self._auth,
                                         headers=self._headers,
                                         timeout=10) as response:
                if response.status == 200:
                    lan_data = await response.json()
                    _LOGGER.debug("Bettercap LAN API response: %s", lan_data)
                    for host in lan_data.get("hosts", []):
                        mac = host.get("mac", "").lower()
                        if mac and mac != "--" and mac != "-":
                            meta = host.get("meta", {})
                            if isinstance(meta, dict) and "values" in meta:
                                meta = meta.get("values", {})

                            # Extract useful metadata for device identification
                            device_model = None
                            device_friendly_name = None
                            device_type = None

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

                                # Determine device type based on services
                                if any(k.startswith("mdns:_googlecast") for k in meta.keys()):
                                    device_type = "cast"
                                elif any(k.startswith("mdns:_esphomelib") for k in meta.keys()):
                                    device_type = "esphome"
                                elif any(k.startswith("mdns:_hap") for k in meta.keys()):
                                    device_type = "homekit"
                                elif any(k.startswith("mdns:_androidtvremote") for k in meta.keys()):
                                    device_type = "android_tv"

                            # Get hostname and remove any trailing dots
                            hostname = host.get("hostname", "")
                            while hostname and hostname.endswith("."):
                                hostname = hostname[:-1]

                            device_data = {
                                "name": hostname, "ip": host.get("ipv4", ""), "vendor": host.get(
                                    "vendor", ""), "vendorclass": host.get("vendor", ""), "online": True, "is_wireless": False, "last_seen": host.get(
                                        "last_seen", ""), "first_seen": host.get("first_seen", ""), "meta": meta,
                                "device_model": device_model, "device_friendly_name": device_friendly_name, "device_type": device_type}
                            devices[mac] = device_data
                            _LOGGER.debug("Found device from /session/lan endpoint: %s (%s) - %s",
                                          device_data.get("name"), mac, device_data.get("ip"))
        except aiohttp.ClientError as err:
            _LOGGER.error("Error fetching LAN devices: %s", err)

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

        if not self._finished_first_scan:
            self._finished_first_scan = True
            await self._async_mark_missing_devices_as_not_home()

    async def _verify_device_connectivity(self, device: NetworkDevice) -> None:
        """Actively verify if a device is still connected to the network using socket connection."""
        if not device.ip:
            _LOGGER.debug("Cannot verify device %s: no IP address", device.mac_address)
            return

        _LOGGER.info("Actively verifying connectivity for %s (%s) - attempt %d/%d", device.name, device.ip, device.verification_attempts, VERIFICATION_ATTEMPTS)

        try:
            # Use Python's socket module for TCP and ICMP ping
            import socket
            from concurrent.futures import ThreadPoolExecutor

            # Define a function to check TCP connectivity
            def check_tcp_port(ip, port, timeout=1):
                """Check if a TCP port is open."""
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    return result == 0
                except Exception:
                    return False

            # Define a function to check ICMP connectivity (ping)
            def check_icmp(ip, timeout=2):
                """Check if a host responds to ICMP echo (ping)."""
                try:
                    # Create a raw socket for ICMP
                    if hasattr(socket, "IPPROTO_ICMP"):
                        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                        sock.settimeout(timeout)
                        sock.connect((ip, 0))
                        sock.send(b'\x08\x00\x00\x00\x00\x01\x00\x01')  # ICMP echo request
                        sock.recv(1024)
                        sock.close()
                        return True
                except (socket.error, OSError, PermissionError):
                    # ICMP requires root privileges on most systems
                    # If it fails, we'll fall back to TCP checks
                    return False

                return False

            # Run the connectivity checks in a thread pool to avoid blocking
            with ThreadPoolExecutor(max_workers=2) as executor:
                # Try common ports: 80 (HTTP), 443 (HTTPS), 22 (SSH), 7 (Echo)
                common_ports = [80, 443, 22, 7]
                tcp_futures = [executor.submit(check_tcp_port, device.ip, port) for port in common_ports]

                # Try ICMP ping if possible
                icmp_future = executor.submit(check_icmp, device.ip)

                # Check if any of the connectivity tests succeeded
                is_reachable = icmp_future.result()
                if not is_reachable:
                    for future in tcp_futures:
                        if future.result():
                            is_reachable = True
                            break

            if is_reachable:
                _LOGGER.debug("Device %s is reachable", device.name)
                device.online = True
                device.first_offline = None
                device.verification_attempts = 0
                # Improve reliability score
                device.reliability_score = min(100, device.reliability_score + 2)

                # We still need to update device data from Bettercap
                device_data = await self._async_fetch_device_data()
                if device_data and device.mac_address in device_data:
                    device.update_from_data(device_data[device.mac_address])

                # Signal device update
                async_dispatcher_send(self._hass, signal_device_update(device.mac_address), True)
                return
            else:
                _LOGGER.debug("Device %s is not reachable", device.name)
        except Exception as ex:
            _LOGGER.warning("Error during connectivity verification for %s: %s", device.name, ex)

        # If we get here, verification failed
        _LOGGER.debug("Device %s failed verification attempt %d", device.name, device.verification_attempts)

    async def _async_scheduled_reverification(self, *_):
        """Periodically try to rediscover offline devices."""
        _LOGGER.debug("Running scheduled reverification of offline devices")
        for mac_address, device in self._devices.items():
            if not device.online and device.ip:
                # Try to rediscover the device
                _LOGGER.debug("Attempting to rediscover offline device: %s", device.name)
                await self._verify_device_connectivity(device)

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
            if formatted_mac not in self._devices:
                # Create a new device
                device = NetworkDevice(formatted_mac)
                self._devices[formatted_mac] = device

                # Update device data
                device.update_from_data(raw_device_data)

                # Log that we've discovered a new device but won't create an entity yet
                _LOGGER.info("Discovered new device: %s (%s) - deferring entity creation",
                            name or f"Unknown {formatted_mac[-4:]}", formatted_mac)
            else:
                # Get the device from our devices dictionary
                device = self._devices[formatted_mac]

                # Update device data
                device.update_from_data(raw_device_data)

                # Increment consecutive scans counter
                device.consecutive_scans += 1

            # Explicitly mark as online and reset offline tracking
            device.online = True
            device.first_offline = None
            device.verification_attempts = 0

            # Signal device update (online) only if entity already exists
            if device.entity_created:
                async_dispatcher_send(self._hass, signal_device_update(formatted_mac), True)

            # Add to found MACs
            found_macs.add(formatted_mac)

            # Try to update existing entity if better info is available
            await self._try_update_existing_entity(formatted_mac, raw_device_data)

        # Process pending devices that might be ready for entity creation
        await self._process_pending_devices()

        return found_macs

    def _is_device_ready_for_entity(self, device: NetworkDevice) -> bool:
        """Determine if a device has sufficient information to create an entity.

        Evaluates device readiness based on data richness and consistency over time.
        """
        now = dt_util.now()

        # Always create entities for known MACs from our integration
        if device.mac_address in self._known_mac_addresses:
            _LOGGER.debug("Device %s is ready: known MAC from integration", device.mac_address)
            return True

        # Check data richness criteria
        better_name, is_significant = self._generate_better_name(device)
        has_good_name = is_significant and better_name and not better_name.startswith("Device ")
        has_vendor = bool(device.vendor and len(device.vendor) > 1)
        has_friendly_name = bool(device.device_friendly_name and len(device.device_friendly_name) > 1)
        has_device_model = bool(device.device_model and len(device.device_model) > 1)
        has_device_type = bool(device.device_type)
        has_mdns_services = len(device.mdns_services) > 0

        # Calculate a data richness score (0-10)
        data_richness = 0
        if has_good_name:
            data_richness += 3
        if has_vendor:
            data_richness += 2
        if has_friendly_name:
            data_richness += 2
        if has_device_model:
            data_richness += 1
        if has_device_type:
            data_richness += 1
        if has_mdns_services:
            data_richness += 1

        # Check time/consistency criteria
        time_since_discovery = (now - device.first_discovered).total_seconds()
        scan_interval_seconds = self._scan_interval.total_seconds()

        # Device has been seen in multiple consecutive scans
        consistent_presence = device.consecutive_scans >= 3

        # Device has been around for a while (at least 2 scan intervals)
        sufficient_time = time_since_discovery > (scan_interval_seconds * 2)

        # Fallback timeout (create entity after 5 scan intervals even with suboptimal data)
        fallback_timeout = time_since_discovery > (scan_interval_seconds * 5)

        # Decision logic
        if fallback_timeout and has_good_name:
            # After fallback timeout, create entity if we at least have a good name
            _LOGGER.debug("Device %s is ready: fallback timeout reached with good name", device.mac_address)
            return True

        if consistent_presence and sufficient_time:
            if data_richness >= 5:
                # Device has been consistently present and has rich data
                _LOGGER.debug("Device %s is ready: consistent presence with rich data (score: %d)",
                             device.mac_address, data_richness)
                return True
            elif data_richness >= 3 and has_good_name:
                # Device has been consistently present with moderate data but good name
                _LOGGER.debug("Device %s is ready: consistent presence with moderate data and good name",
                             device.mac_address)
                return True

        # Special case for devices with very rich data - create entity sooner
        if data_richness >= 7 and device.consecutive_scans >= 2:
            _LOGGER.debug("Device %s is ready: very rich data (score: %d) after %d scans",
                         device.mac_address, data_richness, device.consecutive_scans)
            return True

        # Not ready yet
        return False

    async def _process_pending_devices(self):
        """Process devices that don't have entities yet but might be ready."""
        for mac_address, device in list(self._devices.items()):
            # Skip devices that already have entities
            if device.entity_created:
                continue

            # Check if device is ready for entity creation
            if self._is_device_ready_for_entity(device):
                # Generate the best name we can for logging
                better_name, _ = self._generate_better_name(device)

                _LOGGER.info("Creating entity for device: %s (%s) - seen in %d scans",
                            better_name, mac_address, device.consecutive_scans)

                # Mark as having an entity
                device.entity_created = True

                # Signal new device
                async_dispatcher_send(
                    self._hass,
                    f"{DOMAIN}_device_new_{self._entry.entry_id}",
                    mac_address,
                )

    def _generate_better_name(self, device: NetworkDevice) -> tuple[str, bool]:
        """Generate a better name for a device based on available information.

        Returns:
            tuple: (better_name, is_significant_improvement)
        """
        current_name = device.name or f"Device {device.mac_address[-4:]}"

        # First priority: Use the device_friendly_name from mDNS if available
        if device.device_friendly_name and len(device.device_friendly_name) > 1:
            if device.vendor and len(device.vendor) > 1:
                better_name = f"{device.device_friendly_name} ({device.vendor})"
                return better_name, True
            return device.device_friendly_name, True

        # Second priority: Use hostname
        if device.name and len(device.name) > 1 and not device.name.startswith("Device "):
            # Clean up the hostname - remove .local suffix
            hostname = device.name
            if hostname.endswith(".local"):
                hostname = hostname[:-6] # Remove .local
            # Note: Trailing dots are already removed when the device is created

            # If it's a UUID-like hostname and we have a device model, use that instead
            if (len(hostname) > 30 and "-" in hostname) or hostname.startswith("Android-"):
                if device.device_model:
                    if device.vendor and len(device.vendor) > 1:
                        better_name = f"{device.device_model} ({device.vendor})"
                    else:
                        better_name = device.device_model
                    return better_name, True

            # If we also have vendor information, include it
            if device.vendor and len(device.vendor) > 1:
                better_name = f"{hostname} ({device.vendor})"
                return better_name, True

            # Just the hostname is still good
            return hostname, False

        # Third priority: Use device model with vendor
        if device.device_model and len(device.device_model) > 1:
            if device.vendor and len(device.vendor) > 1:
                better_name = f"{device.device_model} ({device.vendor})"
            else:
                better_name = device.device_model
            return better_name, True

        # Fourth priority: If we have vendor but no good hostname
        if device.vendor and len(device.vendor) > 1:
            better_name = f"{device.vendor} {device.mac_address[-4:]}"
            return better_name, True

        # No significant improvement possible
        return current_name, False

    async def _async_mark_missing_devices_as_not_home(self):
        """Mark devices not found in the first scan as not_home."""
        now = dt_util.now()
        for mac_address, original_name in self._known_mac_addresses.items():
            if mac_address in self._devices:                       # Already tracked in first scan
                # Mark existing device as having an entity
                self._devices[mac_address].entity_created = True
                continue

            device = NetworkDevice(mac_address)
            device.name = original_name
            device.first_offline = now                             # Mark first offline time
            device.entity_created = True                           # Mark as having an entity since it's from registry
            self._devices[mac_address] = device

            _LOGGER.info("Recreating existing device from registry: %s (%s)", original_name, mac_address)

            async_dispatcher_send(
                self._hass,
                f"{DOMAIN}_device_missing_{self._entry.entry_id}",
                mac_address,
            )                                                      # Signal device missing

    def _determine_source_and_icon(self, device_data: dict[str, Any]) -> tuple[str, str]:
        """Determine the source type and icon based on device data."""
        # Default values
        source = "Bettercap"
        icon = "mdi:lan-connect"

        # Safety check for None
        if device_data is None:
            return source, icon

        # Get device type if available
        device_type = device_data.get("device_type")

        # Check if device has wireless data
        if device_data.get("is_wireless") or device_data.get("rssi") or device_data.get("2G") or device_data.get("5G"):
            source = "wifi"
            icon = "mdi:wifi"

        # Check for Bluetooth devices
        if device_data.get("meta") and isinstance(device_data["meta"], dict):
            meta = device_data["meta"]
            if "bluetooth" in meta or "bt" in meta:
                source = "bluetooth"
                icon = "mdi:bluetooth"

        # Check for specific device types based on vendor or other attributes
        vendor = device_data.get("vendor", "")
        if vendor:
            vendor = vendor.lower()
            if "apple" in vendor or "iphone" in vendor or "ipad" in vendor or "macbook" in vendor:
                icon = "mdi:apple"
            elif "google" in vendor or "android" in vendor:
                icon = "mdi:android"
            elif "amazon" in vendor or "kindle" in vendor or "echo" in vendor:
                icon = "mdi:amazon"
            elif "microsoft" in vendor or "windows" in vendor or "xbox" in vendor:
                icon = "mdi:microsoft"
            elif "samsung" in vendor:
                icon = "mdi:cellphone"
            elif "sonos" in vendor:
                icon = "mdi:speaker"
            elif "philips" in vendor or "hue" in vendor:
                icon = "mdi:lightbulb"
            elif "xiaomi" in vendor:
                icon = "mdi:xiaomi"
            elif "espressif" in vendor:
                icon = "mdi:chip"
            elif "raspberry" in vendor:
                icon = "mdi:raspberry-pi"
            elif "asus" in vendor:
                icon = "mdi:router-network"

        # Override based on device type if available
        if device_type == "cast":
            source = "cast"
            icon = "mdi:cast"
        elif device_type == "esphome":
            source = "esphome"
            icon = "mdi:chip"
        elif device_type == "homekit":
            source = "homekit"
            icon = "mdi:home-automation"
        elif device_type == "android_tv":
            source = "android_tv"
            icon = "mdi:android-tv"

        return source, icon

    async def _update_existing_device_tracker(self, entity_id: str, mac_address: str, device_data: dict[str, Any]) -> None:
        """Update an existing device_tracker entity with new data."""
        try:
            # Get current state and attributes
            state = self._hass.states.get(entity_id)
            if not state:
                _LOGGER.warning("Cannot update entity %s: state not found", entity_id)
                return

            # Determine if device is online
            is_online = device_data.get("online", True)
            new_state = "home" if is_online else "not_home"

            # Get hostname/name
            hostname = device_data.get("name", "")
            if not hostname and "host_name" in state.attributes:
                hostname = state.attributes["host_name"]
            elif not hostname and "hostname" in state.attributes:
                hostname = state.attributes["hostname"]

            # Generate a better name if possible
            better_name = hostname
            if hasattr(self, "_generate_better_name") and device_data.get("name"):
                temp_device = NetworkDevice(mac_address)
                temp_device.update_from_data(device_data)
                better_name, _ = self._generate_better_name(temp_device)

            # Determine source type and icon
            source, icon = self._determine_source_and_icon(device_data)

            # Prepare attributes to update
            attributes = dict(state.attributes)

            # Always update these core attributes
            attributes["source_type"] = source
            attributes["mac"] = mac_address
            attributes["icon"] = icon

            if device_data.get("ip"):
                attributes["ip"] = device_data["ip"]

            if hostname:
                attributes["host_name"] = hostname

            if better_name:
                attributes["friendly_name"] = better_name

            # Add last_time_reachable if device is online
            if is_online:
                attributes["last_time_reachable"] = dt_util.now().isoformat()

            # Add vendor information if available
            if device_data.get("vendor"):
                attributes["vendor"] = device_data["vendor"]

            # Update the entity state
            self._hass.states.async_set(entity_id, new_state, attributes)

            _LOGGER.debug("Updated existing entity %s with new data", entity_id)

        except Exception as ex:
            _LOGGER.error("Error updating existing entity %s: %s", entity_id, ex)

    async def _try_update_existing_entity(self, mac_address: str, device_data: dict[str, Any]) -> None:
        """Update an existing entity if better information is available, unless manually changed."""
        registry = er.async_get(self._hass)

        # Check if this MAC address has an existing entity
        existing_entity = self._existing_mac_entities.get(mac_address)
        if not existing_entity:
            # Also check if we have a device with the same hostname but different MAC
            hostname = device_data.get("name", "").lower()
            if hostname and hostname in self._existing_hostname_entities:
                existing_entity = self._existing_hostname_entities[hostname]
                _LOGGER.debug("Found entity with matching hostname %s but different MAC", hostname)

        if not existing_entity:
            return

        # Create a temporary device object to use our naming logic
        temp_device = NetworkDevice(mac_address)
        temp_device.update_from_data(device_data)

        # Generate a better name
        better_name, is_significant = self._generate_better_name(temp_device)
        if not is_significant:
            return

        entity_id = existing_entity["entity_id"]
        _LOGGER.debug("Found better info for existing entity %s (MAC: %s)", entity_id, mac_address)

        try:
            # Get the current entity state
            state = self._hass.states.get(entity_id)
            if not state:
                return

            current_name = state.name

            # Check if the entity has a customized name (manually changed)
            entity_entry = registry.async_get(entity_id)
            has_custom_name = entity_entry and entity_entry.name is not None

            # Only update if the name wasn't manually customized
            if not has_custom_name:
                # Check if the current name is generic or less informative
                should_update_name = False

                # Update if current name is generic or contains MAC-like patterns
                if (not current_name or
                    current_name.startswith("Device ") or
                    current_name.startswith("Unknown ") or
                    ":" in current_name or
                    (len(current_name) < len(better_name) and temp_device.vendor)):
                    should_update_name = True

                # If the current name doesn't have vendor info but new one does
                if (temp_device.vendor and
                    "(" not in current_name and
                    temp_device.vendor.lower() not in current_name.lower()):
                    should_update_name = True

                if should_update_name:
                    _LOGGER.info("Updating entity %s name from '%s' to '%s'", entity_id, current_name, better_name)

                    # Update the friendly name via service call
                    await self._hass.services.async_call(
                        "homeassistant",
                        "update_entity",
                        {"entity_id": entity_id, "name": better_name},
                        blocking=True
                    )
            else:
                _LOGGER.debug("Not updating entity %s name because it was manually customized", entity_id)

            # Always update other attributes with new information
            await self._update_existing_device_tracker(entity_id, mac_address, device_data)

            # If the entity is from a different integration but represents the same device,
            # we should update our internal tracking to include this MAC address
            if mac_address not in self._known_mac_addresses:
                self._known_mac_addresses[mac_address] = entity_id.split(".", 1)[1]
                _LOGGER.debug("Added MAC %s to known addresses for entity %s", mac_address, entity_id)

        except Exception as ex:
            _LOGGER.error("Error updating entity %s: %s", entity_id, ex)

    async def _async_process_device_offline(self, found_macs: set[str], now: datetime):
        """Process devices that are offline or missing in the current scan."""
        devices_to_remove = []
        for mac_address, device in self._devices.items():
            if mac_address not in found_macs:      # Device not in current scan
                if device.online:                  # Device was online before, now missing from scan
                    if not device.first_offline:
                        device.first_offline = now # Mark first offline time
                                                   # Reset verification attempts counter
                        device.verification_attempts = 0
                    elif (device.first_offline + timedelta(seconds=DEVICE_SCAN_INTERVAL * 3) < now):
                                                   # Determine max verification attempts based on device reliability
                        if device.reliability_score < 50:
                                                   # Less reliable devices get more verification attempts
                            max_verification_attempts = VERIFICATION_ATTEMPTS * 2
                        else:
                            max_verification_attempts = VERIFICATION_ATTEMPTS

                        # Time to actively verify if the device is truly offline
                        if device.verification_attempts < max_verification_attempts:
                            # Increment verification counter
                            device.verification_attempts += 1
                            # Schedule active verification
                            self._hass.async_create_task(self._verify_device_connectivity(device))
                        else:
                            # We've tried verification multiple times, mark as offline
                            device.online = False
                            # Update reliability metrics
                            device.offline_frequency += 1
                            device.reliability_score = max(0, device.reliability_score - 5)

                            _LOGGER.debug("Device %s (%s) marked offline after %d verification attempts", device.name, device.mac_address, device.verification_attempts)

                            # Make sure the device exists in _devices before sending update
                            if mac_address in self._devices:
                                async_dispatcher_send(self._hass, signal_device_update(mac_address), False)                                     # Signal offline
                elif (not device.online and device.first_offline and device.first_offline + timedelta(seconds=DEVICE_SCAN_INTERVAL * 6) < now): # Remove device after longer offline period
                    devices_to_remove.append(mac_address)

        for mac_address in devices_to_remove:
            self._devices.pop(mac_address) # Remove devices offline for extended period
