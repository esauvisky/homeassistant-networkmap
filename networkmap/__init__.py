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
        self.first_seen: str | None = None
        self.last_seen: str | None = None
        self.is_wireless: bool = False
        self.first_offline: datetime | None = None
        self.verification_attempts: int = 0
        self.reliability_score: int = 100  # Start with perfect score
        self.offline_frequency: int = 0    # Track how often device goes offline

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

        first_seen = data.get("first_seen")
        if first_seen and first_seen != self.first_seen:
            self.first_seen = first_seen
            
        last_seen = data.get("last_seen")
        if last_seen and last_seen != self.last_seen:
            self.last_seen = last_seen
            
        is_wireless = data.get("is_wireless", False)
        if is_wireless is not None and is_wireless != self.is_wireless:
            self.is_wireless = is_wireless


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
        # Get device naming options
        self._auto_rename_friendly = self._config.get(CONF_AUTO_RENAME_FRIENDLY, DEFAULT_AUTO_RENAME_FRIENDLY)
        self._auto_rename_entity = self._config.get(CONF_AUTO_RENAME_ENTITY, DEFAULT_AUTO_RENAME_ENTITY)
        self._devices: dict[str, NetworkDevice] = {}
        self._scan_lock = asyncio.Lock()
        self._session = async_get_clientsession(hass)
        self._api_url = BETTERCAP_API_URL.format(
            host=self._config[CONF_HOST], 
            port=self._config[CONF_PORT]
        )
        # Set up authentication only if username and password are provided
        self._auth = None
        if self._config.get(CONF_USERNAME) and self._config.get(CONF_PASSWORD):
            self._auth = aiohttp.BasicAuth(
                self._config[CONF_USERNAME],
                self._config[CONF_PASSWORD]
            )

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

        # Get entity registry to find existing device_tracker entities
        registry = er.async_get(self._hass)

        # Get entities for this config entry
        self._known_mac_addresses = {
            entry.unique_id: entry.original_name
            for entry in registry.entities.get_entries_for_config_entry_id(
                self._entry.entry_id
            )
        }

        # Find all device_tracker entities in the system to check for MAC address and hostname matches
        self._existing_mac_entities = {}
        self._existing_hostname_entities = {}

        # First pass: collect all device_tracker entities
        all_device_trackers = {}
        for entity_id, entity in registry.entities.items():
            if entity.domain == "device_tracker":
                all_device_trackers[entity_id] = {
                    "entity_id": entity_id,
                    "config_entry_id": entity.config_entry_id,
                    "disabled": entity.disabled,
                    "unique_id": entity.unique_id,
                    "original_name": entity.original_name
                }

        # Second pass: check for MAC addresses in unique_ids and attributes
        for entity_id, entity_data in all_device_trackers.items():
            # Check if unique_id contains a MAC address
            if entity_data["unique_id"] and ":" in entity_data["unique_id"]:
                mac_parts = entity_data["unique_id"].split("_")
                for part in mac_parts:
                    if ":" in part and len(part) >= 17:  # MAC addresses are at least 17 chars with colons
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

        # Also start a periodic reverification of offline devices
        self._unsub_reverify = async_track_time_interval(
            self._hass,
            self._async_scheduled_reverification,
            timedelta(minutes=15),  # Try to rediscover offline devices every 15 minutes
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

    async def _verify_device_connectivity(self, device: NetworkDevice) -> None:
        """Actively verify if a device is still connected to the network."""
        if not device.ip:
            _LOGGER.debug("Cannot verify device %s: no IP address", device.mac_address)
            return

        _LOGGER.debug("Actively verifying connectivity for %s (%s)", device.name, device.ip)

        # Try different verification methods
        verification_methods = [
            # Method 1: Targeted net.probe
            {"cmd": BETTERCAP_NET_PROBE_TARGET.format(target=device.ip)},
            # Method 2: ARP probe
            {"cmd": BETTERCAP_ARP_PROBE_TARGET.format(target=device.ip)},
            # Method 3: ICMP ping
            {"cmd": BETTERCAP_PING_TARGET.format(target=device.ip)}
        ]

        for method in verification_methods:
            try:
                # Send the verification command
                async with self._session.post(
                    f"{self._api_url}/session",
                    auth=self._auth,
                    headers=self._headers,
                    json=method,
                    timeout=10
                ) as response:
                    if response.status in (200, 204):
                        # Wait a moment for the command to take effect
                        await asyncio.sleep(VERIFICATION_DELAY)

                        # Check if the device responded by fetching updated device data
                        device_data = await self._async_fetch_device_data()
                        if device_data and device.mac_address in device_data:
                            # Device responded to verification, mark as online
                            _LOGGER.debug("Device %s verified as online", device.name)
                            device.online = True
                            device.first_offline = None
                            device.verification_attempts = 0
                            # Improve reliability score
                            device.reliability_score = min(100, device.reliability_score + 2)
                            # Update device data
                            device.update_from_data(device_data[device.mac_address])
                            # Signal device update
                            async_dispatcher_send(
                                self._hass,
                                signal_device_update(device.mac_address),
                                True
                            )
                            return  # Successfully verified, no need to try other methods
            except Exception as ex:
                _LOGGER.warning("Error during connectivity verification for %s: %s", device.name, ex)

        # If we get here, all verification methods failed
        _LOGGER.debug("Device %s failed verification attempt %d",
                     device.name, device.verification_attempts)

    async def _async_scheduled_reverification(self, *_):
        """Periodically try to rediscover offline devices."""
        _LOGGER.debug("Running scheduled reverification of offline devices")
        for mac_address, device in self._devices.items():
            if not device.online and device.ip:
                # Try to rediscover the device
                _LOGGER.debug("Attempting to rediscover offline device: %s", device.name)
                await self._verify_device_connectivity(device)

    async def _async_process_device_data(self, fetched_devices: dict[str, Any]) -> None:
        """Process fetched device data and update entities."""
        current_devices = {}
        now = dt_util.now()
        registry = er.async_get(self._hass)

        for mac_address, raw_device_data in fetched_devices.items():
            formatted_mac = format_mac(mac_address)
            if formatted_mac is None:  # Invalid MAC Address
                _LOGGER.warning("Invalid MAC address found: %s", mac_address)
                continue

            # First check if this MAC is already tracked by another integration
            existing_entity = self._existing_mac_entities.get(formatted_mac)
            if existing_entity and existing_entity["config_entry_id"] != self._entry.entry_id:
                # This MAC is tracked by another integration, update the entity registry
                # to associate it with this integration instead
                _LOGGER.info(
                    "Found existing device_tracker entity %s for MAC %s, updating to use this integration",
                    existing_entity["entity_id"], formatted_mac
                )

                # Only update the entity if it's not disabled
                if not existing_entity["disabled"]:
                    try:
                        # Update the entity to use this integration
                        registry.async_update_entity(
                            entity_id=existing_entity["entity_id"],
                            config_entry_id=self._entry.entry_id,
                            # Keep the original unique_id to maintain entity history
                            new_unique_id=f"{DOMAIN}_{formatted_mac}"
                        )
                        # Add to known MAC addresses
                        self._known_mac_addresses[formatted_mac] = existing_entity["entity_id"].split(".", 1)[1]
                    except Exception as ex:
                        _LOGGER.error("Error updating entity registry for %s: %s", formatted_mac, ex)

            # If no MAC match, check if hostname matches an existing entity
            elif raw_device_data.get("name"):
                hostname = raw_device_data["name"].lower()
                existing_entity = self._existing_hostname_entities.get(hostname)

                if existing_entity and existing_entity["config_entry_id"] != self._entry.entry_id:
                    _LOGGER.info(
                        "Found existing device_tracker entity %s with matching hostname %s, updating to use this integration",
                        existing_entity["entity_id"], hostname
                    )

                    # Only update the entity if it's not disabled
                    if not existing_entity["disabled"]:
                        try:
                            # Update the entity to use this integration
                            registry.async_update_entity(
                                entity_id=existing_entity["entity_id"],
                                config_entry_id=self._entry.entry_id,
                                # Use the new MAC address with our domain prefix
                                new_unique_id=f"{DOMAIN}_{formatted_mac}"
                            )
                            # Add to known MAC addresses
                            self._known_mac_addresses[formatted_mac] = existing_entity["entity_id"].split(".", 1)[1]
                        except Exception as ex:
                            _LOGGER.error("Error updating entity registry for hostname %s: %s", hostname, ex)

            # Check if this device is managed by this config entry
            if (
                self._entry.entry_id
                != self._known_mac_addresses.get(
                    formatted_mac, self._entry.entry_id
                )  # Using entity registry to track ownership, fallback to entry_id for new entities.
            ):
                # If auto-rename is enabled, we might still want to update the entity
                # even if it's not managed by this config entry
                if self._auto_rename_friendly or self._auto_rename_entity:
                    await self._try_rename_existing_entity(formatted_mac, raw_device_data)
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

    def _generate_better_name(self, device: NetworkDevice) -> tuple[str, bool]:
        """Generate a better name for a device based on available information.

        Returns:
            tuple: (better_name, is_significant_improvement)
        """
        current_name = device.name or f"Device {device.mac_address[-4:]}"

        # Check if we have a hostname
        if device.name and len(device.name) > 1 and not device.name.startswith("Device "):
            # We have a good hostname

            # If we also have vendor information, include it
            if device.vendor and len(device.vendor) > 1:
                better_name = f"{device.name} ({device.vendor})"
                return better_name, True

            # Just the hostname is still good
            return device.name, True

        # If we have vendor but no good hostname
        if device.vendor and len(device.vendor) > 1:
            better_name = f"{device.vendor} {device.mac_address[-4:]}"
            return better_name, True

        # No significant improvement possible
        return current_name, False

    async def _async_mark_missing_devices_as_not_home(self):
        """Mark devices not found in the first scan as not_home."""
        now = dt_util.now()
        for mac_address, original_name in self._known_mac_addresses.items():
            if mac_address in self._devices:  # Already tracked in first scan
                continue
            device = NetworkDevice(mac_address)
            device.name = original_name
            device.first_offline = now  # Mark first offline time
            self._devices[mac_address] = device
            async_dispatcher_send(
                self._hass,
                f"{DOMAIN}_device_missing_{self._entry.entry_id}",
                mac_address,
            )  # Signal device missing

    async def _try_rename_existing_entity(self, mac_address: str, device_data: dict[str, Any]) -> None:
        """Try to rename an existing entity if better information is available."""
        registry = er.async_get(self._hass)

        # Check if this MAC address has an existing entity
        existing_entity = self._existing_mac_entities.get(mac_address)
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
        _LOGGER.debug(
            "Found better name '%s' for existing entity %s (MAC: %s)",
            better_name, entity_id, mac_address
        )

        try:
            # Get the current entity state
            state = self._hass.states.get(entity_id)
            if not state:
                return

            current_name = state.name

            # Check if the current name is already good
            if current_name and len(current_name) > 1 and ":" not in current_name and "-" not in current_name:
                # Current name seems good, only replace if we have a hostname and vendor
                if not (temp_device.name and temp_device.vendor):
                    return

            # Update friendly name if enabled
            if self._auto_rename_friendly:
                _LOGGER.info(
                    "Renaming entity %s friendly name from '%s' to '%s'",
                    entity_id, current_name, better_name
                )

                # Update the friendly name via service call
                await self._hass.services.async_call(
                    "homeassistant", "update_entity_attributes",
                    {
                        "entity_id": entity_id,
                        "friendly_name": better_name
                    },
                    blocking=True
                )

            # Update entity ID if enabled
            if self._auto_rename_entity and temp_device.name:
                # Generate a valid entity ID from the device name
                domain = entity_id.split(".", 1)[0]
                new_entity_id = f"{domain}.{temp_device.name.lower().replace(' ', '_')}"

                # Check if this entity ID already exists
                if new_entity_id != entity_id and not self._hass.states.get(new_entity_id):
                    _LOGGER.info(
                        "Renaming entity ID from %s to %s",
                        entity_id, new_entity_id
                    )

                    # Update the entity ID in the registry
                    registry.async_update_entity(
                        entity_id=entity_id,
                        new_entity_id=new_entity_id
                    )

                    # Update our tracking dictionaries
                    self._existing_mac_entities[mac_address]["entity_id"] = new_entity_id

                    # If this entity is in our known MAC addresses, update that too
                    if mac_address in self._known_mac_addresses:
                        self._known_mac_addresses[mac_address] = new_entity_id.split(".", 1)[1]

        except Exception as ex:
            _LOGGER.error("Error renaming entity %s: %s", entity_id, ex)

    async def _async_process_device_offline(
        self, current_devices: dict[str, NetworkDevice], now: datetime
    ):
        """Process devices that are offline or missing in the current scan."""
        devices_to_remove = []
        for mac_address, device in self._devices.items():
            if mac_address not in current_devices:  # Device not in current scan
                if device.online:  # Device was online before, now missing from scan
                    if not device.first_offline:
                        device.first_offline = now  # Mark first offline time
                        # Reset verification attempts counter
                        device.verification_attempts = 0
                    elif (
                        device.first_offline
                        + timedelta(seconds=DEVICE_SCAN_INTERVAL * 3)
                        < now
                    ):
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
                            self._hass.async_create_task(
                                self._verify_device_connectivity(device)
                            )
                        else:
                            # We've tried verification multiple times, mark as offline
                            device.online = False
                            # Update reliability metrics
                            device.offline_frequency += 1
                            device.reliability_score = max(0, device.reliability_score - 5)

                            _LOGGER.debug(
                                "Device %s (%s) marked offline after %d verification attempts",
                                device.name, device.mac_address, device.verification_attempts
                            )

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
                ):  # Remove device after longer offline period
                    devices_to_remove.append(mac_address)

        for mac_address in devices_to_remove:
            self._devices.pop(mac_address)  # Remove devices offline for extended period


