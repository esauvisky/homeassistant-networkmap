"""The Network Map integration."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from datetime import datetime
import logging
from typing import Any

import paramiko
import json

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
        name = data.get("name") or data.get("nickName")
        if name and name != self.name:
            self.name = name

        ip = data.get("ip")
        if ip and ip != self.ip:
            self.ip = ip

        vendor = data.get("vendor")
        if vendor and vendor != self.vendor:
            self.vendor = vendor

        vendor_class = data.get("vendorclass")
        if vendor_class and vendor_class != self.vendor_class:
            self.vendor_class = vendor_class

        type_ = data.get("type")
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

        connection_time = data.get("wlConnectTime")
        if connection_time and connection_time != self.connection_time:
            self.connection_time = connection_time

        self.last_update = dt_util.now()


class NetworkDeviceScanner:
    """Scanner for network devices using router data."""

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
        self._ssh_client: paramiko.SSHClient | None = None
        self._unsub_interval_scan = None
        self._finished_first_scan = False
        self._known_mac_addresses: dict[str, str] = {}

    async def async_setup(self) -> bool:
        """Set up the scanner and start periodic scanning."""
        if not await self._async_connect_ssh():
            return False

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

    async def async_shutdown(self) -> None:
        """Stop the scanner and cleanup."""
        if self._unsub_interval_scan:
            self._unsub_interval_scan()
            self._unsub_interval_scan = None
        if self._ssh_client:
            await self._hass.async_add_executor_job(self._ssh_client.close)
            self._ssh_client = None

    async def _async_connect_ssh(self) -> bool:
        """Establish SSH connection."""
        self._ssh_client = paramiko.SSHClient()
        self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            await self._hass.async_add_executor_job(
                self._ssh_client.connect,
                self._config[CONF_HOST],
                self._config[CONF_PORT],
                self._config[CONF_USERNAME],
                self._config[CONF_PASSWORD],
            )
            return True
        except paramiko.AuthenticationException:
            _LOGGER.error(
                "SSH Authentication failed for %s@%s",
                self._config[CONF_USERNAME],
                self._config[CONF_HOST],
            )
            return False
        except Exception as e:
            _LOGGER.error(
                "Error connecting to %s via SSH: %s", self._config[CONF_HOST], e
            )
            return False

    async def _async_fetch_device_data(self) -> dict[str, Any] | None:
        """Fetch device data from the router via SSH."""
        if self._ssh_client is None:
            if not await self._async_connect_ssh():  # Re-establish connection if lost
                return None
        if self._ssh_client is None:
            _LOGGER.error("SSH Client is not available after connection attempt")
            return None

        try:
            device_data = await self._hass.async_add_executor_job(
                get_device_data, self._ssh_client
            )
            return device_data
        except Exception as e:
            _LOGGER.error("Error fetching device data: %s", e)
            return None

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


def get_device_data(ssh_client: paramiko.SSHClient) -> dict[str, Any] | None:
    """
    Retrieves and parses device data from the router using SSH, including data from /tmp/nmp_cache.js.

    Args:
        ssh_client: An established paramiko SSHClient object.

    Returns:
        A dictionary containing device information, or None if an error occurs.
    """
    try:
        # Read and parse /jffs/nmp_cl_json.js
        _, stdout, stderr = ssh_client.exec_command("cat /jffs/nmp_cl_json.js")
        cl_json_str = stdout.read().decode()
        if stderr.read():
            _LOGGER.warning(
                "Error reading /jffs/nmp_cl_json.js: %s", stderr.read().decode()
            )
            return None

        cl_json = json.loads(cl_json_str)

        # Read and parse /jffs/nmp_vc_json.js
        _, stdout, stderr = ssh_client.exec_command("cat /jffs/nmp_vc_json.js")
        vc_json_str = stdout.read().decode()
        if stderr.read():
            _LOGGER.warning(
                "Error reading /jffs/nmp_vc_json.js: %s", stderr.read().decode()
            )
            return None
        vc_json = json.loads(vc_json_str) if vc_json_str else {}

        # Read and parse /tmp/allwclientlist.json
        _, stdout, stderr = ssh_client.exec_command("cat /tmp/allwclientlist.json")
        allw_json_str = stdout.read().decode()
        if stderr.read():
            _LOGGER.warning(
                "Error reading /tmp/allwclientlist.json: %s", stderr.read().decode()
            )
            return None

        allw_json = json.loads(allw_json_str) if allw_json_str else {}

        # Read and parse /tmp/nmp_cache.js
        _, stdout, stderr = ssh_client.exec_command("cat /tmp/nmp_cache.js")
        cache_json_str = stdout.read().decode()
        if stderr.read():
            _LOGGER.warning(
                "Error reading /tmp/nmp_cache.js: %s", stderr.read().decode()
            )
            return None

        cache_json = json.loads(cache_json_str) if cache_json_str else {}

        # Combine data from all files
        devices = {}
        for mac, data in cl_json.items():
            data["online"] = data["online"] == "1"  # Convert to bool
            data["is_wireless"] = data["is_wireless"] == "1"  # Convert to bool
            devices[mac] = data
            devices[mac]["2G"] = False
            devices[mac]["5G"] = False

            # Append vendorclass from vc_json to existing vendorclass unless it's identical
            if mac in vc_json and devices[mac]["vendorclass"] != vc_json[mac].get(
                "vendorclass"
            ):
                devices[mac]["vendorclass"] += f", {vc_json[mac].get('vendorclass')}"

        # Update online status and band info from allwclientlist.json
        for interface, bands in allw_json.items():
            for band, macs in bands.items():
                for mac, _ in macs.items():
                    if mac in devices:
                        if band == "2G":
                            devices[mac]["2G"] = True
                        elif band == "5G":
                            devices[mac]["5G"] = True

        # Update data from nmp_cache.js
        for mac, data in cache_json.items():
            if mac != "maclist" and mac != "ClientAPILevel":
                if mac not in devices:
                    devices[mac] = {}

                # Check if data is a dictionary before updating
                if isinstance(data, dict):
                    devices[mac].update(data)
                else:
                    _LOGGER.warning(
                        "Data for MAC %s in nmp_cache.js is not a dictionary. Skipping update for this device",
                        mac,
                    )
                    continue

                # Ensure 'online' key exists after update from cache
                if "online" not in devices[mac]:
                    devices[mac]["online"] = False

                # Check if the device is online based on nmp_cache.js
                if "isOnline" in data and data["isOnline"] == "1":
                    devices[mac]["online"] = True

        return devices

    except Exception as e:
        _LOGGER.error("Error processing device data: %s", e)
        return None
