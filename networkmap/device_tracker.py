"""Device tracker platform for Network Map."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.device_tracker import ScannerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import NetworkDevice, NetworkDeviceScanner, signal_device_update
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up device tracker for Network Map component."""
    scanner: NetworkDeviceScanner = hass.data[DOMAIN][entry.entry_id]

    @callback
    def device_new(mac_address):
        """Signal a new device."""
        async_add_entities([NetworkMapDeviceTrackerEntity(scanner, mac_address, True)])

    @callback
    def device_missing(mac_address):
        """Signal a missing device."""
        async_add_entities([NetworkMapDeviceTrackerEntity(scanner, mac_address, False)])

    entry.async_on_unload(
        async_dispatcher_connect(
            hass, f"{DOMAIN}_device_new_{entry.entry_id}", device_new
        )
    )
    entry.async_on_unload(
        async_dispatcher_connect(
            hass, f"{DOMAIN}_device_missing_{entry.entry_id}", device_missing
        )
    )


class NetworkMapDeviceTrackerEntity(ScannerEntity):
    """Representation of a network device."""

    _attr_should_poll = False
    _attr_translation_key = "device_tracker"

    def __init__(
        self, scanner: NetworkDeviceScanner, mac_address: str, active: bool
    ) -> None:
        """Initialize the device tracker entity."""
        self._scanner = scanner
        self._mac_address = mac_address
        self._active = active

    @property
    def _device(self) -> NetworkDevice:
        """Return NetworkDevice object."""
        # Safely get the device, returning a default if not found
        if self._mac_address not in self._scanner._devices:  # pylint: disable=protected-access
            _LOGGER.warning("Device %s not found in scanner devices", self._mac_address)
            # Return a default device to prevent KeyError
            default_device = NetworkDevice(self._mac_address)
            default_device.name = f"Unknown {self._mac_address[-4:]}"
            default_device.online = False
            return default_device
        return self._scanner._devices[self._mac_address]  # pylint: disable=protected-access

    @property
    def unique_id(self) -> str:
        """Return unique ID."""
        # Add a prefix to ensure uniqueness across different integrations
        return f"{DOMAIN}_{self._mac_address}"

    @property
    def name(self) -> str:
        """Return device name."""
        device = self._device
        scanner = self._scanner
        
        # Use the better name generator if available
        if hasattr(scanner, "_generate_better_name"):
            better_name, _ = scanner._generate_better_name(device)
            return better_name
            
        # Fallback to simple naming
        if device.name:
            return device.name
        return f"Device {self._mac_address[-4:]}"

    @property
    def is_connected(self) -> bool:
        """Return connection status."""
        return self._active and self._device.online

    @property
    def ip_address(self) -> str | None:
        """Return IP address of the device."""
        return self._device.ip

    @property
    def mac_address(self) -> str:
        """Return MAC address of the device."""
        return self._mac_address

    @property
    def manufacturer(self) -> str | None:
        """Return manufacturer of the device."""
        return self._device.vendor

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return device state attributes."""
        device = self._device
        attributes = {
            "vendor": device.vendor,
            "vendor_class": device.vendor_class,
        }
        
        # Add optional attributes only if they have values
        if device.first_seen:
            attributes["first_seen"] = device.first_seen
            
        if device.last_seen:
            attributes["last_seen"] = device.last_seen
            
        if device.type:
            attributes["device_type"] = device.type
            
        if device.os_type:
            attributes["os_type"] = device.os_type
            
        if device.rssi:
            attributes["rssi"] = device.rssi
            
        if device.cur_tx:
            attributes["current_tx_rate"] = device.cur_tx
            
        if device.cur_rx:
            attributes["current_rx_rate"] = device.cur_rx
            
        if device.is_2g:
            attributes["is_2g"] = device.is_2g
            
        if device.is_5g:
            attributes["is_5g"] = device.is_5g
            
        if device.is_wireless:
            attributes["is_wireless"] = device.is_wireless
            
        return attributes

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return if entity is enabled by default."""
        # Enable by default for mobile devices
        # return self._device.type == 9 or self._device.os_type == 1
        return self.mac_address is not None

    @callback
    def async_on_demand_update(self, online: bool) -> None:
        """Update state."""
        try:
            self._active = online
            self.async_write_ha_state()
        except Exception as ex:
            _LOGGER.error("Error updating device %s: %s", self._mac_address, ex)

    async def async_added_to_hass(self) -> None:
        """Register state update callback."""
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                signal_device_update(self._mac_address),
                self.async_on_demand_update,
            )
        )
