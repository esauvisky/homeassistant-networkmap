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
        return self._scanner._devices[self._mac_address]  # pylint: disable=protected-access

    @property
    def unique_id(self) -> str:
        """Return unique ID."""
        return self._mac_address

    @property
    def name(self) -> str:
        """Return device name."""
        device = self._device
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
        return {
            "vendor_class": device.vendor_class,
            "device_type": device.type,
            "os_type": device.os_type,
            "rssi": device.rssi,
            "current_tx_rate": device.cur_tx,
            "current_rx_rate": device.cur_rx,
            "connection_time": device.connection_time,
            "is_2g": device.is_2g,
            "is_5g": device.is_5g,
            "last_update": device.last_update.isoformat(timespec="seconds")
            if device.last_update
            else None,
        }

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return if entity is enabled by default."""
        # Enable by default for mobile devices
        # return self._device.type == 9 or self._device.os_type == 1
        return self.mac_address is not None

    @callback
    def async_on_demand_update(self, online: bool) -> None:
        """Update state."""
        self._active = online
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        """Register state update callback."""
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                signal_device_update(self._mac_address),
                self.async_on_demand_update,
            )
        )
