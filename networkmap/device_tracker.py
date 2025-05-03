"""Device tracker platform for Network Map."""

from __future__ import annotations

import logging
from typing import Any

import homeassistant.util.dt as dt_util
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
    _LOGGER.debug("Setting up device_tracker platform for entry %s", entry.entry_id)

    @callback
    def device_new(mac_address):
        """Signal a new device."""
        device = scanner._devices.get(mac_address)
        name = device.name if device else f"Unknown {mac_address[-4:]}"
        _LOGGER.info("Adding new device tracker entity: %s (%s)", name, mac_address)
        async_add_entities([NetworkMapDeviceTrackerEntity(scanner, mac_address, True)])

    @callback
    def device_missing(mac_address):
        """Signal a missing device."""
        device = scanner._devices.get(mac_address)
        name = device.name if device else f"Unknown {mac_address[-4:]}"
        _LOGGER.info("Adding missing device tracker entity: %s (%s)", name, mac_address)
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

        # Log entity creation with unique ID
        config_entry_id = scanner._entry.entry_id
        short_entry_id = config_entry_id.split("-")[0]
        unique_id = f"{DOMAIN}_{short_entry_id}_{mac_address}"

        device = scanner._devices.get(mac_address)
        name = device.name if device and device.name else f"Unknown {mac_address[-4:]}"

        _LOGGER.debug("Initializing device tracker entity: name=%s, mac=%s, unique_id=%s",
                     name, mac_address, unique_id)

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
        # Also add the config entry ID to ensure uniqueness within the integration
        config_entry_id = self._scanner._entry.entry_id
        short_entry_id = config_entry_id.split("-")[0]
        return f"{DOMAIN}_{short_entry_id}_{self._mac_address}"

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
    def suggested_object_id(self) -> str:
        """Return a suggested object ID based on the name."""
        # This will be used when the entity is first created
        # The registry will use this to create the initial entity_id
        if self._device.name:
            name = self._device.name

            # Remove .local suffix (trailing dots are already removed when the device is created)
            if name.endswith(".local"):
                name = name[:-6]

            # Remove any vendor information
            if "(" in name:
                name = name.split("(")[0].strip()

            # For device names with hyphens like "YLBulbColor1s-71CB", keep only the main part
            if "-" in name:
                parts = name.split("-")
                # If the last part looks like a MAC suffix or ID (alphanumeric and 4-6 chars)
                if len(parts) > 1 and len(parts[-1]) <= 6 and parts[-1].isalnum():
                    # Keep the device name and the ID part, but not other parts
                    name = f"{parts[0]}_{parts[-1]}"

            # Clean up the name
            import re
            name = re.sub(r'[^a-z0-9_]+', '_', name.lower())
            return name

        # Fallback to MAC-based ID
        return f"device_{self._mac_address[-4:].lower()}"

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
    def icon(self) -> str:
        """Return the icon to use in the frontend."""
        try:
            # Determine icon based on device properties
            scanner = self._scanner
            device = self._device

            if hasattr(scanner, "_determine_source_and_icon"):
                # Create a device_data dict to pass to the method
                device_data = {
                    "name": device.name,
                    "ip": device.ip,
                    "vendor": device.vendor,
                    "is_wireless": device.is_wireless,
                    "rssi": device.rssi,
                    "2G": device.is_2g,
                    "5G": device.is_5g,
                    "meta": {}
                }
                _, icon = scanner._determine_source_and_icon(device_data)
                return icon
        except Exception as ex:
            _LOGGER.debug("Error determining icon: %s", ex)

        # Default icon if method not available or error occurs
        return "mdi:lan-connect"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return device state attributes."""
        device = self._device
        scanner = self._scanner

        # Determine source type
        source = "Bettercap"
        if hasattr(scanner, "_determine_source_and_icon"):
            # Create a device_data dict to pass to the method
            device_data = {
                "name": device.name,
                "ip": device.ip,
                "vendor": device.vendor,
                "is_wireless": device.is_wireless,
                "rssi": device.rssi,
                "2G": device.is_2g,
                "5G": device.is_5g,
                "meta": getattr(device, "meta", {}),
                "device_model": device.device_model,
                "device_friendly_name": device.device_friendly_name
            }
            source, _ = scanner._determine_source_and_icon(device_data)

        attributes = {
            # Required attributes that should always be present
            "source_type": source,
            "mac": self.mac_address,
            "host_name": device.name or f"device_{self.mac_address[-4:]}",
        }

        # Add IP if available
        if device.ip:
            attributes["ip"] = device.ip

        # Add last_time_reachable if device is online
        if device.online:
            attributes["last_time_reachable"] = dt_util.now().isoformat()

        # Add vendor information
        if device.vendor:
            attributes["vendor"] = device.vendor

        if device.vendor_class:
            attributes["vendor_class"] = device.vendor_class

        # Add enhanced device identification
        if device.device_model:
            attributes["model"] = device.device_model

        if device.device_friendly_name:
            attributes["friendly_device_name"] = device.device_friendly_name

        if device.mdns_services and len(device.mdns_services) > 0:
            attributes["services"] = ", ".join(device.mdns_services)

        # Add optional attributes only if they have values
        if device.first_seen:
            attributes["first_seen"] = device.first_seen

        if device.last_seen:
            attributes["last_seen"] = device.last_seen

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

        # Add all meta values as attributes
        if hasattr(device, "meta") and isinstance(device.meta, dict):
            for key, value in device.meta.items():
                # Convert meta keys to valid attribute names
                attr_key = key.replace(":", "_").replace(".", "_")

                # Handle JSON objects and lists by splitting them into multiple attributes
                if isinstance(value, dict):
                    # For dictionaries, create separate attributes for each key
                    for sub_key, sub_value in value.items():
                        sub_attr_key = f"{attr_key}_{sub_key}".replace(":", "_").replace(".", "_")
                        if sub_attr_key not in attributes:
                            attributes[sub_attr_key] = sub_value
                elif isinstance(value, list):
                    # For lists, create indexed attributes or join simple values
                    if value and all(isinstance(item, (str, int, float, bool)) for item in value):
                        # If all items are simple types, join them
                        attributes[attr_key] = ", ".join(str(item) for item in value)
                    else:
                        # For complex items, create indexed attributes
                        for i, item in enumerate(value):
                            if not isinstance(item, (dict, list)):
                                indexed_key = f"{attr_key}_{i}".replace(":", "_").replace(".", "_")
                                if indexed_key not in attributes:
                                    attributes[indexed_key] = item
                elif attr_key not in attributes:
                    # For simple values, add directly
                    attributes[attr_key] = value

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
