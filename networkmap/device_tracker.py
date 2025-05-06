"""Device tracker platform for Network Map."""

from __future__ import annotations

import logging
from typing import Any, Dict, Set

import homeassistant.util.dt as dt_util
from homeassistant.components.device_tracker import ScannerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import signal_device_new, signal_device_updated, signal_device_offline
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up device tracker for Network Map component."""
    _LOGGER.debug("Setting up device_tracker platform for entry %s", entry.entry_id)

    # Keep track of entities we've created
    tracked_macs: Set[str] = set()
    entity_registry: Dict[str, NetworkMapDeviceTrackerEntity] = {}

    @callback
    def handle_device_new(mac_address: str, device_data: dict[str, Any]):
        """Handle new device discovery."""
        if mac_address in tracked_macs:
            _LOGGER.debug("Device %s already has an entity", mac_address)
            return

        _LOGGER.info("Adding new device tracker entity: %s", mac_address)

        # Create new entity
        entity = NetworkMapDeviceTrackerEntity(entry.entry_id, mac_address, device_data)
        async_add_entities([entity])

        # Track this entity
        tracked_macs.add(mac_address)
        entity_registry[mac_address] = entity

    @callback
    def handle_device_updated(mac_address: str, device_data: dict[str, Any]):
        """Handle device data updates."""
        if mac_address not in tracked_macs:
            # If we get an update for a device we don't have an entity for yet,
            # create one now
            handle_device_new(mac_address, device_data)
            return

        if mac_address in entity_registry:
            entity = entity_registry[mac_address]
            entity.async_process_update(device_data)

    @callback
    def handle_device_offline(mac_address: str):
        """Handle device going offline."""
        if mac_address in entity_registry:
            entity = entity_registry[mac_address]
            entity.async_mark_offline()

    # Register for all the signals
    entry.async_on_unload(
        async_dispatcher_connect(
            hass, signal_device_new(entry.entry_id), handle_device_new
        )
    )

    entry.async_on_unload(
        async_dispatcher_connect(
            hass, signal_device_updated(entry.entry_id), handle_device_updated
        )
    )

    entry.async_on_unload(
        async_dispatcher_connect(
            hass, signal_device_offline(entry.entry_id), handle_device_offline
        )
    )


class NetworkMapDeviceTrackerEntity(ScannerEntity):
    """Representation of a network device."""

    _attr_should_poll = False
    _attr_translation_key = "device_tracker"
    _attr_has_entity_name = True
    _attr_name = None

    def __init__(
        self, entry_id: str, mac_address: str, device_data: dict[str, Any]
    ) -> None:
        """Initialize the device tracker entity."""
        self._entry_id = entry_id
        self._mac_address = mac_address
        self._raw_data = device_data
        self._is_on = True  # Start as connected since we just discovered it

        # Extract a short entry ID for the unique_id
        short_entry_id = entry_id.split("-")[0]
        self._attr_unique_id = f"{DOMAIN}_{short_entry_id}_{mac_address}"

        # Extract basic info for logging
        name = device_data.get("name") or f"Unknown {mac_address[-4:]}"
        _LOGGER.debug("Initializing device tracker entity: name=%s, mac=%s, unique_id=%s",
                     name, mac_address, self._attr_unique_id)

    @property
    def is_connected(self) -> bool:
        """Return connection status."""
        return self._is_on

    @property
    def ip_address(self) -> str | None:
        """Return IP address of the device."""
        return self._raw_data.get("ip")

    @property
    def mac_address(self) -> str:
        """Return MAC address of the device."""
        return self._mac_address

    @property
    def manufacturer(self) -> str | None:
        """Return manufacturer of the device."""
        return self._raw_data.get("vendor")

    @property
    def icon(self) -> str:
        """Return the icon to use in the frontend."""
        # Default icon
        icon = "mdi:lan-connect"

        # Check if device has wireless data
        if (self._raw_data.get("is_wireless") or
            self._raw_data.get("rssi") or
            self._raw_data.get("2G") or
            self._raw_data.get("5G")):
            icon = "mdi:wifi"

        # Check for Bluetooth devices
        meta = self._raw_data.get("meta", {})
        if isinstance(meta, dict) and ("bluetooth" in meta or "bt" in meta):
            icon = "mdi:bluetooth"

        # Check for specific device types based on vendor
        vendor = self._raw_data.get("vendor", "")
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
            # elif "xiaomi" in vendor:
            #     icon = "mdi:xiaomi"
            elif "espressif" in vendor:
                icon = "mdi:chip"
            elif "raspberry" in vendor:
                icon = "mdi:raspberry-pi"
            elif "asus" in vendor:
                icon = "mdi:router-network"

        # Override based on device type if available
        device_type = self._raw_data.get("device_type")
        if device_type == "cast":
            icon = "mdi:cast"
        elif device_type == "esphome":
            icon = "mdi:chip"
        elif device_type == "homekit":
            icon = "mdi:home-automation"
        elif device_type == "android_tv":
            icon = "mdi:cast"

        return icon

    @property
    def source_type(self) -> str:
        """Return the source type of the device."""
        from homeassistant.components.device_tracker import SourceType

        # Default source type
        source_type = SourceType.ROUTER

        # Check for Bluetooth devices
        meta = self._raw_data.get("meta", {})
        if isinstance(meta, dict) and ("bluetooth" in meta or "bt" in meta):
            source_type = SourceType.BLUETOOTH

        # Check for GPS devices (unlikely in this integration, but included for completeness)
        if self._raw_data.get("gps") or self._raw_data.get("location"):
            source_type = SourceType.GPS

        return source_type

    @property
    def device_info(self):
        """Return device information for the device registry."""
        from homeassistant.helpers.device_registry import DeviceInfo

        # Generate a better name for the device
        device_name = self._generate_better_name()

        # Create device info
        info = DeviceInfo(
            identifiers={(DOMAIN, self._mac_address)},
            name=device_name,
            connections={("mac", self._mac_address)},
        )

        # Add manufacturer if available
        if self._raw_data.get("vendor"):
            info["manufacturer"] = self._raw_data["vendor"]

        # Add model if available
        if self._raw_data.get("device_model"):
            info["model"] = self._raw_data["device_model"]

        return info

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return device state attributes."""
        attributes = {
            # Only include essential attributes
            "host_name": self._raw_data.get("name") or f"device_{self._mac_address[-4:]}",
        }

        # Add last_seen timestamp if available
        if self._raw_data.get("last_seen"):
            attributes["last_seen"] = self._raw_data["last_seen"]

        # Add RSSI for wireless devices
        if self._raw_data.get("rssi"):
            attributes["rssi"] = self._raw_data["rssi"]

        return attributes

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return if entity is enabled by default."""
        return self.mac_address is not None

    def _generate_better_name(self) -> str:
        """Generate a better name for a device based on available information."""
        device_data = self._raw_data
        current_name = device_data.get("name") or f"Device {self._mac_address[-4:]}"

        # First priority: Use the device_friendly_name from mDNS if available
        device_friendly_name = device_data.get("device_friendly_name")
        if device_friendly_name and len(device_friendly_name) > 1:
            vendor = device_data.get("vendor")
            if vendor and len(vendor) > 1:
                return f"{device_friendly_name} ({vendor})"
            return device_friendly_name

        # Second priority: Use hostname
        name = device_data.get("name")
        if name and len(name) > 1 and not name.startswith("Device "):
            # Clean up the hostname - remove .local suffix
            hostname = name
            if hostname.endswith(".local"):
                hostname = hostname[:-6]
            # Note: Trailing dots are already removed when the device is created

            # If it's a UUID-like hostname and we have a device model, use that instead
            if (len(hostname) > 30 and "-" in hostname) or hostname.startswith("Android-"):
                device_model = device_data.get("device_model")
                if device_model:
                    vendor = device_data.get("vendor")
                    if vendor and len(vendor) > 1:
                        return f"{device_model} ({vendor})"
                    return device_model

            # If we also have vendor information, include it
            vendor = device_data.get("vendor")
            if vendor and len(vendor) > 1:
                return f"{hostname} ({vendor})"

            # Just the hostname is still good
            return hostname

        # Third priority: Use device model with vendor
        device_model = device_data.get("device_model")
        if device_model and len(device_model) > 1:
            vendor = device_data.get("vendor")
            if vendor and len(vendor) > 1:
                return f"{device_model} ({vendor})"
            return device_model

        # Fourth priority: If we have vendor but no good hostname
        vendor = device_data.get("vendor")
        if vendor and len(vendor) > 1:
            return f"{vendor} {self._mac_address[-4:]}"

        # No significant improvement possible
        return current_name

    @callback
    def async_process_update(self, device_data: dict[str, Any]) -> None:
        """Process device data update."""
        self._raw_data = device_data
        self._is_on = True
        self.async_write_ha_state()

    @callback
    def async_mark_offline(self) -> None:
        """Mark device as offline."""
        self._is_on = False
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        """Register state update callback."""
        # No need for callbacks as we're using the new signal structure
        pass
