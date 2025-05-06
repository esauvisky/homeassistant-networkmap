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
from homeassistant.helpers.device_registry import DeviceInfo


from . import signal_device_new, signal_device_updated, signal_device_offline
from .const import DOMAIN
from .utils import get_short_manufacturer

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
        name = device_data.get("name") or f"Unknown {mac_address[-5:]}"
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
        raw_vendor = self._raw_data.get("vendor")
        if not raw_vendor:
            return None

        return get_short_manufacturer(raw_vendor)

    @property
    def icon(self) -> str:
        """Return the icon to use in the frontend."""
        from .utils import determine_icon
        return determine_icon(self._raw_data)


    @property
    def device_info(self):
        """Return device information for the device registry."""
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
        meta = self._raw_data.get("meta", {})

        # Determine model with priority order
        model = None
        if self._raw_data.get("device_model"):
            model = self._raw_data["device_model"]
        elif isinstance(meta, dict) and "mdns:md" in meta:
            model = meta["mdns:md"]
        elif (isinstance(meta, dict) and "mdns:platform" in meta
              and "mdns:board" in meta):
            model = f"{meta['mdns:platform']} ({meta['mdns:board']})"

        if model:
            info["model"] = model

        # Add firmware version if available
        if isinstance(meta, dict) and "mdns:version" in meta:
            info["sw_version"] = meta["mdns:version"]

        return info

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return device state attributes."""
        attributes = {
            # Only include essential attributes
            "host_name": self._raw_data.get("name") or f"device_{self._mac_address[-5:]}",
        }

        # Add last_seen timestamp if available
        if self._raw_data.get("last_seen"):
            attributes["last_seen"] = self._raw_data["last_seen"]


        return attributes

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return if entity is enabled by default."""
        return self.mac_address is not None

    def _generate_better_name(self) -> str:
        """Generate a better name for a device based on available information."""
        from .utils import generate_better_name
        return generate_better_name(self._raw_data, self._mac_address)

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
