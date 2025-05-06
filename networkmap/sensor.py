"""Sensor platform for Network Map integration."""
from __future__ import annotations

import logging
from typing import Any, Dict, Set, List, Optional, Callable

from homeassistant.components.sensor import (
    SensorEntity,
    SensorEntityDescription,
    SensorDeviceClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.device_registry import DeviceInfo

from . import signal_device_new, signal_device_updated, signal_device_offline
from .const import DOMAIN
from .utils import get_short_manufacturer

_LOGGER = logging.getLogger(__name__)

# Define sensor descriptions for diagnostic data
SENSOR_DESCRIPTIONS = [
    SensorEntityDescription(
        key="vendor",
        name="Vendor",
        icon="mdi:factory",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    SensorEntityDescription(
        key="device_model",
        name="Model",
        icon="mdi:devices",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
]


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up diagnostic sensors for Network Map."""
    _LOGGER.debug("Setting up sensor platform for entry %s", entry.entry_id)

    # Keep track of entities we've created
    tracked_sensors: Dict[str, Dict[str, NetworkMapDiagnosticSensor]] = {}

    @callback
    def handle_device_new(mac_address: str, device_data: dict[str, Any]):
        """Handle new device discovery."""
        _LOGGER.debug("Creating diagnostic sensors for device: %s", mac_address)

        # Create a sensor for each description
        new_entities = []

        # Initialize dictionary for this device if needed
        if mac_address not in tracked_sensors:
            tracked_sensors[mac_address] = {}

        for description in SENSOR_DESCRIPTIONS:
            # Create a unique ID for this sensor
            unique_id = f"{DOMAIN}_{entry.entry_id.split('-')[0]}_{mac_address}_{description.key}"

            # Skip if we already have this sensor
            if description.key in tracked_sensors.get(mac_address, {}):
                continue

            # Create the sensor entity
            sensor = NetworkMapDiagnosticSensor(
                entry_id=entry.entry_id,
                mac_address=mac_address,
                description=description,
                device_data=device_data,
            )

            # Add to our tracking dict
            tracked_sensors.setdefault(mac_address, {})[description.key] = sensor

            # Add to the list of entities to add
            new_entities.append(sensor)

        if new_entities:
            async_add_entities(new_entities)

    @callback
    def handle_device_updated(mac_address: str, device_data: dict[str, Any]):
        """Handle device data updates."""
        if mac_address not in tracked_sensors:
            # If we don't have sensors for this device yet, create them
            handle_device_new(mac_address, device_data)
            return

        # Update each sensor for this device
        for sensor in tracked_sensors[mac_address].values():
            sensor.async_process_update(device_data)

    @callback
    def handle_device_offline(mac_address: str):
        """Handle device going offline."""
        if mac_address in tracked_sensors:
            # Mark all sensors for this device as unavailable
            for sensor in tracked_sensors[mac_address].values():
                sensor.async_mark_unavailable()

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


class NetworkMapDiagnosticSensor(SensorEntity):
    """Diagnostic sensor for Network Map devices."""

    _attr_has_entity_name = True

    def __init__(
        self,
        entry_id: str,
        mac_address: str,
        description: SensorEntityDescription,
        device_data: dict[str, Any],
    ) -> None:
        """Initialize the sensor."""
        self.entity_description = description
        self._entry_id = entry_id
        self._mac_address = mac_address
        self._raw_data = device_data

        # Set unique ID
        short_entry_id = entry_id.split("-")[0]
        self._attr_unique_id = f"{DOMAIN}_{short_entry_id}_{mac_address}_{description.key}"

        # Process initial data
        self._extract_value_from_data()

        _LOGGER.debug(
            "Initializing diagnostic sensor: mac=%s, key=%s, unique_id=%s",
            mac_address, description.key, self._attr_unique_id
        )

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information for the device registry."""
        # Generate a better name for the device
        device_name = self._generate_better_name()

        # Create device info that links to the same device as the tracker
        return DeviceInfo(
            identifiers={(DOMAIN, self._mac_address)},
            name=device_name,
            connections={("mac", self._mac_address)},
            manufacturer=self._raw_data.get("vendor"),
            model=self._raw_data.get("device_model"),
        )

    def _generate_better_name(self) -> str:
        """Generate a better name for a device based on available information."""
        from .utils import generate_better_name
        return generate_better_name(self._raw_data, self._mac_address)


    def _extract_value_from_data(self) -> None:
        """Extract the sensor value from the device data based on the entity description key."""
        key = self.entity_description.key

        if key == "vendor":
            self._attr_native_value = self._raw_data.get("vendor")

        elif key == "os_type":
            self._attr_native_value = self._raw_data.get("os_type")

        elif key == "device_model":
            self._attr_native_value = self._raw_data.get("device_model")

        elif key == "rssi":
            rssi = self._raw_data.get("rssi")
            if rssi and rssi.isdigit():
                self._attr_native_value = int(rssi)
            else:
                self._attr_native_value = None

        elif key == "mdns_services":
            # Extract mDNS services from metadata
            services = []
            meta = self._raw_data.get("meta", {})
            if isinstance(meta, dict):
                for meta_key in meta.keys():
                    if meta_key.startswith("mdns:_") and meta_key.endswith(":name"):
                        service_name = meta_key.split(":")[1]
                        if service_name not in services:
                            services.append(service_name)

            if services:
                self._attr_native_value = ", ".join(services)
            else:
                self._attr_native_value = None


    @callback
    def async_process_update(self, device_data: dict[str, Any]) -> None:
        """Process device data update."""
        if self.hass is None:
            # Skip update if entity isn't fully initialized yet
            return
        self._raw_data = device_data
        self._extract_value_from_data()
        self.async_write_ha_state()

    @callback
    def async_mark_unavailable(self) -> None:
        """Mark sensor as unavailable."""
        if self.hass is None:
            # Skip update if entity isn't fully initialized yet
            return
        self._attr_available = False
        self.async_write_ha_state()
