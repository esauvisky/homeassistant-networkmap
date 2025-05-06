"""Sensor platform for Network Map integration."""
from __future__ import annotations

import logging
from typing import Any, Dict, Set, List, Optional, Callable, Protocol
import json

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

# Define custom sensor types
SENSOR_TYPE_MDNS_NAME = "mdns_friendly_name"
SENSOR_TYPE_MDNS_MODEL = "mdns_model"
SENSOR_TYPE_MDNS_HOSTNAME = "mdns_hostname"
SENSOR_TYPE_MDNS_SERVICE_ID = "mdns_service_id"
SENSOR_TYPE_FIRMWARE_VERSION = "firmware_version"
SENSOR_TYPE_MDNS_BOARD = "mdns_board"
SENSOR_TYPE_MDNS_PLATFORM = "mdns_platform"
SENSOR_TYPE_UPNP_SERVER = "upnp_server"
SENSOR_TYPE_NBNS_HOSTNAME = "nbns_hostname"
SENSOR_TYPE_MDNS_OTHER = "mdns_other_values"
SENSOR_TYPE_OTHER_PROTOCOLS = "other_protocol_values"

# Helper functions for value extraction
def get_mdns_value(device_data: Dict[str, Any], key: str) -> Any:
    """Get a value from the mdns metadata."""
    meta = device_data.get("meta", {})
    if isinstance(meta, dict):
        return meta.get(f"mdns:{key}")
    return None

def get_meta_value(device_data: Dict[str, Any], protocol: str, key: str) -> Any:
    """Get a value from metadata with protocol prefix."""
    meta = device_data.get("meta", {})
    if isinstance(meta, dict):
        return meta.get(f"{protocol}:{key}")
    return None

def has_mdns_key(device_data: Dict[str, Any], key: str) -> bool:
    """Check if device has a specific mdns key."""
    meta = device_data.get("meta", {})
    if isinstance(meta, dict):
        return f"mdns:{key}" in meta
    return False

def has_meta_key(device_data: Dict[str, Any], protocol: str, key: str) -> bool:
    """Check if device has a specific metadata key with protocol prefix."""
    meta = device_data.get("meta", {})
    if isinstance(meta, dict):
        return f"{protocol}:{key}" in meta
    return False

def has_any_meta_prefix(device_data: Dict[str, Any], prefix: str) -> bool:
    """Check if device has any metadata with given prefix."""
    meta = device_data.get("meta", {})
    if isinstance(meta, dict):
        return any(k.startswith(prefix) for k in meta.keys())
    return False

def get_other_mdns_values(device_data: Dict[str, Any]) -> str:
    """Get all mdns values that aren't explicitly handled."""
    meta = device_data.get("meta", {})
    if not isinstance(meta, dict):
        return "{}"

    # Keys that are already handled by specific sensors
    handled_keys = {
        "mdns:fn", "mdns:friendly_name", "mdns:md", "mdns:hostname",
        "mdns:id", "mdns:version", "mdns:board", "mdns:platform"
    }

    # Collect all other mdns values
    other_values = {}
    for k, v in meta.items():
        if k.startswith("mdns:") and k not in handled_keys:
            other_values[k] = v

    return json.dumps(other_values, sort_keys=True)

def get_non_mdns_values(device_data: Dict[str, Any]) -> str:
    """Get all non-mdns metadata values."""
    meta = device_data.get("meta", {})
    if not isinstance(meta, dict):
        return "{}"

    # Collect all non-mdns values
    other_values = {}
    for k, v in meta.items():
        if not k.startswith("mdns:") and not k.startswith("_"):
            other_values[k] = v

    return json.dumps(other_values, sort_keys=True)

def should_create_sensor(sensor_type: str, device_data: Dict[str, Any]) -> bool:
    """Determine if a sensor should be created for this device."""
    if sensor_type == SENSOR_TYPE_MDNS_NAME:
        return has_mdns_key(device_data, "fn") or has_mdns_key(device_data, "friendly_name")

    elif sensor_type == SENSOR_TYPE_MDNS_MODEL:
        return has_mdns_key(device_data, "md")

    elif sensor_type == SENSOR_TYPE_MDNS_HOSTNAME:
        return has_mdns_key(device_data, "hostname")

    elif sensor_type == SENSOR_TYPE_MDNS_SERVICE_ID:
        return has_mdns_key(device_data, "id")

    elif sensor_type == SENSOR_TYPE_FIRMWARE_VERSION:
        return has_mdns_key(device_data, "version")

    elif sensor_type == SENSOR_TYPE_MDNS_BOARD:
        return has_mdns_key(device_data, "board")

    elif sensor_type == SENSOR_TYPE_MDNS_PLATFORM:
        return has_mdns_key(device_data, "platform")

    elif sensor_type == SENSOR_TYPE_UPNP_SERVER:
        return has_meta_key(device_data, "upnp", "Server")

    elif sensor_type == SENSOR_TYPE_NBNS_HOSTNAME:
        return has_meta_key(device_data, "nbns", "hostname")

    elif sensor_type == SENSOR_TYPE_MDNS_OTHER:
        return has_any_meta_prefix(device_data, "mdns:")

    elif sensor_type == SENSOR_TYPE_OTHER_PROTOCOLS:
        return isinstance(device_data.get("meta"), dict) and bool(device_data.get("meta"))

    # Default sensors like vendor and device_model are always created
    return True

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
    # mDNS Friendly Name
    SensorEntityDescription(
        key=SENSOR_TYPE_MDNS_NAME,
        name="mDNS Reported Name",
        icon="mdi:tag-text",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    # mDNS Model
    SensorEntityDescription(
        key=SENSOR_TYPE_MDNS_MODEL,
        name="mDNS Reported Model",
        icon="mdi:devices",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    # mDNS Hostname
    SensorEntityDescription(
        key=SENSOR_TYPE_MDNS_HOSTNAME,
        name="mDNS Hostname",
        icon="mdi:web",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    # mDNS Service ID
    SensorEntityDescription(
        key=SENSOR_TYPE_MDNS_SERVICE_ID,
        name="mDNS Service ID",
        icon="mdi:identifier",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    # Firmware Version
    SensorEntityDescription(
        key=SENSOR_TYPE_FIRMWARE_VERSION,
        name="Firmware Version (mDNS)",
        icon="mdi:chip",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=True,
    ),
    # ESPHome Board
    SensorEntityDescription(
        key=SENSOR_TYPE_MDNS_BOARD,
        name="mDNS Board",
        icon="mdi:circuit-board",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    # ESPHome Platform
    SensorEntityDescription(
        key=SENSOR_TYPE_MDNS_PLATFORM,
        name="mDNS Platform",
        icon="mdi:chip",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    # UPnP Server
    SensorEntityDescription(
        key=SENSOR_TYPE_UPNP_SERVER,
        name="UPnP Server",
        icon="mdi:server",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    # NetBIOS Name
    SensorEntityDescription(
        key=SENSOR_TYPE_NBNS_HOSTNAME,
        name="NetBIOS Name",
        icon="mdi:microsoft-windows",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    # Other mDNS Values
    SensorEntityDescription(
        key=SENSOR_TYPE_MDNS_OTHER,
        name="Additional mDNS Data",
        icon="mdi:code-json",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    # Other Protocol Values
    SensorEntityDescription(
        key=SENSOR_TYPE_OTHER_PROTOCOLS,
        name="Additional Protocol Data",
        icon="mdi:code-json",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
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
            # Skip if we already have this sensor
            if description.key in tracked_sensors.get(mac_address, {}):
                continue
                
            # Check if this sensor should exist for this device
            if not should_create_sensor(description.key, device_data):
                # Skip this sensor if the data doesn't exist
                continue

            # Create a unique ID for this sensor
            unique_id = f"{DOMAIN}_{entry.entry_id.split('-')[0]}_{mac_address}_{description.key}"

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
