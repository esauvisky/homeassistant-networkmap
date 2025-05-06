"""Utility functions for the Network Map integration."""

def get_short_manufacturer(raw_vendor: str) -> str:
    """Get the short version of the manufacturer name."""
    if raw_vendor:
        raw_vendor_lower = raw_vendor.lower()
        if "xiaomi" in raw_vendor_lower:
            return "Xiaomi"
        elif "apple" in raw_vendor_lower:
            return "Apple"
        elif "samsung" in raw_vendor_lower:
            return "Samsung"
        elif "google" in raw_vendor_lower:
            return "Google"
        elif "microsoft" in raw_vendor_lower:
            return "Microsoft"
        elif "sonos" in raw_vendor_lower:
            return "Sonos"
        elif "philips" in raw_vendor_lower:
            return "Philips"
        elif "esphome" in raw_vendor_lower:
            return "ESPHome"
        elif "homekit" in raw_vendor_lower:
            return "HomeKit"
        elif "raspberry" in raw_vendor_lower:
            return "Raspberry Pi"
        elif "asus" in raw_vendor_lower:
            return "ASUS"
        elif "amazon" in raw_vendor_lower:
            return "Amazon"
        elif "tuya" in raw_vendor_lower:
            return "Tuya"
    return raw_vendor

def generate_better_name(device_data: dict, mac_address: str) -> str:
    """Generate a better name for a device based on available information."""
    current_name = device_data.get("name") or f"Device {mac_address[-4:]}"

    # First priority: Use the device_friendly_name from mDNS if available
    device_friendly_name = device_data.get("device_friendly_name")
    if device_friendly_name and len(device_friendly_name) > 1:
        raw_vendor = device_data.get("vendor")
        if raw_vendor and len(raw_vendor) > 1:
            # Use the short version of the manufacturer
            vendor = get_short_manufacturer(raw_vendor)
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
                raw_vendor = device_data.get("vendor")
                if raw_vendor and len(raw_vendor) > 1:
                    vendor = get_short_manufacturer(raw_vendor)
                    return f"{device_model} ({vendor})"
                return device_model

        # If we also have vendor information, include it
        raw_vendor = device_data.get("vendor")
        if raw_vendor and len(raw_vendor) > 1:
            # Use the short version of the manufacturer
            vendor = get_short_manufacturer(raw_vendor)
            return f"{hostname} ({vendor})"

        # Just the hostname is still good
        return hostname

    # Third priority: Use device model with vendor
    device_model = device_data.get("device_model")
    if device_model and len(device_model) > 1:
        raw_vendor = device_data.get("vendor")
        if raw_vendor and len(raw_vendor) > 1:
            # Use the short version of the manufacturer
            vendor = get_short_manufacturer(raw_vendor)
            return f"{device_model} ({vendor})"
        return device_model

    # Fourth priority: If we have vendor but no good hostname
    raw_vendor = device_data.get("vendor")
    if raw_vendor and len(raw_vendor) > 1:
        # Use the short version of the manufacturer
        vendor = get_short_manufacturer(raw_vendor)
        return f"{vendor} {mac_address[-4:]}"

    # No significant improvement possible
    return current_name

def determine_icon(device_data: dict) -> str:
    """Determine the icon to use based on device data."""
    # Default icon
    icon = "mdi:lan-connect"

    # We no longer check for wireless data

    # Check for Bluetooth devices
    meta = device_data.get("meta", {})
    if isinstance(meta, dict) and ("bluetooth" in meta or "bt" in meta):
        icon = "mdi:bluetooth"

    # Check for specific device types based on vendor
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
    device_type = device_data.get("device_type")
    if device_type == "cast":
        icon = "mdi:cast"
    elif device_type == "esphome":
        icon = "mdi:chip"
    elif device_type == "homekit":
        icon = "mdi:home-automation"
    elif device_type == "android_tv":
        icon = "mdi:android-tv"

    return icon
