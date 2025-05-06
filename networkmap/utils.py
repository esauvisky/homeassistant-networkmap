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

from typing import Dict

# 1) Extended device-type → keywords map (checked in order)
TYPE_KEYWORDS = [
    ("mdi:cast",            ["cast", "chromecast", "dongle", "google tv"]),
    ("mdi:home-automation", ["homekit", "home assistant", "smartthings", "bridge"]),
    ("mdi:android-tv",      ["android tv", "android_tv", "fire tv", "firestick"]),
    ("mdi:television",      ["television", "tv", "roku", "apple tv", "samsung tv"]),
    ("mdi:chip",            ["esphome", "esp32", "esp8266", "espressif", "arduino"]),
    ("mdi:speaker",         ["sonos", "homepod", "speaker", "bose", "denon", "yamaha"]),
    ("mdi:lightbulb",       ["hue", "light", "philips", "lifx", "yeelight"]),
    ("mdi:cellphone",       ["pixel", "galaxy", "phone", "smartphone",
                             "oneplus"]),
    ("mdi:tablet-ipad",     ["ipad", "tablet", "galaxy tab", "surface go"]),
    ("mdi:laptop",          ["laptop", "notebook", "macbook", "xps",
                             "thinkpad", "surface book"]),
    ("mdi:desktop-classic", ["desktop", "pc", "imac", "mac mini", "mac pro"]),
    ("mdi:camera",          ["camera", "cctv", "ipcam", "webcam", "ring cam",
                             "arlo", "nest cam"]),
    ("mdi:printer",         ["printer", "epson", "canon", "brother", "hp"]),
    ("mdi:server",          ["server", "nas", "synology", "qnap", "unraid"]),
    ("mdi:router-network",  ["router", "gateway", "asus", "netgear",
                             "ubiquiti", "tp-link", "linksys"]),
    ("mdi:network",         ["switch", "repeater", "access point",
                             "unifi", "meraki", "bridge"]),
    ("mdi:thermostat",      ["thermostat", "nest thermostat",
                             "tado", "hive", "ecobee", "climate"]),
    ("mdi:lock",            ["lock", "smart lock", "schlage", "august",
                             "yale", "kwikset"]),
    ("mdi:light-switch",    ["switch", "smart switch", "sonoff", "kasa"]),
    ("mdi:power-plug",      ["plug", "outlet", "smart plug", "kasa",
                             "tp-link hs"]),
    ("mdi:fan",             ["fan", "ventilator"]),
    ("mdi:water-percent",   ["humidity", "humidifier", "hygrometer"]),
    ("mdi:thermometer",     ["temperature", "temp sensor", "thermometer"]),
    ("mdi:motion-sensor",   ["motion", "pir sensor", "presence"]),
    ("mdi:smoke-detector",  ["smoke", "co2", "carbon monoxide"]),
]

# 2) Fallback brand → icon map
VENDOR_ICONS = {
    "apple":        "mdi:apple",
    "amazon":       "mdi:amazon",
    "google":       "mdi:google",
    "samsung":      "mdi:samsung",
    "sony":         "mdi:sony",
    "microsoft":    "mdi:microsoft",
    "roku":         "mdi:roku",
    "playstation":  "mdi:playstation",
    "nintendo":     "mdi:nintendo-switch",
    "xbox":         "mdi:xbox",
    "ubiquiti":     "mdi:ubiquiti",
    "tp-link":      "mdi:router-network",
    "netgear":      "mdi:router-network",
    "huawei":       "mdi:cellphone",
    "lg":           "mdi:lg",
    "hp":           "mdi:printer",
    "dell":         "mdi:laptop",
    "canon":        "mdi:printer",
    "epson":        "mdi:printer",
    "brother":      "mdi:printer",
}

DEFAULT_ICON = "mdi:lan-connect"
FIELD_ORDER  = ["device_type", "device_model", "hostname", "vendor"]

def determine_icon(device_data: Dict[str, str]) -> str:
    """
    1) Try every (icon, keywords) in TYPE_KEYWORDS against
       device_type → device_model → hostname → vendor.
    2) If nothing matches, look for a brand in `vendor`.
    3) Else fall back to DEFAULT_ICON.
    """
    for icon, keywords in TYPE_KEYWORDS:
        for field in FIELD_ORDER:
            val = device_data.get(field, "")
            if not val:
                continue
            norm = val.replace("-", " ").lower()
            if any(kw in norm for kw in keywords):
                return icon

    vendor = device_data.get("vendor", "").lower()
    for brand, icon in VENDOR_ICONS.items():
        if brand in vendor:
            return icon

    return DEFAULT_ICON
