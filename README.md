# Network Map - Home Assistant Custom Component

[![hacs_badge](https://img.shields.io/badge/HACS-Default-orange.svg)](https://github.com/custom-components/hacs)

Home Assistant custom component to track devices on your network by fetching data from your **ASUS router** via SSH.

## Important Notes

*   **This component is specifically designed for ASUS routers.** It might work on other routers with a similar firmware (like some ASUSWRT Merlin-based) that store device information in the same file paths, but compatibility is not guaranteed.
*   **You must enable SSH access on your router and allow login via username/password.** This is required for the component to connect and retrieve device data. See instructions below.

## Features

*   Creates `device_tracker` entities in Home Assistant for devices connected to your ASUS router.
*   Fetches device information via a secure SSH connection.
*   Provides detailed device information, including:
    *   MAC Address (used as unique ID)
    *   IP Address
    *   Hostname (Name)
    *   Vendor and Vendor Class
    *   Device Type and OS Type
    *   Online Status
    *   2.4 GHz or 5 GHz connection status
    *   RSSI (signal strength)
    *   Current TX/RX rates
    *   Connection Time
    *   Last Update Timestamp
*   Automatically discovers new devices as they connect to your network.
*   Smart device detection: Only adds devices that are online and have sufficient information (name and IP).
*   Integrates with the Home Assistant entity registry.
*   Configurable scan interval.
*   Robust error handling.

## Installation

### HACS (Recommended)

1. Go to HACS.
2. Click on "Integrations".
3. Click on the three dots in the top-right corner and select "Custom repositories".
4. Paste `https://github.com/esauvisky/networkmap` into "Repository" and select "Integration" as the category.
5. Click "Add".
6. Find "Network Map" in the list and install it.
7. Restart Home Assistant.

### Manual Installation

1. Copy the `networkmap` folder from this repository to your `custom_components` folder in your Home Assistant configuration directory.
2. Restart Home Assistant.

## Configuration

1. **Enable SSH on your ASUS router:**
    *   Log in to your router's web interface (usually `http://router.asus.com`).
    *   Go to **Administration** -> **System**.
    *   Set **Enable SSH** to `LAN Only` or `LAN + WAN` (less secure).
    *   Set **Allow SSH password login** to `Yes`.
    *   Click **Apply**.
    *   **Note:** The exact steps may vary slightly depending on your router model and firmware version.

2. **Configure the integration in Home Assistant:**
    *   Go to **Settings** -> **Devices & Services** -> **Integrations**.
    *   Click **+ Add Integration**.
    *   Search for "Network Map" and select it.
    *   Enter the following information:
        *   **Host:** The IP address of your router (e.g., 192.168.1.1).
        *   **Port:** The SSH port (default: 22).
        *   **Username:** Your router's SSH username (default: `admin`).
        *   **Password:** Your router's SSH password.
    *   Click **Submit**.
3. **(Optional) Configure the scan interval:**
    *   After adding the integration, click on **Options** in the Network Map integration card.
    *   Adjust the **Scan interval (seconds)** as desired (default: 60, minimum: 10). A shorter interval provides more up-to-date device status but consumes more resources.

## Usage

Once configured, the component will automatically create `device_tracker` entities for devices connected to your router. You can find these entities in the **Entities** list in Home Assistant.

**Note:** During the initial scan, the component will register all known MAC addresses in the entity registry, but will only create device tracker entities for devices that are currently online and have sufficient information (name and IP).

## Troubleshooting

*   **Error connecting to the router:**
    *   Ensure that SSH is enabled on your router and that you are using the correct IP address, port, username, and password.
    *   Check your router's firewall settings to make sure that SSH traffic is allowed.
*   **No devices are discovered:**
    *   Make sure that your router stores device information in the expected file paths (`/jffs/nmp_cl_json.js`, `/jffs/nmp_vc_json.js`, `/tmp/allwclientlist.json`, and `/tmp/nmp_cache.js`).
    *   Verify that the files contain data. You might need to SSH into your router and manually check the contents of these files.
    *   Check the Home Assistant logs for any error messages related to the `networkmap` component.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues on the GitHub repository.

## Disclaimer

This is a custom component and is not officially supported by Home Assistant or ASUS. Use it at your own risk.
