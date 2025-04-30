# Network Map - Home Assistant Custom Component

[![hacs_badge](https://img.shields.io/badge/HACS-Default-orange.svg)](https://github.com/custom-components/hacs)

Home Assistant custom component to track devices on your network by fetching data from **Bettercap** via its REST API.

## Important Notes

* **This component uses Bettercap for network scanning.** Bettercap is a powerful network tool that can discover devices on your network.
* **You must have Bettercap running and accessible from Home Assistant.** The component connects to Bettercap's API to retrieve device data.

## Features

* Creates `device_tracker` entities in Home Assistant for devices discovered on your network.
* Fetches device information via Bettercap's REST API.
* Provides detailed device information as entity attributes, including:
    * MAC Address (used as unique ID)
    * IP Address
    * Hostname (Name)
    * Vendor information
    * Online Status
    * Network traffic statistics
    * Signal strength (for wireless devices)
    * First and last seen timestamps
* Automatically discovers new devices as they connect to your network.
* Smart device detection: Only adds devices that are online and have sufficient information.
* Configurable scan types (probe, sniff, ARP spoofing).
* Configurable scan interval.
* Robust error handling.

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

## Setting up Bettercap

### Docker (Recommended)

The easiest way to run Bettercap is using Docker:

```yaml
version: '3'

services:
  bettercap:
    image: bettercap/bettercap:latest
    container_name: bettercap
    network_mode: host
    privileged: true
    restart: unless-stopped
    command: >
      -eval "set api.rest.address 0.0.0.0; 
             set api.rest.port 8081; 
             set api.rest.username user; 
             set api.rest.password your_secure_password; 
             api.rest on"
```

### Direct Installation

1. Install Bettercap on a Linux system (see [Bettercap installation guide](https://www.bettercap.org/installation/)).
2. Start Bettercap with API access:
   ```
   sudo bettercap -eval "set api.rest.address 0.0.0.0; set api.rest.port 8081; set api.rest.username user; set api.rest.password your_secure_password; api.rest on"
   ```

## Configuration

1. **Configure the integration in Home Assistant:**
    * Go to **Settings** -> **Devices & Services** -> **Integrations**.
    * Click **+ Add Integration**.
    * Search for "Network Map" and select it.
    * Enter the following information:
        * **Host:** The IP address of your Bettercap server.
        * **Port:** The API port (default: 8081).
        * **Username:** Bettercap API username.
        * **Password:** Bettercap API password.
        * **API Key:** Optional API token.
        * **Enable network probing:** Discovers devices on your network.
        * **Enable network sniffing:** Captures network traffic for more device info.
        * **Enable ARP spoofing:** Man-in-the-middle technique (use with caution).
        * **Enable ticker:** Periodic status updates in Bettercap.
    * Click **Submit**.

2. **(Optional) Configure the scan interval:**
    * After adding the integration, click on **Options** in the Network Map integration card.
    * Adjust the **Scan interval (seconds)** as desired (default: 30, minimum: 10).

## Usage

Once configured, the component will automatically create `device_tracker` entities for devices discovered on your network. You can find these entities in the **Entities** list in Home Assistant.

These entities can be used in automations, such as:
* Presence detection (home/away)
* Notifications when specific devices connect or disconnect
* Tracking guest devices on your network

## Troubleshooting

* **Error connecting to Bettercap:**
    * Ensure that Bettercap is running and that you are using the correct IP address, port, username, and password.
    * Check that your firewall allows connections to the Bettercap API port.
    * Verify Bettercap is running with proper permissions to scan the network.

* **No devices are discovered:**
    * Make sure network probing is enabled in the integration settings.
    * Check that Bettercap has permission to scan your network.
    * Some devices may go to sleep and not respond to network scans.
    * Try reducing the scan interval for more frequent updates.

* **For more detailed logs:**
    * Add this to your configuration.yaml:
      ```yaml
      logger:
        default: info
        logs:
          custom_components.networkmap: debug
      ```

## Security Considerations

* Network scanning tools like Bettercap should be used responsibly and only on networks you own or have permission to scan.
* ARP spoofing is a powerful technique that can disrupt network traffic. Only enable it if you understand the implications.
* Always secure your Bettercap instance with strong credentials.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues on the GitHub repository.

## Disclaimer

This is a custom component and is not officially supported by Home Assistant or Bettercap. Use it at your own risk.
