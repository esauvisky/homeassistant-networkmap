#!/usr/bin/env python3
import json
import subprocess
import time
import paramiko
import json
import subprocess
import time
import paramiko

def get_device_data(ssh_client):
    """
    Retrieves and parses device data from the router using SSH, including data from /tmp/nmp_cache.js.

    Args:
        ssh_client: An established paramiko SSHClient object.

    Returns:
        A dictionary containing device information, or None if an error occurs.
    """
    try:
        # Read and parse /jffs/nmp_cl_json.js
        _, stdout, stderr = ssh_client.exec_command("cat /jffs/nmp_cl_json.js")
        cl_json_str = stdout.read().decode()
        if stderr.read():
            print(f"Error reading /jffs/nmp_cl_json.js: {stderr.read().decode()}")
            return None

        cl_json = json.loads(cl_json_str)

        # Read and parse /jffs/nmp_vc_json.js
        _, stdout, stderr = ssh_client.exec_command("cat /jffs/nmp_vc_json.js")
        vc_json_str = stdout.read().decode()
        if stderr.read():
            print(f"Error reading /jffs/nmp_vc_json.js: {stderr.read().decode()}")
            return None

        vc_json = json.loads(vc_json_str)

        # Read and parse /tmp/allwclientlist.json
        _, stdout, stderr = ssh_client.exec_command("cat /tmp/allwclientlist.json")
        allw_json_str = stdout.read().decode()
        if stderr.read():
            print(f"Error reading /tmp/allwclientlist.json: {stderr.read().decode()}")
            return None

        allw_json = json.loads(allw_json_str)

        # Read and parse /tmp/nmp_cache.js
        _, stdout, stderr = ssh_client.exec_command("cat /tmp/nmp_cache.js")
        cache_json_str = stdout.read().decode()
        if stderr.read():
            print(f"Error reading /tmp/nmp_cache.js: {stderr.read().decode()}")
            return None

        cache_json = json.loads(cache_json_str)

        # Combine data from all files
        devices = {}
        for mac, data in cl_json.items():
            devices[mac] = data
            devices[mac]["online"] = False  # Default to offline, update later
            devices[mac]["2G"] = False
            devices[mac]["5G"] = False

            # Update vendorclass from vc_json if available
            if mac in vc_json:
                devices[mac]["vendorclass"] = vc_json[mac]["vendorclass"]

        # Update online status and band info from allwclientlist.json
        for interface, bands in allw_json.items():
            for band, macs in bands.items():
                for mac, _ in macs.items():
                    if mac in devices:
                        devices[mac]["online"] = True
                        if band == "2G":
                            devices[mac]["2G"] = True
                        elif band == "5G":
                            devices[mac]["5G"] = True

        # Update data from nmp_cache.js
        for mac, data in cache_json.items():
            if mac != "maclist":
                if mac not in devices:
                    devices[mac] = {}

                # Check if data is a dictionary before updating
                if isinstance(data, dict):
                    devices[mac].update(data)
                else:
                    print(f"Warning: Data for MAC {mac} in nmp_cache.js is not a dictionary. Skipping update for this device.")

                # Ensure 'online' key exists after update from cache
                if "online" not in devices[mac]:
                    devices[mac]["online"] = False

                # Check if the device is online based on nmp_cache.js
                if "isOnline" in data and data["isOnline"] == "1":
                    devices[mac]["online"] = True

        return devices

    except Exception as e:
        print(f"Error processing device data: {e}")
        return None

def print_device_info(devices):
    """
    Prints formatted device information.

    Args:
        devices: A dictionary of device information.
    """
    if not devices:
        print("No device data available.")
        return

    print("-" * 40)
    for mac, data in devices.items():
        print(f"MAC: {mac}")
        print(f"  Name: {data.get('name', 'N/A')}")
        print(f"  IP: {data.get('ip', 'N/A')}")
        print(f"  Vendor: {data.get('vendor', 'N/A')}")
        print(f"  Vendor Class: {data.get('vendorclass', 'N/A')}")
        print(f"  Type: {data.get('type', 'N/A')}")
        print(f"  OS Type: {data.get('os_type', 'N/A')}")
        print(f"  Online: {data.get('online', False)}")
        print(f"  2G: {data.get('2G', False)}")
        print(f"  5G: {data.get('5G', False)}")
        print(f"  RSSI: {data.get('rssi', 'N/A')}")
        print(f"  Current TX Rate: {data.get('curTx', 'N/A')}")
        print(f"  Current RX Rate: {data.get('curRx', 'N/A')}")
        print(f"  Connection Time: {data.get('wlConnectTime', 'N/A')}")
        print("-" * 40)

def main():
    """
    Main function to periodically retrieve and display device information.
    """
    ssh_host = "192.168.1.1"
    ssh_user = "admin"
    ssh_password = "your_password"  # Replace with your actual password
    ssh_port = 22

    try:
        # Establish SSH connection
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_password)

        while True:
            devices = get_device_data(ssh_client)
            print_device_info(devices)
            time.sleep(60)  # Wait for 60 seconds (adjust as needed)

    except Exception as e:
        print(f"Error: {e}")
    finally:
        if ssh_client:
            ssh_client.close()

if __name__ == "__main__":
    main()