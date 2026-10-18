#!/usr/bin/python3

"""
Script Name: adbWebView.py
Version: 1.0.0
Author: d0wn3rDav3

Description: 
This is just a simple script to invoke a WebView
request from a device connected via ADB. This 
script attempts to ensure that our websites are
handled appropriately within a WebView context.
"""

import subprocess
import time
from ppadb.client import Client as AdbClient

# Connect to ADB server
adb = AdbClient(host="127.0.0.1", port=5037)

# Get connected devices
devices = adb.devices()

if not devices:
    print("No devices connected.")
    exit()

# Display the list of connected devices and prompt the user to select one
print("Connected devices:")
for i, device in enumerate(devices):
    print(f"{i+1}. {device.serial}")

device_index = int(input("Enter the number corresponding to the device you want to select: ")) - 1

if device_index < 0 or device_index >= len(devices):
    print("Invalid device number.")
    exit()

# Select the device based on the user's input
selected_device = devices[device_index]

# Take input for URL to open
url_to_open = input("[?] Please enter full URL to open: ")

# Get current date and time for the log file name
current_time = time.strftime("%Y-%m-%d_%H-%M-%S")
log_file_name = f"logcat_output_{current_time}.txt"

# Specify the number of lines of Logcat output to capture
num_lines = 1000  # Change this to the desired number of lines

# Validate make and model of targeted device
make = selected_device.shell("getprop ro.product.manufacturer").strip()
model = selected_device.shell("getprop ro.product.model").strip()
serial = selected_device.shell("getprop ro.serialno").strip()
osVer = selected_device.shell("getprop ro.build.version.release").strip()

# Ensure you're attached to the correct device
print("#####################################")
print("# [+] Targeting the following device:")
print(f"# Device Make: {make}".title())
print(f"# Device Model: {model}")
print(f"# Device Serial Number: {serial}")
print(f"# Device OS Version: {osVer}")
print("#####################################")

# Kill any existing webviews
selected_device.shell("am force-stop com.android.chrome")

# Launch the WebView
selected_device.shell(f'am start --activity-clear-task -a android.intent.action.VIEW -d "{url_to_open}"')

# Start logging the Logcat output to a file
logcat_process = subprocess.Popen(["adb", "logcat", "-t", str(num_lines)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
with open(log_file_name, "wb") as f:
    for line in logcat_process.stdout:
        f.write(line)