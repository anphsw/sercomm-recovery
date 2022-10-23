This tool allows you to flash firmware into a Sercomm router after it
was put into download mode, e.g. if the original firmware was destroyed.
It runs under Linux only, you must be root to execute it.

## 1. Compile

make


## 2. Enter Download Mode

 1. Power off the device
 2. Press the RESET or WPS button (this depends on the router model)
 3. Power on while holding the button
 4. Wait 5 seconds or more until the LEDs blink in a special pattern depending on the router model.

If TTL console is connected, it will look like:
DEBUG_INF:===================================================
DEBUG_INF:Sercomm Upgrade(Module Ver 2.06.01.11) Start!
DEBUG_INF:===================================================


## 3. Run the Tool
Connect a LAN port to a NIC of the host, e.g. to eth1.


### 3.1. Probe the Device
`./sercomm-recovery -i eth1`

This should list some info about all device found in download mode.


### 3.1a. Specify device mac address to omit discovery (if discovery fails)
`./sercomm-recovery -i eth1 -d XX:XX:XX:XX:XX:XX`


### 3.1b. AND/OR change device mac address (optional, if it shows invalid or empty mac)
`./sercomm-recovery -i eth1 -d XX:XX:XX:XX:XX:XX -m XX:XX:XX:XX:XX:XX`


### 3.2. Flash
`./sercomm-recovery -i eth1 -f flash_burn.bin`

This probes for devices in download mode. If more than one found, it
prompts for the one to flash. A reboot is executed afterwards.

Warning! Some devices expect firmware with bootloader part or firmware without vendor headers.


## 4. Troubleshooting

If anything goes wrong with probing or flashing, please execute the command
again with "-v", e.g:

`./sercomm-recovery -v -i eth1 -f flash_burn.bin`

This adds a lot of debug output to stdout.


## 5. Status

In development, works with varoius Sercomm routers.
