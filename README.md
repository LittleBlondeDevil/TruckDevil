## Description

TruckDevil is an interface for interacting with Trucks that use J1939 for communications on the CANBUS.

## Requirements

### Hardware:

The CAN transciever in use is the Macchina M2 ([Under-the-Dash](https://www.macchina.cc/catalog/m2-boards/m2-under-dash))

A USB-A to Micro B Cable will be required to connect to the M2 with a laptop.

Additionally, an OBD-II to J1939 deutsch 9 pin adapter or splitter should be utilized, available on [Amazon](https://www.amazon.com/gp/product/B073DJN7FG/ref=ppx_yo_dt_b_asin_title_o05_s00?ie=UTF8&psc=1).

### Software:

[Python 3](https://www.python.org/downloads/) is required.

Additional software is required to flash the truckdevil_sketch firmware to the M2 (see Installation)

## Installation

Follow the first 3 steps included in the M2 [Arduino IDE Quick Start](https://docs.macchina.cc/m2-docs/arduino) guide
	1. Install the Arduino Desktop IDE
	2. Install the Macchina M2 Board Configuration
	3. Install drivers
Upload truckDevil_sketch.ino to the M2
	1. Ensure M2 is plugged in over USB and that it's selected as the active board. 
	```
	Tools > Board: "[...]" > Macchina M2
	```
	2. Select the serial port in use for the M2.
	```
	Tools > Port
	```
	3. Open the truckDevil_sketch.ino file and upload it to the M2.
	```
	Sketch > Upload
	```
	4. Once uploaded, disconnect M2 and plug back in.
Install pyserial for connecting to the M2 over python code:
	```
	$pip install pyserial
	```