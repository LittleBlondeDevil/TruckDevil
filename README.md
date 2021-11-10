## Description

TruckDevil is a framework for interacting with and assessing ECUs that use J1939 for communications on the CANBUS.

## Requirements

### Hardware:

The recommended CAN transciever to use is the Macchina M2 ([Under-the-Dash](https://www.macchina.cc/catalog/m2-boards/m2-under-dash)).

However, python-can is used so hardware devices with any of the supported interfaces, such as SocketCAN, could be used: ([CAN Interface Modules](https://python-can.readthedocs.io/en/master/interfaces.html)).

Additionally, an OBD-II to J1939 deutsch 9 pin adapter or splitter could be utilized, available on [Amazon](https://www.amazon.com/gp/product/B073DJN7FG/ref=ppx_yo_dt_b_asin_title_o05_s00?ie=UTF8&psc=1).

### Software:

[Python 3](https://www.python.org/downloads/) is required.

Additional software is required to flash the m2_sketch firmware to the M2, if used (see Installation).

## Installation
```
> git clone https://github.com/LittleBlondeDevil/TruckDevil.git
```
### M2 (if used)

- Follow the first 3 steps included in the M2 [Arduino IDE Quick Start](https://docs.macchina.cc/m2-docs/arduino) guide
    - Install the Arduino Desktop IDE
    - Install the Macchina M2 Board Configuration
    - Install drivers
- Download and include due_can and can_common libraries from collin80 into IDE
    - [due_can](https://github.com/collin80/due_can)
    - [can_common](https://github.com/collin80/can_common)
    ```
    Sketch > Include Library > Add .Zip Library...
    ```
- Upload m2_sketch.ino to the M2
    - Ensure M2 is plugged in over USB and that it's selected as the active board. 
    ```
    Tools > Board: "[...]" > Arduino Due (Native USB Port)
    ```
    - Select the serial port in use for the M2 (usually named "Arduino Due").
    ```
    Tools > Port
    ```
    - Open the m2_sketch.ino file and upload it to the M2.
    ```
    Sketch > Upload
    ```
    - Once uploaded, disconnect M2 and plug back in.

## Usage

TruckDevil contains various modules for reading, sending, ECU discovery, and fuzzing. Additional modules can be added
for more specific tasks.

### Getting Started
* Interactively 
```
> python truckdevil.py
Welcome to the truckdevil framework
(truckdevil)?

Documented commands (type help <topic>):
========================================
add_device  help  list_device  list_modules  run_module

(truckdevil)add_device m2 can0 250000 COM5
(truckdevil)list_device

***** CAN Device Info *****
Device Type: m2
Serial Port: COM5
CAN Channel: can0
Baud Rate: 250000

(truckdevil)list_modules
ecu_discovery
j1939_fuzzer
read_messages
send_messages

(truckdevil)run_module read_messages
Welcome to the Read Messages tool.
(truckdevil.read_messages) ?

Documented commands (type help <topic>):
========================================
help  load  print_messages  save  set  settings  unset

(truckdevil.read_messages) ? set

        Provide a setting name and a value to set the setting. For a list of
        available settings and their current and default values see the
        settings command.

        example:
        set read_time 10
        set filter_src_addr 11,249

(truckdevil.read_messages) set num_messages 5
(truckdevil.read_messages) print_messages
18FECA00    06 FECA 00 --> FF [0008] 00FF00000000FFFF
0CF00400    03 F004 00 --> FF [0008] F87D7D000000F07D
18F00E00    06 F00E 00 --> FF [0008] FFFF285AFFFFFFFF
0CF00300    03 F003 00 --> FF [0008] D10000FFFFFF00FF
18FEDF00    06 FEDF 00 --> FF [0008] FE00FEFE7D0200FF
```
* From command line (arguments are passed to module)
```
> python .\truckdevil.py add_device m2 can0 250000 COM5 run_module read_messages set num_messages 5 print_messages
18FECA00    06 FECA 00 --> FF [0008] 00FF00000000FFFF
0CF00400    03 F004 00 --> FF [0008] F87D7D000000F07D
18F00E00    06 F00E 00 --> FF [0008] FFFF285AFFFFFFFF
0CF00300    03 F003 00 --> FF [0008] D10000FFFFFF00FF
18FEDF00    06 FEDF 00 --> FF [0008] FE00FEFE7D0200FF
```

### Custom Modules

Create custom modules by creating a python file in the 'modules' folder. 
The file should contain the following function:
```
def main_mod(argv, device)
```
- <b>argv</b> contains the list of arguments passed to the module 
- <b>device</b> contains the Device object passed to the module

### J1939 API

Python docs are available in the j1939.py file. Existing modules provide example usage.

