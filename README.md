# TruckDevil

A framework for interacting with and assessing ECUs that use J1939 for communications on the CAN bus.

## Requirements

### Hardware

The recommended CAN transceiver is the Macchina M2 ([Under-the-Dash](https://www.macchina.cc/catalog/m2-boards/m2-under-dash)).

However, python-can is used so any [supported CAN interface](https://python-can.readthedocs.io/en/master/interfaces.html) (e.g. SocketCAN) will work. An OBD-II to J1939 deutsch 9-pin adapter or splitter may also be needed, available on [Amazon](https://www.amazon.com/dp/B073DJN7FG).

### Software

[Python 3](https://www.python.org/downloads/) is required.

Additional software is required to flash the m2_sketch firmware to the M2, if used (see Installation).

If you would like to read J1939 messages remotely, a TCP socket server can be set up to bridge M2 encoded messages to a remote client also running TruckDevil (see [Remote Socket Server](#remote-socket-server--client-sessions)).

## Installation

### From package indexes

Once TruckDevil is published, install it directly from PyPI.

CLI install with `uv`:

```bash
uv tool install truckdevil
truckdevil --version
```

One-shot execution with `uvx`:

```bash
uvx truckdevil --version
```

Library or local-environment install with `pip`:

```bash
pip install truckdevil
truckdevil --version
```

Optional pretty-printing support:

```bash
uv tool install 'truckdevil[pretty]'
pip install 'truckdevil[pretty]'
```

### With uv (recommended)

```bash
> git clone https://github.com/LittleBlondeDevil/TruckDevil.git
> cd TruckDevil
> uv sync
```

Run the CLI from the project environment:

```bash
> uv run truckdevil --version
> uv run truckdevil
```

### With pip / venv

```
> git clone https://github.com/LittleBlondeDevil/TruckDevil.git
> cd TruckDevil
> python -m venv venv
> venv\Scripts\activate        # Windows
> source venv/bin/activate     # Linux / macOS
> pip install -r requirements.txt
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

## Testing

From the repo root (uses a virtual CAN interface; no hardware required):

With `uv`:

```bash
> uv run pytest tests/ -v
```

With `pip` / `venv`:

```
> pip install pytest
> python -m pytest tests/ -v
```

See [tests/README.md](tests/README.md) for more detail.

## Usage

TruckDevil contains various modules for reading, sending, ECU discovery, and fuzzing. Additional modules can be added
for more specific tasks.

### Getting Started
* Interactively (example using M2; replace with `add_device virtual vcan0 250000` for no-hardware testing)
```
> uv run truckdevil
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
> uv run truckdevil add_device m2 can0 250000 COM5 run_module read_messages set num_messages 5 print_messages
18FECA00    06 FECA 00 --> FF [0008] 00FF00000000FFFF
0CF00400    03 F004 00 --> FF [0008] F87D7D000000F07D
18F00E00    06 F00E 00 --> FF [0008] FFFF285AFFFFFFFF
0CF00300    03 F003 00 --> FF [0008] D10000FFFFFF00FF
18FEDF00    06 FEDF 00 --> FF [0008] FE00FEFE7D0200FF
```

### Pretty Printing with pretty_j1939

TruckDevil can integrate with the `pretty_j1939` project to provide high-performance, colorized, and searchable J1939 message rendering.

The optional dependency can be installed with `pip install 'truckdevil[pretty]'` or `uv tool install 'truckdevil[pretty]'`.

#### Settings:
- `pretty` (boolean): Enable or disable pretty printing.
- `pretty_j1939_args` (string): Pass arguments directly to the `pretty_j1939` renderer
- `pretty_da_json` (string): Source for J1939 definitions. Use `<truckdevil>` (default) to sync from TruckDevil's internal JSON files, `""` (blank) to use `pretty_j1939`'s installed defaults, or provide a path to a consolidated `J1939db.json`.

#### Example:

```
(truckdevil.read_messages) set pretty true
(truckdevil.read_messages) set num_messages 4
(truckdevil.read_messages) print_messages
{"PGN":"Vehicle Dynamic Stability Control 2(61449)","SA":"Brakes - System Controller( 11)","DA":"All(255)","Bytes":"FFFFFFFFFFFFFFFF"}
{"PGN":"Vehicle Dynamic Stability Control 2(61449)","SA":"Brakes - System Controller( 11)","DA":"All(255)","Bytes":"FFFFFFFFFFFFFFFF"}
{"PGN":"Vehicle Dynamic Stability Control 2(61449)","SA":"Brakes - System Controller( 11)","DA":"All(255)","Bytes":"FFFFFFFFFFFFFFFF"}
{"PGN":"Vehicle Dynamic Stability Control 2(61449)","SA":"Brakes - System Controller( 11)","DA":"All(255)","Bytes":"FFFFFFFFFFFFFFFF"}
{"Summary":"graph LR; N11["Brakes - System Controller(11)"]; All["All(255)"]; N11 -- Vehicle Dynamic Stability Control 2(61449) --> All"}
```

### Custom Modules

TruckDevil supports three module sources:

1. Built-in modules bundled with TruckDevil
2. User module directories
3. Python packages that register entry-point plugins

Every module should expose either:

```
def main_mod(argv, device)
```

or an entry-point callable with the same `(argv, device)` signature.

- **argv** contains the list of arguments passed to the module 
- **device** contains the Device object passed to the module

### User Modules

Default user module directory:

```bash
~/.config/truckdevil/modules
```

Example module file:

```python
def main_mod(argv, device):
    print("hello from custom module", argv)
```

Run with the default user-module location:

```bash
truckdevil
list_modules
run_module my_module foo bar
```

Override the user module directory for a single run:

```bash
truckdevil --module-path /path/to/modules
truckdevil --module-path /path/to/modules run_module my_module foo bar
```

You can also set it with an environment variable:

```bash
export TRUCKDEVIL_MODULE_PATH=/path/to/modules
truckdevil
```

`TRUCKDEVIL_MODULE_PATH` accepts multiple directories separated by your platform path separator.

### Plugin Packages

TruckDevil also discovers modules from Python entry points in the `truckdevil.modules` group.

Example plugin package configuration in `pyproject.toml`:

```toml
[project.entry-points."truckdevil.modules"]
my_plugin = "truckdevil_my_plugin:main_mod"
```

After installing that package in the same environment as TruckDevil, the module will appear in `list_modules` and can be run with:

```bash
truckdevil run_module my_plugin
```

### In-Repo Modules

If you are developing inside the TruckDevil repository itself, you can still add built-in modules under:

```bash
truckdevil/modules/
```

That is still the right approach for changes intended to ship with the main project.

### J1939 API

Python docs are available in the j1939.py file. Existing modules provide example usage.

### Remote Socket Server & Client Sessions

If you want to access a CAN bus remotely (e.g. running on a vehicle testbed, single-board computer like a Raspberry Pi / BeagleBone, or remote Linux host), TruckDevil includes an M2-over-TCP bridge server and client connection support.

The bridge server ([`tcp/truckdevil-tcp`](tcp/truckdevil-tcp)) bridges a local Linux SocketCAN interface with a TCP socket, encoding frames into the M2 ASCII format. The TruckDevil client connects to the server over TCP and treats it identically to a local CAN hardware device.

#### 1. Configuring the Remote Server

On the remote Linux machine with CAN hardware (SocketCAN):

##### Manual execution:
```bash
# Display help and options
./tcp/truckdevil-tcp -h
usage: truckdevil-tcp [-h] [-v] bind_ip tcp_port

Bridge a SocketCAN interface <-> M2-over-TCP.

positional arguments:
  bind_ip        IP address to bind the server socket (e.g., 0.0.0.0 or 192.168.7.2)
  tcp_port       TCP port to listen on (e.g., 1234)

options:
  -h, --help     show this help message and exit
  -v, --verbose  Increase verbosity (-v for INFO, -vv for DEBUG)

# Example: Run server listening on all interfaces at port 1234
./tcp/truckdevil-tcp -v 0.0.0.0 1234
```

*Note: Running `truckdevil-tcp` requires privileges to manage CAN network links (root or `CAP_NET_ADMIN`).*

##### Running as a Systemd service:
A template unit file is provided at [`tcp/truckdevil-tcp.service`](tcp/truckdevil-tcp.service). To install and enable it:

```bash
# Copy binary and service definition
sudo cp tcp/truckdevil-tcp /usr/bin/truckdevil-tcp
sudo chmod +x /usr/bin/truckdevil-tcp
sudo cp tcp/truckdevil-tcp.service /etc/systemd/system/

# Edit IP/port in /etc/systemd/system/truckdevil-tcp.service if needed
sudo systemctl daemon-reload
sudo systemctl enable --now truckdevil-tcp.service
```

#### 2. Configuring the Client Session (TruckDevil REPL)

On your client machine running TruckDevil, configure the remote device session using `add_device` with the `m2:<ip_address>` interface syntax:

```text
(truckdevil) add_device m2:<server_ip> <channel> <baudrate> <tcp_port>
```

##### Interactive REPL Session Example:
```text
(truckdevil) add_device m2:192.168.7.2 can0 500000 1234
(truckdevil) list_device

***** CAN Device Info *****
Device Type: m2 encoder
TCP IP: 192.168.7.2
Port: 1234
CAN Channel: can0
Baud Rate: 500000

(truckdevil) use read_messages
(truckdevil.read_messages) set num_messages 10
(truckdevil.read_messages) set verbose True
(truckdevil.read_messages) print_messages
```

##### Command-Line One-Shot / Non-Interactive Client Example:
You can also launch TruckDevil and execute commands non-interactively in client mode:

```bash
truckdevil add_device m2:192.168.7.2 can0 500000 1234 run_module read_messages set num_messages 5 print_messages back quit
```

