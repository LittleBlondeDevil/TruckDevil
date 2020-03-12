## Description

TruckDevil is an interface for interacting with Trucks that use J1939 for communications on the CANBUS.

## Requirements

### Hardware:

The CAN transciever in use is the Macchina M2 ([Under-the-Dash](https://www.macchina.cc/catalog/m2-boards/m2-under-dash)).

A USB-A to Micro B Cable will be required to connect to the M2 with a laptop.

Additionally, an OBD-II to J1939 deutsch 9 pin adapter or splitter should be utilized, available on [Amazon](https://www.amazon.com/gp/product/B073DJN7FG/ref=ppx_yo_dt_b_asin_title_o05_s00?ie=UTF8&psc=1).

### Software:

[Python 3](https://www.python.org/downloads/) is required.

Additional software is required to flash the truckdevil_sketch firmware to the M2 (see Installation).

## Installation

- Follow the first 3 steps included in the M2 [Arduino IDE Quick Start](https://docs.macchina.cc/m2-docs/arduino) guide
	- Install the Arduino Desktop IDE
	- Install the Macchina M2 Board Configuration
	- Install drivers
- Upload truckDevil_sketch.ino to the M2
	- Ensure M2 is plugged in over USB and that it's selected as the active board. 
	```
	Tools > Board: "[...]" > Macchina M2
	```
	- Select the serial port in use for the M2 (usually named "Arduino Due").
	```
	Tools > Port
	```
	- Open the truckDevil_sketch.ino file and upload it to the M2.
	```
	Sketch > Upload
	```
	- Once uploaded, disconnect M2 and plug back in.
- Install pyserial for connecting to the M2 over python code:
	```
	$pip install pyserial
	```

## Usage

TruckDevil allows for reading messages, decoding them, saving them, and sending them.

### Command Line Tools

For simple tasks, such as reading and sending messages, there are two command line tools that can be utilized.

- Read Messages

```
> python readMessages.py -h

usage: readMessages.py [-h] [-s SERIAL_BAUD] [-t READ_TIME] [-n NUM_MESSAGES]
                       [-a] [-l] [-v]
                       port can_baud

read and print all messages from M2. If read_time and num_messages are both
specified, stop printing when whichever one is reached first.

positional arguments:
  port                  serial port that the M2 is connected to. For example:
                        COM7 or /dev/ttyX.
  can_baud              baud rate on the CAN BUS that the M2 is connected. For
                        example: 250000.

optional arguments:
  -h, --help            show this help message and exit
  -s SERIAL_BAUD, --serial_baud SERIAL_BAUD
                        baud rate of the serial connection to the M2. By
                        default it is 115200.
  -t READ_TIME, --read_time READ_TIME
                        the amount of time, in seconds, to print messages for.
                        If not specified, it will not be limited.
  -n NUM_MESSAGES, --num_messages NUM_MESSAGES
                        number of messages to print before stopping. If not
                        specified, it will not be limited.
  -a, --abstract_TPM    abstract Transport Protocol messages.
  -l, --log_to_file     log the messages to a file in the current directory
                        with the form 'm2_collected_data_[TIME]'.
  -v, --verbose         print the message in decoded form
```

- Send Message

```
> python sendMessage.py -h

usage: sendMessage.py [-h] [-s SERIAL_BAUD] [-p PRIORITY] [-a SRC_ADDR]
                      [-d DST_ADDR] [-v]
                      port can_baud pgn data

send message to M2 to get pushed to the BUS.

positional arguments:
  port                  serial port that the M2 is connected to. For example:
                        COM7 or /dev/ttyX.
  can_baud              baud rate on the CAN BUS that the M2 is connected. For
                        example: 250000.
  pgn                   range: 0x0000-0xFFFF (0-65535).
  data                  hex string of data to send, example: 0102030405060708.

optional arguments:
  -h, --help            show this help message and exit
  -s SERIAL_BAUD, --serial_baud SERIAL_BAUD
                        baud rate of the serial connection to the M2. Default:
                        115200.
  -p PRIORITY, --priority PRIORITY
                        range: 0x00-0x07 (0-7).
  -a SRC_ADDR, --src_addr SRC_ADDR
                        range: 0x00-0xFF (0-255).
  -d DST_ADDR, --dst_addr DST_ADDR
                        range: 0x00-0xFF (0-255), 0xFF is for broadcast
                        messages.
  -v, --verbose         print the message that was sent, use -vv to print the
                        decoded form of the message.
```

### Programmatic Uses

For more complicated tasks, TruckDevil can be used programmatically.

The first thing that must be done is to create a new python file within the project directory and import the truckDevil file:

```
import truckDevil
```

Next, serial communications and the truckDevil object can be created like so, passing in the serial port, the serial baud rate, and the CAN baud rate:

```
devil = truckDevil.TruckDevil('COM7', 115200, 250000)
```

The serial port could be 'COMX' on Windows or '/dev/ttyX' on Linux, corresponding to the port that the M2 is connected to.
The serial baud rate is defaulted to 115200, unless the truckDevil_sketch firmware file has been modified.
The CAN baud rate is dependent on the CANBUS that the M2 is connected to.

When finished, the connection can be closed with the following:

```
devil.done()
```


#### Reading Messages

To read and print all J1939 messages on the BUS, continually:

```
devil.printMessages()
```

The following optional parameters can be added and combined:

```
devil.printMessages(abstractTPM=False)	#don't abstract the Transport Protocol Messages, include every message

devil.printMessages(readTime=5.0)	#only read and print messages for 5 seconds

devil.printMessages(numMessages=100)	#only read and print 100 messages

devil.printMessages(verbose=True)	#includes decoded information about each message
```


To read and save all J1939 messages on the BUS, in a background thread:

```
devil.startDataCollection()		#start the collection of messages
time.sleep(5)				#sleep or do something while the messages are being collected
messages = devil.stopDataCollection()	#stops the background thread and returns the messages that were collected
devil.saveDataCollected(messages)	#saves the messages that were collected to a file
```

The following optional parameter can be added to the previous functions used:

```
devil.startDataCollection(abstractTPM=False)			#don't abstract the Transport Protocol Messages, include every message

devil.saveDataCollected(messages, fileName='myfile.txt')	#specify the file name to save to
devil.saveDataCollected(messages, verbose=True)			#includes decoded information about each message
```

To get the data collected in the current data collection thread:

```
devil.startDataCollection(abstractTPM=True)			#start the collection of messages
#do something here
messages = devil.getCurrentCollectedData()			#does not stop the background thread, simply returns the messages that have been collected so far
for m in messages:
	print(devil.getDecodedMessage(m))			#returns the verbose version of the message
#do something here
devil.stopDataCollection()					#stops the background thread and returns the messages that were collected
```


To read until a specific J1939 message is found on the BUS:

```
message, messages = devil.readMessagesUntil(target_pgn=0xFECA, target_src_addr=0x00)		#read until a message with pgn 0xFECA, originating from node addr 0, is found
for m in messages:
    print(str(m))
```

The following parameters can be added to readMessagesUntil. When more than one is added, the target message must have all attributes specified.

```
devil.readMessagesUntil(dataContains="0102ABECFF")		#the message must contain this hex string in the data portion
devil.readMessagesUntil(target_src_addr=0x00, target_dst_addr=0xF9)
devil.readMessagesUntil(target_pgn=0xFECA)
```

Both the J1939 message that was found is returned, as well as the list of messages that was collected while looking for it.

To import a file that was originally saved using saveDataCollected:

```
messages = devil.importDataCollected('m2_collected_data_1582310916')  #returns a list of J1939_Message objects
```

This would be useful for post-capture analysis and replaying.

#### Sending Messages

To create a standard J1939 message, use the J1939_Message class:

```
priority = 0x06
pgn = 0xF004
dst_addr = 0xFF
src_addr = 0xF9
data = "08FEFEFEFE00FFFE"
message = truckDevil.J1939_Message(priority, pgn, dst_addr, src_addr, data)	#takes in integers, except data which is a hex string
```

Next, send the created message:

```
devil.sendMessage(message)
```


To send a multipacket message, just pass the data string in it's entirety to J1939_Message:

```
priority = 0x06
pgn = 0xFECA
dst_addr = 0xFF
src_addr = 0xF9
data = "47FF5B00040171020E256F00030101080907"
message = truckDevil.J1939_Message(priority, pgn, dst_addr, src_addr, data)
devil.sendMessage(message)
```

The Transport Protocol will be handled automatically.

## Acknowledgments

Thank you Jeremy Daily for providing truck ECUs and other useful hardware. Additionally, the dataBitDecoding.json file was created and modified from resources contained within Jeremy's [TU-RP1210](https://github.com/Heavy-Vehicle-Networking-At-U-Tulsa/TU-RP1210) repo.

I would also like to make mention of another great tool available for CAN experimentations, [CanCat](https://github.com/atlas0fd00m/CanCat), developed by researchers at GRIMM.