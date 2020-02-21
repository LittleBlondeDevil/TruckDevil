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
	- Select the serial port in use for the M2.
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

## Useage

TruckDevil allows for reading messages, decoding them, saving them, and sending them.

The first thing that must be done is to create a new python file and import the truckDevil file:

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


### Reading Messages

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


To find a specific J1939 message on the BUS:

```
devil.startDataCollection(abstractTPM=True)			#start the collection of messages

found = False
while not found:
	messages = devil.getCurrentCollectedData()		#does not stop the background thread, simply returns the messages that have been collected so far
	for m in messages:					#iterate through the messages
		if (m.pgn == 0xf004):				#if the message we care about is in the messages list
			print(devil.getDecodedMessage(m))	#returns the verbose version of the message
			found = True
			break
devil.stopDataCollection()					#stops the background thread and returns the messages that were collected
```


### Sending Messages

To create a standard J1939 message, use the J1939_Message class:

```
priority = 0x06
pgn = 0xF004
dst_addr = 0x00
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
dst_addr = 0x00
src_addr = 0xF9
data = "47FF5B00040171020E256F00030101080907"
message = truckDevil.J1939_Message(priority, pgn, dst_addr, src_addr, data)
devil.sendMessage(message)
```

The Transport Protocol will be handled automatically.

### Acknowledgments

Thank you Jeremy Daily for providing truck ECUs and other useful tools. Additionally, the dataBitDecoding.json file was created and modified from resources contained within Jeremy's TU-RP1210 [repo](https://github.com/Heavy-Vehicle-Networking-At-U-Tulsa/TU-RP1210).

I would also like to make mention of another great tool available for CAN experimentations, [CANCAT](https://github.com/atlas0fd00m/CanCat), developed by researchers at GRIMM.