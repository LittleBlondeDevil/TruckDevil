#include <due_can.h>

#define Serial SerialUSB

int filter;


void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
  while(Serial.available() <= 0);
  char tempbuf[8];
  Serial.readBytes(tempbuf, 7); //read the baud rate (ex: 0250000)
  long baud_rate = strtol(tempbuf, 0 ,10);
  Can0.begin(baud_rate);
  //Can0.begin(250000);
  
  //accept extended CAN frames
  for (filter = 0; filter < 3; filter++) {
    Can0.setRXFilter(filter, 0, 0, true);
  }
}

void passFrameToSerial(CAN_FRAME &frame) {
   if (frame.extended == true) {
     Serial.print("$"); //start delimiter
     if(frame.id <0x10000000) {Serial.print("0");}//adds leading zero if needed, to ensure 8 digits
     Serial.print(frame.id, HEX); //id (ex: 18ECFFF9
     Serial.print("0"); //adds leading zero to ensure 2 digits
     Serial.print(frame.length, HEX); //length (ex: 08)
     for (int count = 0; count < frame.length; count++) {
         if (frame.data.bytes[count] <0x10) {Serial.print("0");} //adds leading zero if needed, to ensure 2 digits is always sent
         Serial.print(frame.data.bytes[count], HEX); //the data (ex: 0102030405060708)
     }
     Serial.print("*"); //end delimiter
   }
}

CAN_FRAME passFrameFromSerial() {
  CAN_FRAME outgoing;
  outgoing.extended = 1;
  
  char c;
  char message[27]; //full message (ex: '18EF0B00080102030405060708')
  char start_delim = '$';
  char end_delim = '*';
  char tempbuf[17];
  byte ndx = 0;
  
  c = char(Serial.read());
  if (c == start_delim) { //start of new message
    while (Serial.available() > 0) {
      if (Serial.peek() == start_delim || ndx >= 27) {
        //ignore, misalignment happened, return frame indicating error
        outgoing.id = -1;
        return outgoing;
      }
      c = Serial.read();
      if (c == end_delim && ndx == 26) {
        message[26] = '\0';
        memcpy(tempbuf, &message[0], 8); //pull the 8 digit id out (18EF0B00)
        tempbuf[8] = '\0';
        outgoing.id = strtol(tempbuf, 0 ,16);
    
        memcpy(tempbuf, &message[8], 2); //pull the 2 digit DLC out)
        tempbuf[2] = '\0';
        outgoing.length = strtol(tempbuf, 0, 16);
    
        for (int count = 0; count < 8; count++) {
          memcpy(tempbuf, &message[10 + (count*2)], 2); //pull one byte out at a time of data)
          tempbuf[2] = '\0';
          outgoing.data.byte[count] = strtol(tempbuf, 0, 16);
        }
        return outgoing;
      }
      message[ndx] = c;
      ndx++;
    }

  } else {
    //ignore, misalignment happened, return frame indicating error
    outgoing.id = -1;
    return outgoing;
  }
}

void loop() {
  // put your main code here, to run repeatedly:
  CAN_FRAME incoming;
  CAN_FRAME outgoing;
  //if there's an incoming CAN message to read from M2, pass it to Serial
  if (Can0.available() > 0) {
	Can0.read(incoming);
	passFrameToSerial(incoming);
  }
  //if there's a message from Serial, pass it to M2 CAN transceiver
  if (Serial.available() > 0) {
	outgoing = passFrameFromSerial();
	if (outgoing.id != -1) { //no errors occurred
	  Can0.sendFrame(outgoing);
	}
  }
}
