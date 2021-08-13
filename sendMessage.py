import argparse
import truckDevil as td

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description='send message to M2 to get pushed to the BUS.')
    
    ap.add_argument("device_type", help="type of device to use. For example: m2 or socketcan.")
    ap.add_argument("port", help="serial port that the M2 is connected to, if used. For example: COM7 or /dev/ttyX. 0 if not using M2.")
    ap.add_argument("can_channel", help="CAN channel to send/receive on. For example: can0 or can1.")
    ap.add_argument("can_baud", type=int, help="baud rate on the CAN BUS. For example: 250000.")
    
    
    ap.add_argument("pgn", help="range: 0x0000-0xFFFF (0-65535).")
    ap.add_argument("data", help="hex string of data to send, example: 0102030405060708.")
    
    ap.add_argument("-p", "--priority", default='0x06', help="range: 0x00-0x07 (0-7).")
    ap.add_argument("-a", "--src_addr", default='0x00', help="range: 0x00-0xFF (0-255).")
    ap.add_argument("-d", "--dst_addr", default='0xFF', help="range: 0x00-0xFF (0-255), 0xFF is for broadcast messages.")
    ap.add_argument("-v", "--verbose", action="count", help="print the message that was sent, use -vv to print the decoded form of the message.")
    
    args = vars(ap.parse_args())

    if (args['pgn'].startswith('0x')):
        pgn = int(args['pgn'], 16)
    else:
        pgn = int(args['pgn'])
    
    if (args['priority'].startswith('0x')):
        priority = int(args['priority'], 16)
    else:
        priority = int(args['priority'])
        
    if (args['src_addr'].startswith('0x')):
        src_addr = int(args['src_addr'], 16)
    else:
        src_addr = int(args['src_addr'])
        
    if (args['dst_addr'].startswith('0x')):
        dst_addr = int(args['dst_addr'], 16)
    else:
        dst_addr = int(args['dst_addr'])
        
     
    devil = td.TruckDevil(args['device_type'], args['port'], args['can_channel'], args['can_baud'])
    
    
    message = td.J1939_Message(priority, pgn, dst_addr, src_addr, args['data'])
    devil.sendMessage(message)
    
    if(args['verbose'] != None and args['verbose'] == 1):
        print(str(message))
    elif(args['verbose'] != None and args['verbose'] >= 2):
        print(devil.getDecodedMessage(message))