import argparse
from j1939.j1939 import J1939Interface, J1939Message
#from libs.device import Device


def get_vals_from_args(args):
    if args['pgn'].startswith('0x'):
        pgn = int(args['pgn'], 16)
    else:
        pgn = int(args['pgn'])

    if args['priority'].startswith('0x'):
        priority = int(args['priority'], 16)
    else:
        priority = int(args['priority'])

    if args['src_addr'].startswith('0x'):
        src_addr = int(args['src_addr'], 16)
    else:
        src_addr = int(args['src_addr'])

    if args['dst_addr'].startswith('0x'):
        dst_addr = int(args['dst_addr'], 16)
    else:
        dst_addr = int(args['dst_addr'])
    return pgn, priority, src_addr, dst_addr


def main_mod(argv, device=None):
    print("\n***** Send Message *****")
    print("Send message to CAN device to get pushed to the BUS.")
    ap = argparse.ArgumentParser(usage="pgn data [-h] [-p PRIORITY] [-a SRC_ADDR] [-d DST_ADDR] [-v]")
    ap.add_argument("pgn", help="range: 0x0000-0xFFFF (0-65535).")
    ap.add_argument("data", help="hex string of data to send, example: 0102030405060708.")

    ap.add_argument("-p", "--priority", default='0x06', help="range: 0x00-0x07 (0-7).")
    ap.add_argument("-s", "--src_addr", default='0x00', help="range: 0x00-0xFF (0-255).")
    ap.add_argument("-d", "--dst_addr", default='0xFF',
                    help="range: 0x00-0xFF (0-255), 0xFF is for broadcast messages.")
    ap.add_argument("-v", "--verbose", action="count",
                    help="print the message that was sent, use -vv to print the decoded form of the message.")
    ap.print_help()
    while True:
        arg_input = input("Args (q to return) > ")
        if arg_input == "q" or arg_input == "quit" or arg_input == "exit":
            return
        try:
            args = vars(ap.parse_args(arg_input.split()))
            pgn, priority, src_addr, dst_addr = get_vals_from_args(args)
            #message = J1939Message(priority, pgn, dst_addr, src_addr, args['data'])
            # TODO: make this based on user input again
            devil = J1939Interface(device)
            message = J1939Message(0x18EF0BF9, "1122334455667788")
        except (SystemExit, ValueError) as e:
            print(e)
            continue
        devil.send_message(message)
        if args['verbose'] is not None and args['verbose'] == 1:
            print(str(message))
        elif args['verbose'] is not None and args['verbose'] >= 2:
            print(devil.get_decoded_message(message))


def main():
    ap = argparse.ArgumentParser(description='send message to CAN device to get pushed to the BUS.')

    ap.add_argument("device_type", help="type of device to use. For example: m2 or socketcan.")
    ap.add_argument("port",
                    help="serial port that the M2 is connected to, if used. For example: COM7 or /dev/ttyX. 0 if not "
                         "using M2.")
    ap.add_argument("can_channel", help="CAN channel to send/receive on. For example: can0 or can1.")
    ap.add_argument("can_baud", type=int, help="baud rate on the CAN BUS. For example: 250000.")

    ap.add_argument("pgn", help="range: 0x0000-0xFFFF (0-65535).")
    ap.add_argument("data", help="hex string of data to send, example: 0102030405060708.")

    ap.add_argument("-p", "--priority", default='0x06', help="range: 0x00-0x07 (0-7).")
    ap.add_argument("-s", "--src_addr", default='0x00', help="range: 0x00-0xFF (0-255).")
    ap.add_argument("-d", "--dst_addr", default='0xFF',
                    help="range: 0x00-0xFF (0-255), 0xFF is for broadcast messages.")
    ap.add_argument("-v", "--verbose", action="count",
                    help="print the message that was sent, use -vv to print the decoded form of the message.")

    args = vars(ap.parse_args())
    pgn, priority, src_addr, dst_addr = get_vals_from_args(args)

    #devil = J1939Interface(args['device_type'], args['port'], args['can_channel'], args['can_baud'])
    device = Device(args['device_type'], args['port'], args['can_channel'], args['can_baud'])
    devil = J1939Interface(device)
    message = J1939Message(int("18AA00F9", 16), "1122334455667788")
    devil.send_message(message)
    #message = J1939Message(priority, pgn, dst_addr, src_addr, args['data'])
    #devil.sendMessage(message)

    if args['verbose'] is not None and args['verbose'] == 1:
        print(str(message))
    elif args['verbose'] is not None and args['verbose'] >= 2:
        print(devil.get_decoded_message(message))


if __name__ == "__main__":
    main()
