import argparse
import truckDevil as td

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description='read and print all messages from M2. If read_time and num_messages are both specified, stop printing when whichever one is reached first.')
    
    ap.add_argument("device_type", help="type of device to use. For example: m2 or socketcan.")
    ap.add_argument("port", help="serial port that the M2 is connected to, if used. For example: COM7 or /dev/ttyX. 0 if not using M2.")
    ap.add_argument("can_channel", help="CAN channel to send/receive on. For example: can0 or can1.")
    ap.add_argument("can_baud", type=int, help="baud rate on the CAN BUS. For example: 250000.")
    
    ap.add_argument("-s", "--serial_baud", default=115200, type=int, help="baud rate of the serial connection to the M2. By default it is 115200.")
    ap.add_argument("-t", "--read_time", type=float, help="the amount of time, in seconds, to print messages for. If not specified, it will not be limited.")
    ap.add_argument("-n", "--num_messages", type=int, help="number of messages to print before stopping. If not specified, it will not be limited.")
    ap.add_argument("-a", "--abstract_TPM", action="store_true", help="abstract Transport Protocol messages.")
    ap.add_argument("-l", "--log_to_file", action="store_true", help="log the messages to a file in the current directory with the form 'm2_collected_data_[TIME]'.")
    
    ap.add_argument("-v", "--verbose", action="store_true", help="print the message in decoded form")

    args = vars(ap.parse_args())
    
    devil = td.TruckDevil(args['device_type'], args['port'], args['can_channel'], args['can_baud'])
    devil.printMessages(args['abstract_TPM'], args['read_time'], args['num_messages'], args['verbose'], args['log_to_file'])
    devil.done()
