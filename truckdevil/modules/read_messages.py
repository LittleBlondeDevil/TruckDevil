import argparse
from j1939.j1939 import J1939Interface


def main_mod(argv, device=None):
    if device is None:
        print("Device must be added first.")
        return
    interface = J1939Interface(device)

    print("\n***** Read Messages *****")
    print("Read and print all messages from CAN device.")
    ap = argparse.ArgumentParser(usage="[-h] [-t READ_TIME] [-n NUM_MESSAGES] [-a] [-l] [-v]",
                                 description='If read_time and num_messages are both specified, stop printing when '
                                             'whichever one is reached first.')
    ap.add_argument("-t", "--read_time", type=float, help="the amount of time, in seconds, to print messages for. If "
                                                          "not specified, it will not be limited.")
    ap.add_argument("-n", "--num_messages", type=int, help="number of messages to print before stopping. If not "
                                                           "specified, it will not be limited.")
    ap.add_argument("-a", "--abstract_TPM", action="store_true", help="abstract Transport Protocol messages.")
    ap.add_argument("-l", "--log_to_file", action="store_true", help="log the messages to a file in the current "
                                                                     "directory with the form 'm2_collected_data_["
                                                                     "TIME]'.")
    ap.add_argument("-v", "--verbose", action="store_true", help="print the message in decoded form")
    ap.print_help()
    while True:
        arg_input = input("Optional Args (q to return) > ")
        if arg_input == "q" or arg_input == "quit" or arg_input == "exit":
            return
        try:
            args = vars(ap.parse_args(arg_input.split()))

        except (SystemExit, ValueError) as e:
            print(e)
            continue

        interface.print_messages(args['abstract_TPM'], args['read_time'], args['num_messages'], args['verbose'],
                                 args['log_to_file'])

