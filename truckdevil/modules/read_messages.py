import argparse
import cmd

from j1939.j1939 import J1939Interface
from libs.settings import SettingsManager, Setting


class Reader:
    def __init__(self, device):
        self.devil = J1939Interface(device)

        self.sm = SettingsManager()
        sl = [
            Setting("read_time", 0).add_constraint("minimum", lambda x: 0 <= x)
                .add_description("The amount of time to read messages for, in seconds. Ignored if not set."),

            Setting("num_messages", 0).add_constraint("minimum", lambda x: 0 <= x)
                .add_description("The number of messages to read before stopping. Ignored if not set."),

            Setting("abstract_TPM", False).add_constraint("boolean", lambda x: type(x) is bool)
                .add_description("Whether or not to abstract Transport Protocol messages."),

            Setting("log_to_file", False).add_constraint("boolean", lambda x: type(x) is bool)
                .add_description("Whether or not to log the messages to a file."),

            Setting("log_name", "log_[time].txt")
                .add_description("The name of the log file, if used."),

            Setting("verbose", False).add_constraint("boolean", lambda x: type(x) is bool)
                .add_description("Display the messages in decoded form, if applicable."),

            Setting("filter_can_id", [0]).add_constraint("list_of_ints", lambda x: all(isinstance(i, int) for i in x))
                .add_description("Only read messages containing one of these CAN IDs."),

            Setting("filter_priority", [0]).add_constraint("list_of_ints", lambda x: all(isinstance(i, int) for i in x))
                .add_description("Only read messages containing one of these priorities."),

            Setting("filter_pdu_format", [0]).add_constraint("list_of_ints",
                                                             lambda x: all(isinstance(i, int) for i in x))
                .add_description("Only read messages containing one of these PDU Formats."),

            Setting("filter_pdu_specific", [0]).add_constraint("list_of_ints",
                                                               lambda x: all(isinstance(i, int) for i in x))
                .add_description("Only read messages containing one of these PDU Specifics."),

            Setting("filter_src_addr", [0]).add_constraint("list_of_ints", lambda x: all(isinstance(i, int) for i in x))
                .add_description("Only read messages containing one of these source addresses."),

            Setting("filter_data_snippet", [""])
                .add_description(
                "Only read messages containing one of these data snippets. Checks if snippets in data."),

        ]

        for setting in sl:
            self.sm.add_setting(setting)


class ReadCommands(cmd.Cmd):
    intro = "Welcome to the Read Messages tool."
    prompt = "(truckdevil.read_messages) "

    def __init__(self, argv, device):
        super().__init__()
        self.reader = Reader(device)

    def do_settings(self, arg):
        """Show the settings and each setting value"""
        print(self.reader.sm)
        return

    def do_set(self, arg):
        """
        Provide a setting name and a value to set the setting. For a list of
        available settings and their current and default values see the
        settings command.

        example:
        set read_time 10
        set filter_src_addr 11,249
        """
        argv = arg.split()
        name = argv[0]
        if len(argv) == 1:
            print("expected value, see 'help set'")
            return
        try:
            if self.reader.sm[name].datatype == int:
                self.reader.sm.set(name, int(argv[1]))
            elif self.reader.sm[name].datatype == float:
                self.reader.sm.set(name, float(argv[1]))
            elif self.reader.sm[name].datatype == bool:
                if argv[1] in ["True", "true", "on", 1]:
                    self.reader.sm.set(name, True)
                elif argv[1] in ["False", "false", "off", 0]:
                    self.reader.sm.set(name, False)
                else:
                    self.reader.sm.set(name, argv[1])
            elif self.reader.sm[name].datatype == list:
                values = argv[1].split(",")
                if type(self.reader.sm[name].default_value[0]) == int:
                    new_values = []
                    for v in values:
                        if v.startswith("0x"):
                            new_values.append(int(v, 16))
                        else:
                            new_values.append(int(v))
                    self.reader.sm.set(name, new_values)
                else:
                    self.reader.sm.set(name, values)
            else:
                self.reader.sm.set(name, argv[1])
        except ValueError as e:
            print("Could not set: {}".format(e))
        return

    def do_unset(self, arg):
        """
        Provide a setting name to set it back to it's default value. For a list of
        available settings and their current and default values see the
        settings command.

        example:
        unset read_time
        """
        argv = arg.split()
        if len(argv) == 0:
            print("expected name, see 'help unset'")
            return
        name = argv[0]
        self.reader.sm.unset(name)

    def do_print_messages(self, arg):
        """Read and print all messages from CAN device, based on settings"""
        read_time = None
        num_messages = None
        if self.reader.sm["read_time"].updated:
            read_time = self.reader.sm.read_time
        if self.reader.sm["num_messages"].updated:
            num_messages = self.reader.sm.num_messages
        filters = {}
        if self.reader.sm["filter_can_id"].updated:
            filters["can_id"] = self.reader.sm.filter_can_id
        else:
            if self.reader.sm["filter_priority"].updated:
                filters["priority"] = self.reader.sm.filter_priority
            if self.reader.sm["filter_pdu_format"].updated:
                filters["pdu_format"] = self.reader.sm.filter_pdu_format
            if self.reader.sm["filter_pdu_specific"].updated:
                filters["pdu_specific"] = self.reader.sm.filter_pdu_specific
            if self.reader.sm["filter_src_addr"].updated:
                filters["src_addr"] = self.reader.sm.filter_src_addr
        if self.reader.sm["filter_data_snippet"].updated:
            filters["data_snippet"] = self.reader.sm.filter_data_snippet
        file_name = None
        if self.reader.sm["log_name"].updated:
            file_name = self.reader.sm.log_name
        try:
            self.reader.devil.print_messages(self.reader.sm.abstract_TPM, read_time, num_messages,
                                             self.reader.sm.verbose, self.reader.sm.log_to_file, file_name, **filters)
        except KeyboardInterrupt:
            return
        except FileExistsError:
            print("Log file already exists.")
            return

    # TODO: add feature for viewing messages that have changed. Instead of scrolling, show a count and the bytes
    # that changed in the data between receives


def main_mod(argv, device):
    rcli = ReadCommands(argv, device)
    rcli.cmdloop()
