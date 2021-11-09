import cmd


class Command(cmd.Cmd):
    def run_commands(self, argv):
        """
        run commands from list of arguments
        """
        command_names = []
        for name in self.get_names():
            if name.startswith("do_"):
                command_names.append(name.strip("do_"))
        cmd_args = []
        for arg in argv:
            if arg in command_names and len(cmd_args) != 0:
                self.onecmd(' '.join(cmd_args))
                cmd_args = []
            cmd_args.append(arg)
        if len(cmd_args) != 0:
            self.onecmd(' '.join(cmd_args))
