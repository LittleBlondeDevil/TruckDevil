import cmd
import sys


class Command(cmd.Cmd):
    def __init__(self, sm=None):
        """
        :param sm: optional SettingsManager instance for tab-completion of
                   set/unset commands. Subclasses may also set self.sm after
                   calling super().__init__().
        """
        super().__init__()
        self.sm = sm

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

    def complete_set(self, text, line, begidx, endidx):
        if not self.sm:
            return []

        settings = list(self.sm.settings.keys())
        if not text:
            return settings
        return [s for s in settings if s.startswith(text)]

    def complete_unset(self, text, line, begidx, endidx):
        return self.complete_set(text, line, begidx, endidx)

    def do_quit(self, arg):
        """
        Quit TruckDevil immediately, regardless of the current module state.
        Unlike 'back', which returns to the parent menu, 'quit' will exit
        the entire TruckDevil REPL immediately.
        """
        sys.exit("Exiting TruckDevil")