import shlex
import sys
import os
from prompt_toolkit import PromptSession
from prompt_toolkit.output import DummyOutput
from prompt_toolkit.completion import NestedCompleter, WordCompleter, Completer, Completion
from prompt_toolkit.history import FileHistory
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import print_formatted_text
from prompt_toolkit.formatted_text import HTML


class Command:
    intro = ""
    prompt = "> "

    def __init__(self, sm=None):
        """
        :param sm: optional SettingsManager instance for tab-completion of
                   set/unset commands. Subclasses may also set self.sm after
                   calling super().__init__().
        """
        self.sm = sm
        self.running = True
        
        # Use a hidden history file in the user's home directory
        history_path = os.path.expanduser("~/.truckdevil_history")
        
        # In non-interactive environments (like pytest), use DummyOutput
        # to avoid NoConsoleScreenBufferError on Windows.
        if not sys.stdout.isatty() or "pytest" in sys.modules:
            self.session = PromptSession(history=FileHistory(history_path), output=DummyOutput())
        else:
            self.session = PromptSession(history=FileHistory(history_path))

    def get_prompt(self):
        """
        Returns the prompt to be displayed. Subclasses can override this
        to provide dynamic prompts (e.g. including device status).
        """
        return self.prompt

    def get_commands(self):
        """Helper to find all 'do_' methods."""
        return [name[3:] for name in dir(self) if name.startswith("do_")]

    def get_completion_dict(self):
        """
        Returns a dictionary representing the command structure for completion.
        Subclasses should override this and call super().get_completion_dict()
        to preserve base completions like settings.
        """
        completions = {cmd: None for cmd in self.get_commands()}
        
        # Integrate SettingsManager if present
        if self.sm:
            settings_dict = {s: None for s in self.sm.settings.keys()}
            if 'set' in completions:
                completions['set'] = settings_dict
            if 'unset' in completions:
                completions['unset'] = settings_dict
        
        return completions

    def get_completer(self):
        """Builds a NestedCompleter from the completion dictionary."""
        return NestedCompleter.from_nested_dict(self.get_completion_dict())

    def onecmd(self, line):
        """Dispatches a single command string to the appropriate 'do_' method."""
        line = line.strip()
        if not line:
            return False
            
        try:
            # shlex.split handles quotes correctly for paths/values with spaces
            argv = shlex.split(line)
            if not argv:
                return False
                
            cmd_name = argv[0]
            arg_str = line[len(cmd_name):].strip()
            
            # Special case for '?' which is common in cmd.Cmd
            if cmd_name == '?':
                cmd_name = 'help'
            
            func = getattr(self, f"do_{cmd_name}", None)
            if func:
                # cmd.Cmd methods expect a single string argument
                return func(arg_str)
            else:
                print(f"*** Unknown syntax: {line}")
        except Exception as e:
            print(f"*** Error executing command: {e}")
        return False

    def do_help(self, arg):
        """
        List available commands with "help" or detailed help with "help <cmd>".
        """
        if not arg:
            cmds = sorted(self.get_commands())
            print("\nDocumented commands (type help <topic>):")
            print("========================================")
            # Simple column print
            for i in range(0, len(cmds), 4):
                print("  ".join(f"{c:<15}" for c in cmds[i:i+4]))
            print()
        else:
            func = getattr(self, f"do_{arg}", None)
            if func and func.__doc__:
                # Clean up docstring indentation
                doc = func.__doc__.strip()
                # Remove common indentation
                lines = doc.split('\n')
                if len(lines) > 1:
                    indent = len(lines[1]) - len(lines[1].lstrip())
                    doc = lines[0] + '\n' + '\n'.join(line[indent:] for line in lines[1:])
                print(doc)
            else:
                print(f"*** No help on {arg}")

    def do_quit(self, arg):
        """
        Quit TruckDevil immediately, regardless of the current module state.
        Unlike 'back', which returns to the parent menu, 'quit' will exit
        the entire TruckDevil REPL immediately.
        """
        sys.exit("Exiting TruckDevil")

    def run_commands(self, argv):
        """
        run commands from list of arguments
        """
        command_names = self.get_commands()
        cmd_args = []
        for arg in argv:
            if arg in command_names and len(cmd_args) != 0:
                self.onecmd(' '.join(cmd_args))
                cmd_args = []
            cmd_args.append(arg)
        if len(cmd_args) != 0:
            self.onecmd(' '.join(cmd_args))

    def preloop(self):
        """Hook method executed once when cmdloop() is called."""
        pass

    def cmdloop(self):
        """The main REPL loop."""
        if self.intro:
            print(self.intro)
            
        self.preloop()
        while self.running:
            try:
                # patch_stdout allows background threads (like CAN receivers) 
                # to print without messing up the prompt.
                with patch_stdout():
                    text = self.session.prompt(
                        self.get_prompt(), 
                        completer=self.get_completer()
                    )
                    if self.onecmd(text):
                        # If a command returns True (like 'back'), exit this loop
                        break
            except KeyboardInterrupt:
                # Ctrl-C clears the line or stops a running command
                continue
            except EOFError:
                # Ctrl-D exits
                break
        return