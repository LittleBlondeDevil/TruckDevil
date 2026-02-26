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

    def _get_sm(self):
        """
        Attempt to find a SettingsManager in the instance
        """
        # Search in direct attributes
        if hasattr(self, 'sm'):
            return self.sm
        
        # Search in common module attributes
        for attr_name in ['fz', 'reader', 'devil']:
            if hasattr(self, attr_name):
                attr = getattr(self, attr_name)
                if hasattr(attr, 'sm'):
                    return attr.sm
        
        # Fallback: search all attributes for anything with an 'sm' attribute
        for attr_name in dir(self):
            if attr_name.startswith('_'):
                continue
            try:
                attr = getattr(self, attr_name)
                if hasattr(attr, 'sm'):
                    from libs.settings import SettingsManager
                    if isinstance(attr.sm, SettingsManager):
                        return attr.sm
            except:
                continue
        return None

    def complete_set(self, text, line, begidx, endidx):
        sm = self._get_sm()
        if not sm:
            return []
        
        settings = list(sm.settings.keys())
        if not text:
            return settings
        return [s for s in settings if s.startswith(text)]

    def complete_unset(self, text, line, begidx, endidx):
        return self.complete_set(text, line, begidx, endidx)
