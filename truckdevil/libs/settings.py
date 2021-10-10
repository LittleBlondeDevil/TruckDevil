"""
Settings management for truckdevil
"""
from typing import Any
from collections.abc import Callable
from textwrap import fill


class Setting:
    """
    A setting is a strongly typed tunable parameter.

    Requirements:
        * Settings must maintain type information and enforce typing.
        * Settings must be able to report if they have been changed from
          its default value.
        * Settings must be able to validate ranges (e.g. [0..7] etc.)

    """

    def __init__(self, name: str, def_val: Any):
        """
        Create a setting object with the given name and value, the type of
        this setting will be inferred from the default value, so make sure it
        has the same type as what's desired.

        :param name: str - string name of this setting
        :param def_val: Any - the default value of this setting
        """
        self.name = name
        self.datatype = type(def_val)
        self.default_value = def_val
        self._value = None
        self.constraints = {}
        self.description = ""
        return

    @property
    def value(self) -> Any:
        """
        Get the value (or default value) of the setting

        :return: Any - the current value of this setting
        """
        if self._value is None:
            return self.default_value
        return self._value

    @value.setter
    def value(self, new_value: Any):
        """
        Set this setting's value with type checking

        :param new_value: Any - Value to set this setting to
        """

        if len(self.constraints) > 0:
            for name in self.constraints:
                if not self.constraints[name](new_value):
                    raise ValueError("constraint {} excludes {}".format(name, new_value))

        if type(new_value) == self.datatype:
            self._value = new_value
            return

        raise ValueError("expected a {} but got {} ({})".format(type(self.datatype), type(new_value), new_value))

    @property
    def updated(self):
        """
        Check if this setting has been modified from it's default value

        :return: bool - True if it has been modified False otherwise
        """
        return self._value is not None

    def add_constraint(self, name: str, constraint: Callable[[Any], bool]):
        """
        Add constraints to the allowed value of setting.

        :param name: str - name of this constraint (e.g. max)
        :param constraint: Callable[[Any], bool] - validation function
        """
        self.constraints[name] = constraint
        return self

    def add_description(self, desc: str):
        self.description = desc
        return self

    def __str__(self):
        return fill("{:<24} {:>12} (default: {:<5}) {:<}".format(
            self.name, self.value, self.default_value, self.description), width=120, subsequent_indent=" " * 55)


class SettingsManager:
    """
    Manage settings
    """

    def __init__(self):
        self.settings = {}

    def add_setting(self, setting: Setting):
        """
        Add a setting to the settings manager

        :param setting: Setting - to be added
        :return: self
        """
        self.settings[setting.name] = setting
        return self

    def set(self, name: str, value: Any):
        """
        Set a setting to the given value
        :param name: str - name of setting to set
        :param value: Any - value to set
        """
        if name in self.settings:
            self.settings[name].value = value

    def __getattr__(self, name: str) -> Any:
        if name in self.settings:
            return self.settings[name].value

    def __getitem__(self, name: str) -> Setting:
        if name in self.settings:
            return self.settings[name]
        raise ValueError("setting name not found")

    def __str__(self):
        ret_val = ""
        for name in self.settings:
            ret_val += str(self.settings[name]) + "\n"
        return ret_val
