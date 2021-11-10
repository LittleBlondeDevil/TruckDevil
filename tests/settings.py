import unittest

from TruckDevil.truckdevil.libs.settings import Setting
from TruckDevil.truckdevil.libs.settings import SettingsManager


class SettingsManagerTestCase(unittest.TestCase):

    def test_settings_constructor(self):
        sm = SettingsManager()
        sm.add_setting(Setting("example", 10))

        self.assertEqual(sm.example, 10)
        self.assertFalse(sm['example'].updated)

        sm.set("example", 17)
        self.assertEqual(sm.example, 17)
        self.assertTrue(sm['example'].updated)

        self.assertTrue(isinstance(sm['example'], Setting))


class SettingsTestCase(unittest.TestCase):

    def test_setting_constructor(self):
        setting = Setting("example", 25)
        self.assertTrue(isinstance(setting, Setting))
        self.assertEqual(setting.value, 25)
        self.assertEqual(setting.default_value, 25)
        self.assertEqual(type(setting.value), type(25))

    def test_setting_mutator(self):
        setting = Setting("example", 25)
        self.assertEqual(setting.value, 25)
        setting.value = 30
        self.assertEqual(setting.value, 30)

        with self.assertRaises(ValueError) as context:
            setting.value = "25"

        self.assertTrue("expected a " in str(context.exception))

    def test_setting_updated(self):
        setting = Setting("example", "")
        self.assertEqual(setting.value, "")
        self.assertFalse(setting.updated)
        setting.value = "new value"
        self.assertEqual(setting.value, "new value")
        self.assertTrue(setting.updated)

    def test_setting_constraints(self):
        setting = Setting("example", 10)
        setting.add_constraint("minval", lambda x: 0 <= x <= 10)
        setting.value = 2
        self.assertEqual(setting.value, 2)

        with self.assertRaises(ValueError) as context:
            setting.value = -1

        self.assertTrue("constraint minval" in str(context.exception))

        with self.assertRaises(ValueError) as context:
            setting.value = 11

        self.assertTrue("constraint minval" in str(context.exception))


if __name__ == '__main__':
    unittest.main()
