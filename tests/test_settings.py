"""Unit tests for Setting and SettingsManager (no device)."""
import pytest

from truckdevil.libs.settings import Setting, SettingsManager


def test_settings_manager_constructor():
    sm = SettingsManager()
    sm.add_setting(Setting("example", 10))

    assert sm.example == 10
    assert sm["example"].updated is False

    sm.set("example", 17)
    assert sm.example == 17
    assert sm["example"].updated is True

    assert isinstance(sm["example"], Setting)


def test_setting_constructor():
    setting = Setting("example", 25)
    assert isinstance(setting, Setting)
    assert setting.value == 25
    assert setting.default_value == 25
    assert type(setting.value) is type(25)


def test_setting_mutator():
    setting = Setting("example", 25)
    assert setting.value == 25
    setting.value = 30
    assert setting.value == 30

    with pytest.raises(ValueError) as exc_info:
        setting.value = "25"
    assert "expected a " in str(exc_info.value)


def test_setting_updated():
    setting = Setting("example", "")
    assert setting.value == ""
    assert setting.updated is False
    setting.value = "new value"
    assert setting.value == "new value"
    assert setting.updated is True


def test_setting_constraints():
    setting = Setting("example", 10)
    setting.add_constraint("minval", lambda x: 0 <= x <= 10)
    setting.value = 2
    assert setting.value == 2

    with pytest.raises(ValueError) as exc_info:
        setting.value = -1
    assert "constraint minval" in str(exc_info.value)

    with pytest.raises(ValueError) as exc_info:
        setting.value = 11
    assert "constraint minval" in str(exc_info.value)


def test_setting_add_description():
    setting = Setting("example", 10)
    result = setting.add_description("a test description")
    assert result is setting  # returns self for chaining
    assert setting.description == "a test description"


def test_setting_str_scalar():
    setting = Setting("example", 10)
    setting.add_description("desc here")
    s = str(setting)
    assert "example" in s
    assert "10" in s
    assert "desc here" in s


def test_setting_str_list():
    setting = Setting("filter", [1, 2, 3])
    s = str(setting)
    assert "filter" in s
    assert "1" in s


def test_setting_str_updated():
    setting = Setting("example", 10)
    setting.value = 42
    s = str(setting)
    assert "42" in s
    assert "10" in s  # default still shown


def test_settings_manager_getitem():
    sm = SettingsManager()
    sm.add_setting(Setting("foo", 5))
    item = sm["foo"]
    assert isinstance(item, Setting)
    assert item.value == 5


def test_settings_manager_getitem_missing():
    sm = SettingsManager()
    with pytest.raises(ValueError, match="not found"):
        sm["nonexistent"]


def test_settings_manager_str():
    sm = SettingsManager()
    sm.add_setting(Setting("alpha", 1))
    sm.add_setting(Setting("beta", "hello"))
    s = str(sm)
    assert "alpha" in s
    assert "beta" in s
    assert "hello" in s


def test_settings_manager_unset():
    sm = SettingsManager()
    sm.add_setting(Setting("val", 10))
    sm.set("val", 20)
    assert sm.val == 20
    assert sm["val"].updated is True
    sm.unset("val")
    assert sm.val == 10
    assert sm["val"].updated is False


def test_settings_manager_getattr_missing():
    sm = SettingsManager()
    assert sm.nonexistent is None
