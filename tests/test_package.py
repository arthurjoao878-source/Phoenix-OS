import phoenix_os


def test_package_version() -> None:
    assert phoenix_os.__version__ == "0.13.0"
