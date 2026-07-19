import phoenix_os


def test_package_version() -> None:
    assert phoenix_os.__version__ == "0.17.0"
    assert phoenix_os.ControlPlaneHttpServer.__name__ == "ControlPlaneHttpServer"
    assert phoenix_os.DashboardAssets().get("/dashboard/") is not None
