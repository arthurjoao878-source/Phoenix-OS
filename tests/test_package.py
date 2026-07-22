import phoenix_os
import phoenix_os.control_plane as control_plane


def test_package_version() -> None:
    assert phoenix_os.__version__ == "0.23.0"
    assert phoenix_os.ControlPlaneHttpServer.__name__ == "ControlPlaneHttpServer"
    assert phoenix_os.DashboardAssets().get("/dashboard/") is not None
    assert phoenix_os.ControlPlaneSecureHttpServer.__name__ == ("ControlPlaneSecureHttpServer")


def test_package_exports_rfc_0023_control_plane_surface() -> None:
    markers = (
        "ServiceAccount",
        "ApiToken",
        "SERVICE_ACCOUNT",
        "API_TOKEN",
        "service_account",
        "api_token",
    )
    required = {name for name in control_plane.__all__ if any(marker in name for marker in markers)}

    assert len(required) == 125
    assert required <= set(phoenix_os.__all__)

    for name in required:
        assert getattr(phoenix_os, name) is getattr(control_plane, name)
