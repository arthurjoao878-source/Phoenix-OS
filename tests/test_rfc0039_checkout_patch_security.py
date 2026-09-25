from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from phoenix_os.agent.checkout_patch_security import (
    CheckoutPatchSecurityMetadata,
    bind_checkout_patch_security_metadata,
    observe_checkout_patch_security_metadata,
)

_DESCRIPTOR_DIGEST = "sha256:" + ("a" * 64)


@dataclass
class _FakeSecurityBackend:
    file_attributes_value: int = 32
    descriptor: bytes = b"descriptor-bytes"
    named_stream_count_value: int = 0

    def file_attributes(self, path: str) -> int:
        assert path
        return self.file_attributes_value

    def security_descriptor(self, path: str) -> bytes:
        assert path
        return self.descriptor

    def named_stream_count(self, path: str) -> int:
        assert path
        return self.named_stream_count_value


def _metadata() -> CheckoutPatchSecurityMetadata:
    return bind_checkout_patch_security_metadata(
        file_attributes=32,
        security_descriptor_digest=_DESCRIPTOR_DIGEST,
        named_stream_count=0,
        link_count=1,
    )


def test_security_metadata_binding_is_deterministic_and_content_free() -> None:
    first = _metadata()
    second = _metadata()

    assert first == second
    assert first.platform == "windows"
    assert first.file_attributes == 32
    assert first.named_stream_count == 0
    assert first.link_count == 1
    assert first.fingerprint.startswith("sha256:")
    assert _DESCRIPTOR_DIGEST not in repr(first.fingerprint)


def test_security_metadata_binding_rejects_named_streams_and_hardlinks() -> None:
    with pytest.raises(ValueError, match="alternate data streams"):
        bind_checkout_patch_security_metadata(
            file_attributes=32,
            security_descriptor_digest=_DESCRIPTOR_DIGEST,
            named_stream_count=1,
            link_count=1,
        )

    with pytest.raises(ValueError, match="unique-link"):
        bind_checkout_patch_security_metadata(
            file_attributes=32,
            security_descriptor_digest=_DESCRIPTOR_DIGEST,
            named_stream_count=0,
            link_count=2,
        )


def test_security_metadata_binding_rejects_tampered_fingerprint() -> None:
    metadata = _metadata()

    with pytest.raises(ValueError, match="fingerprint is inconsistent"):
        replace(metadata, fingerprint="sha256:" + ("0" * 64))


def test_security_metadata_binding_covers_file_attributes_and_descriptor_digest() -> None:
    baseline = _metadata()
    attributes_changed = bind_checkout_patch_security_metadata(
        file_attributes=33,
        security_descriptor_digest=_DESCRIPTOR_DIGEST,
        named_stream_count=0,
        link_count=1,
    )
    descriptor_changed = bind_checkout_patch_security_metadata(
        file_attributes=32,
        security_descriptor_digest="sha256:" + ("b" * 64),
        named_stream_count=0,
        link_count=1,
    )

    assert attributes_changed.fingerprint != baseline.fingerprint
    assert descriptor_changed.fingerprint != baseline.fingerprint


def test_security_metadata_observer_binds_transient_descriptor_without_raw_bytes(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    target.write_text("safe\n", encoding="utf-8")
    backend = _FakeSecurityBackend(descriptor=b"secret-security-descriptor")

    first = observe_checkout_patch_security_metadata(target, _backend=backend)
    second = observe_checkout_patch_security_metadata(target, _backend=backend)

    assert first == second
    assert first.file_attributes == 32
    assert first.named_stream_count == 0
    assert first.link_count == 1
    assert first.security_descriptor_digest.startswith("sha256:")
    assert b"secret-security-descriptor".decode() not in repr(first)


def test_security_metadata_observer_rejects_ads_reparse_and_non_regular_file(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    target.write_text("safe\n", encoding="utf-8")

    with pytest.raises(ValueError, match="alternate data streams"):
        observe_checkout_patch_security_metadata(
            target,
            _backend=_FakeSecurityBackend(named_stream_count_value=1),
        )

    with pytest.raises(ValueError, match="reparse point"):
        observe_checkout_patch_security_metadata(
            target,
            _backend=_FakeSecurityBackend(file_attributes_value=0x00000400),
        )

    with pytest.raises(ValueError, match="regular file"):
        observe_checkout_patch_security_metadata(
            tmp_path,
            _backend=_FakeSecurityBackend(),
        )


def test_security_metadata_observer_rejects_hardlink_target(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("safe\n", encoding="utf-8")
    sibling = tmp_path / "sibling.txt"

    try:
        os.link(target, sibling)
    except OSError as exception:
        pytest.skip(f"hardlinks unavailable on this platform: {exception}")

    with pytest.raises(ValueError, match="unique-link"):
        observe_checkout_patch_security_metadata(
            target,
            _backend=_FakeSecurityBackend(),
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows native metadata observer")
def test_windows_security_metadata_observer_reads_real_temp_file(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("safe\n", encoding="utf-8")

    observed = observe_checkout_patch_security_metadata(target)

    assert observed.platform == "windows"
    assert observed.file_attributes >= 0
    assert observed.named_stream_count == 0
    assert observed.link_count == 1
    assert observed.security_descriptor_digest.startswith("sha256:")
    assert observed.fingerprint.startswith("sha256:")
