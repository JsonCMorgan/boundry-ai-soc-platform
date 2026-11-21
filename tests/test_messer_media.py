"""HTTP Range streaming for Messer local media."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def messer_media_file(tmp_path, monkeypatch):
    import os

    import messer_paths

    media = tmp_path / "sy0-701-audio" / "sample.mp3"
    media.parent.mkdir(parents=True)
    media.write_bytes(b"\x00" * 5000 + b"MPEG" + b"\xff" * 100)
    monkeypatch.setattr(messer_paths, "LOCAL_MIRROR", tmp_path)
    monkeypatch.setenv("MESSER_CONTENT_ROOT", str(tmp_path))
    os.environ["ENABLE_MESSER_LAYER"] = "1"
    rel = "sy0-701-audio/sample.mp3"
    return rel, media


def test_messer_media_full(analyst_client, messer_media_file):
    rel, media = messer_media_file
    r = analyst_client.get(f"/career/secplus/messer/media/{rel}")
    assert r.status_code == 200
    assert r.headers.get("Accept-Ranges") == "bytes"
    assert r.mimetype == "audio/mpeg"
    assert len(r.data) == media.stat().st_size


def test_messer_media_range_206(analyst_client, messer_media_file):
    rel, _media = messer_media_file
    r = analyst_client.get(
        f"/career/secplus/messer/media/{rel}",
        headers={"Range": "bytes=0-1023"},
    )
    assert r.status_code == 206
    assert r.headers.get("Content-Range") == "bytes 0-1023/5104"
    assert len(r.data) == 1024
    assert r.mimetype == "audio/mpeg"


def test_messer_media_range_mid_file(analyst_client, messer_media_file):
    rel, media = messer_media_file
    size = media.stat().st_size
    r = analyst_client.get(
        f"/career/secplus/messer/media/{rel}",
        headers={"Range": f"bytes={size - 100}-"},
    )
    assert r.status_code == 206
    assert len(r.data) == 100
