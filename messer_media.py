"""Stream local Messer audio/video with HTTP Range support (browser players need 206)."""

from __future__ import annotations

import mimetypes
from pathlib import Path

from flask import Response, request, send_file
from werkzeug.http import parse_range_header

# 1 MiB read chunks — balances memory and Windows read throughput.
_MEDIA_CHUNK = 1024 * 1024

_MESSER_MIME: dict[str, str] = {
    ".mp3": "audio/mpeg",
    ".mp4": "video/mp4",
    ".m4a": "audio/mp4",
    ".webm": "video/webm",
}


def messer_media_mimetype(path: Path) -> str:
    """Return a stable MIME type for Messer A/V files."""
    ext = path.suffix.lower()
    if ext in _MESSER_MIME:
        return _MESSER_MIME[ext]
    guessed, _ = mimetypes.guess_type(str(path))
    return guessed or "application/octet-stream"


def stream_messer_file(target: Path) -> Response:
    """Serve a file under messer_root with Accept-Ranges and partial content."""
    size = target.stat().st_size
    mime = messer_media_mimetype(target)
    as_download = request.args.get("download", "").lower() in ("1", "true", "yes")

    range_header = request.headers.get("Range")
    if range_header:
        byte_range = parse_range_header(range_header)
        if byte_range is None or byte_range.units != "bytes":
            return Response("Invalid range", status=416)
        if len(byte_range.ranges) != 1:
            return Response("Multiple ranges not supported", status=416)

        start, stop = byte_range.range_for_length(size)
        length = stop - start

        def generate():
            with open(target, "rb") as fp:
                fp.seek(start)
                remaining = length
                while remaining > 0:
                    data = fp.read(min(_MEDIA_CHUNK, remaining))
                    if not data:
                        break
                    remaining -= len(data)
                    yield data

        resp = Response(generate(), status=206, mimetype=mime)
        resp.headers["Content-Range"] = byte_range.make_content_range(size)
        resp.headers["Accept-Ranges"] = "bytes"
        resp.headers["Content-Length"] = str(length)
        resp.headers["Cache-Control"] = "private, max-age=86400"
        if as_download:
            resp.headers["Content-Disposition"] = f'attachment; filename="{target.name}"'
        return resp

    resp = send_file(
        target,
        mimetype=mime,
        conditional=True,
        max_age=86400,
        etag=True,
        last_modified=True,
        as_attachment=as_download,
        download_name=target.name if as_download else None,
    )
    resp.headers.setdefault("Accept-Ranges", "bytes")
    return resp
