from __future__ import annotations

from typing import Callable, Iterable, Iterator, Optional


def iter_lines(
    chunks: Iterable[bytes],
    stop: Optional[Callable[[], bool]] = None,
) -> Iterator[str]:
    buf = b""
    for chunk in chunks:
        if stop is not None and stop():
            return
        if not chunk:
            continue
        buf += chunk
        parts = buf.split(b"\n")
        buf = parts.pop()
        for raw in parts:
            yield raw.rstrip(b"\r").decode("utf-8", "replace")
    if buf:
        yield buf.rstrip(b"\r").decode("utf-8", "replace")


def iter_sse_frames(
    chunks: Iterable[bytes],
    stop: Optional[Callable[[], bool]] = None,
) -> Iterator[tuple[Optional[str], str]]:
    event_name: Optional[str] = None
    data_lines: list[str] = []

    for line in iter_lines(chunks, stop=stop):
        if not line:
            if data_lines:
                yield event_name, "\n".join(data_lines)
            event_name = None
            data_lines = []
            continue
        if line.startswith(":"):
            continue
        name, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if name == "event":
            event_name = value
        elif name == "data":
            data_lines.append(value)

    if data_lines:
        yield event_name, "\n".join(data_lines)
