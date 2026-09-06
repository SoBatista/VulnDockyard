"""Stable human and machine output."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from typing import Any, TextIO

JSON_SCHEMA_VERSION = 1


def terminal_safe(value: str) -> str:
    """Escape terminal controls while retaining ordinary text, tabs, and line breaks."""
    pieces: list[str] = []
    for character in value:
        if character in {"\n", "\t"} or character.isprintable():
            pieces.append(character)
        else:
            codepoint = ord(character)
            pieces.append(f"\\x{codepoint:02x}" if codepoint <= 0xFF else f"\\u{codepoint:04x}")
    return "".join(pieces)


@dataclass
class Output:
    json_mode: bool = False
    stream: TextIO = field(default_factory=lambda: sys.stdout)
    error_stream: TextIO = field(default_factory=lambda: sys.stderr)

    def emit(self, command: str, data: object, human: str = "") -> None:
        if self.json_mode:
            document = {"schema_version": JSON_SCHEMA_VERSION, "command": command, "data": data}
            print(json.dumps(document, sort_keys=True, separators=(",", ":")), file=self.stream)
        elif human:
            print(terminal_safe(human), file=self.stream)

    def error(self, command: str, message: str, code: int) -> None:
        if self.json_mode:
            document: dict[str, Any] = {
                "schema_version": JSON_SCHEMA_VERSION,
                "command": command,
                "error": {"code": code, "message": message},
            }
            print(
                json.dumps(document, sort_keys=True, separators=(",", ":")), file=self.error_stream
            )
        else:
            print(f"Error: {terminal_safe(message)}", file=self.error_stream)
