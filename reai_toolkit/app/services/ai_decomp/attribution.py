from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

DISASSEMBLY_ROW_OFFSET = 1

_LINE_ADDRESS_RE = re.compile(r"^\s*(0[xX][0-9a-fA-F]+)")


def _as_index(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        try:
            parsed = int(value, 10)
        except ValueError:
            return None
        return parsed if parsed >= 0 else None
    return None


@dataclass
class LineAttributions:
    disasm_to_decomp: dict[int, list[int]] = field(default_factory=dict)
    decomp_to_disasm: dict[int, list[int]] = field(default_factory=dict)

    def is_empty(self) -> bool:
        return not self.disasm_to_decomp


def invert_attributions(forward: Any) -> LineAttributions:
    if not isinstance(forward, dict):
        return LineAttributions()

    disasm_to_decomp: dict[int, list[int]] = {}
    decomp_to_disasm: dict[int, list[int]] = {}

    for raw_line, raw_decomp_lines in forward.items():
        disasm_line = _as_index(raw_line)
        if disasm_line is None or not raw_decomp_lines:
            continue
        decomp_lines = [
            line
            for line in (_as_index(value) for value in raw_decomp_lines)
            if line is not None
        ]
        if not decomp_lines:
            continue
        disasm_to_decomp[disasm_line] = decomp_lines
        for decomp_line in decomp_lines:
            decomp_to_disasm.setdefault(decomp_line, []).append(disasm_line)

    for disasm_lines in decomp_to_disasm.values():
        disasm_lines.sort()

    return LineAttributions(disasm_to_decomp, decomp_to_disasm)


def _block_min_addr(block: Any) -> int:
    value = block.get("min_addr") if isinstance(block, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _block_asm(block: Any) -> list[str]:
    value = block.get("asm") if isinstance(block, dict) else None
    if not isinstance(value, list):
        return []
    return [line for line in value if isinstance(line, str)]


def _line_address(line: str) -> Optional[int]:
    match = _LINE_ADDRESS_RE.match(line)
    return int(match.group(1), 16) if match is not None else None


def asm_row_addresses(basic_blocks: Any) -> list[Optional[int]]:
    if not isinstance(basic_blocks, list):
        return []
    rows: list[Optional[int]] = []
    for block in sorted(basic_blocks, key=_block_min_addr):
        for line in _block_asm(block):
            rows.append(_line_address(line))
    return rows


class AttributionMap:
    def __init__(
        self,
        attributions: Optional[LineAttributions] = None,
        row_addresses: Optional[list[Optional[int]]] = None,
    ) -> None:
        self.attributions = attributions or LineAttributions()
        self.row_addresses = row_addresses or []
        self._rows_by_address: dict[int, list[int]] = {}
        for row, address in enumerate(self.row_addresses):
            if address is not None:
                self._rows_by_address.setdefault(address, []).append(row)

    def is_empty(self) -> bool:
        return self.attributions.is_empty() or not self._rows_by_address

    def addresses_for_decomp_line(self, decomp_line: int) -> list[int]:
        addresses: set[int] = set()
        for disasm_line in self.attributions.decomp_to_disasm.get(decomp_line, ()):
            row = disasm_line + DISASSEMBLY_ROW_OFFSET
            if 0 <= row < len(self.row_addresses):
                address = self.row_addresses[row]
                if address is not None:
                    addresses.add(address)
        return sorted(addresses)

    def decomp_lines_for_address(self, address: int) -> list[int]:
        decomp_lines: set[int] = set()
        for row in self._rows_by_address.get(address, ()):
            disasm_line = row - DISASSEMBLY_ROW_OFFSET
            decomp_lines.update(self.attributions.disasm_to_decomp.get(disasm_line, ()))
        return sorted(decomp_lines)
