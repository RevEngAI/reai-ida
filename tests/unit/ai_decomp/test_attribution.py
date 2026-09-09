import pytest

from reai_toolkit.app.services.ai_decomp.attribution import (
    DISASSEMBLY_ROW_OFFSET,
    AttributionMap,
    asm_row_addresses,
    invert_attributions,
)


FORWARD = {"12": [3, 4, 6], "17": [4]}


def _blocks(*specs):
    return [{"min_addr": addr, "asm": list(asm)} for addr, asm in specs]


def test_invert_keeps_the_forward_map_and_builds_the_reverse():
    attributions = invert_attributions(FORWARD)

    assert attributions.disasm_to_decomp == {12: [3, 4, 6], 17: [4]}
    assert attributions.decomp_to_disasm == {3: [12], 4: [12, 17], 6: [12]}


def test_invert_sorts_the_reverse_lists():
    attributions = invert_attributions({"9": [1], "2": [1], "5": [1]})

    assert attributions.decomp_to_disasm[1] == [2, 5, 9]


def test_invert_drops_lines_with_no_counterpart():
    attributions = invert_attributions({"1": None, "2": [], "3": [7]})

    assert attributions.disasm_to_decomp == {3: [7]}


def test_invert_drops_unusable_keys_and_values():
    attributions = invert_attributions(
        {"nope": [1], "-2": [1], "4": ["x", None, 2], "5": [True]}
    )

    assert attributions.disasm_to_decomp == {4: [2]}


@pytest.mark.parametrize("forward", [None, [], "", 0])
def test_invert_of_a_non_mapping_is_empty(forward):
    assert invert_attributions(forward).is_empty()


def test_an_empty_correspondence_is_ordinary_not_an_error():
    assert invert_attributions({}).is_empty()


def test_rows_flatten_blocks_in_address_order():
    blocks = _blocks(
        (0x2000, ["0x2000 ret"]),
        (0x1000, ["0x1000 push rbp", "0x1004 mov rbp, rsp"]),
    )

    assert asm_row_addresses(blocks) == [0x1000, 0x1004, 0x2000]


def test_rows_keep_their_index_when_a_line_has_no_address():
    blocks = _blocks((0x1000, ["; a comment", "0x1000 ret"]))

    assert asm_row_addresses(blocks) == [None, 0x1000]


def test_rows_read_addresses_beyond_32_bits():
    blocks = _blocks((0x7FFF00001000, ["0x7fff00001000 ret"]))

    assert asm_row_addresses(blocks) == [0x7FFF00001000]


@pytest.mark.parametrize("blocks", [None, {}, "", 0])
def test_rows_of_an_unusable_blocks_payload_are_empty(blocks):
    assert asm_row_addresses(blocks) == []


def test_rows_tolerate_a_block_missing_its_fields():
    blocks = [{}, {"asm": None}, {"min_addr": 1, "asm": ["0x1 nop", 5]}]

    assert asm_row_addresses(blocks) == [0x1]


def _map():
    rows = [0x1000 + 4 * i for i in range(20)]
    return AttributionMap(invert_attributions(FORWARD), rows)


def test_a_decomp_line_resolves_to_its_disassembly_addresses():
    assert _map().addresses_for_decomp_line(4) == [0x1000 + 4 * 13, 0x1000 + 4 * 18]


def test_an_address_resolves_back_to_its_decomp_lines():
    assert _map().decomp_lines_for_address(0x1000 + 4 * 13) == [3, 4, 6]
    assert _map().decomp_lines_for_address(0x1000 + 4 * 18) == [4]


def test_the_disassembly_row_offset_is_applied_in_both_directions():
    rows = [0x1000 + 4 * i for i in range(20)]
    amap = AttributionMap(invert_attributions({"12": [3]}), rows)
    expected = rows[12 + DISASSEMBLY_ROW_OFFSET]

    assert amap.addresses_for_decomp_line(3) == [expected]
    assert amap.decomp_lines_for_address(expected) == [3]
    assert amap.decomp_lines_for_address(rows[12]) == []


def test_a_decomp_line_with_no_counterpart_resolves_to_nothing():
    assert _map().addresses_for_decomp_line(99) == []
    assert _map().decomp_lines_for_address(0xDEAD) == []


def test_rows_beyond_the_disassembly_are_skipped_rather_than_wrapping():
    amap = AttributionMap(invert_attributions({"12": [3]}), [0x1000, 0x1004])

    assert amap.addresses_for_decomp_line(3) == []


def test_one_address_on_several_rows_unions_their_decomp_lines():
    rows = [0x1000] * 20
    amap = AttributionMap(invert_attributions(FORWARD), rows)

    assert amap.decomp_lines_for_address(0x1000) == [3, 4, 6]


def test_a_map_without_attributions_or_rows_is_empty():
    assert AttributionMap().is_empty()
    assert AttributionMap(invert_attributions(FORWARD), []).is_empty()
    assert AttributionMap(invert_attributions({}), [0x1000]).is_empty()
    assert not _map().is_empty()
