import float_type
import math
import pytest

def test_basic():
    assert float_type.decode(1) == 1


def test_too_big():
    with pytest.raises(ValueError):
        float_type.decode(0xffffffffffffffffffff)


def test_count_hex_digits():
    assert float_type.count_hex_digits(0x0) == 0
    assert float_type.count_hex_digits(0x1) == 1
    assert float_type.count_hex_digits(0x10) == 2
    assert float_type.count_hex_digits(0x01) == 1
    assert float_type.count_hex_digits(0x11) == 2
    assert float_type.count_hex_digits(0x100) == 3


def test_documented_examples():
    # PIPG-41

    assert float_type.decode(0xfd007d00) == 32
    assert float_type.decode(0xff000140) == 32

    assert float_type.decode(0x01000140) == 3200
    assert float_type.decode(0x02000020) == 3200


def test_inferred_special_values():
    assert math.isnan(float_type.decode(0x007fffff))
    assert math.isnan(float_type.decode(0x00800000))  # "Not at this resolution"


# There is no decode-encode identity because encodings aren't normalised
@pytest.mark.skip(reason="No decode implementation and no Hypothesis hookup yet")
def test_encode_decode_identity(num):
    assert float_type.decode(float_type.encode(num)) == num
