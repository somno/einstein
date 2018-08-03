"""
The IntelliVue uses its own custom non-IEEE-754 fp encoding.

These functions handle this encoding.

Note that the exponent is decimal, so there should be none of the common
binary/decimal representation issues that IEEE-754 has.

PIPG-40
"""


def decode(encoded):
    if len(hex(encoded)) > (2 + 32/4):  # Check this is a 32-bit value!
        raise ValueError

    mantissa = encoded & 0x00FFFFFF

    # Special cases key on mantissa
    if mantissa == 0x7fffff:
        return float("NaN")
    elif mantissa == 0x800000:
        return float("NaN") # TODO Need an encoding for NRes ("Not at this resolution")
    elif mantissa == 0x7ffffe:
        return Inf
    elif mantissa == 0x800002:
        return -Inf

    if mantissa >> 23 == 1:  # Is the most significant (i.e. sign) bit set)
        mantissa = mantissa - 0xFFFFFF - 1

    exponent = (encoded & 0xFF000000) >> 24
    if exponent >> 7 == 1:  # Is the most significant (i.e. sign) bit set)
        exponent = exponent - 0xFF - 1

    return mantissa * (10 ** exponent)

def encode(num):
    return num
