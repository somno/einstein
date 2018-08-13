from scapy.all import *
from intellivue.association import LIField

class LIPacket(Packet):
    name = "LIPacket"
    fields_desc=[
        LIField("length", None),
    ]


def test_zero_length():
    p = LIPacket()
    p = LIPacket(p.build())
    assert p.length == 0


def test_zero_encoded():
    p = LIPacket()
    p = LIPacket(p.build())
    assert p.length == 0
    data = raw(p)
    assert len(data) == 1
    assert data[0] == '\x00'


def test_small_length():
    count = 4
    p = LIPacket() / ("A" * count)
    p = LIPacket(p.build())
    assert p.length == count


def test_small_encoded():
    count = 4
    p = LIPacket() / ("A" * count)
    p = LIPacket(p.build())
    assert p.length == count
    data = raw(p)
    assert len(data) == 1 + count
    assert data[0] == b"\x04"  # count


def test_large_length():
    count = 300
    p = LIPacket() / ("A" * count)
    p = LIPacket(p.build())
    assert p.length == count


def test_large_encoded():
    count = 300
    p = LIPacket() / ("A" * count)
    p = LIPacket(p.build())
    assert p.length == count
    data = raw(p)
    assert len(data) == 3 + count
    assert data[0:3] == b"\xff\x01\x2c"  # count
