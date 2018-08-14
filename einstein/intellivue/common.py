"""
Common Data Types - PIPG-36
"""

from scapy.all import *


class NonContainerPacket(Packet):
    """
    A Packet that cannot contain other things.
    An IP Packet can contain TCP Packets which can contain e.g. HTTP Packets.
    This protocol uses field-like things that are more like complex structs.
    Packet (and PacketField) seem the right tools to represent these,
    but it's important to indicate to Scapy that they will not contain any other data,
    via extract_padding (thanks to https://stackoverflow.com/a/38836550/928098)
    """

    def extract_padding(self, p):
        return "", p


class AbsoluteTime(NonContainerPacket):  # PIPG-36
    name = "AbsoluteTime"
    fields_desc = [
        ByteField("century", 0),
        ByteField("year", 0),
        ByteField("month", 0),
        ByteField("day", 0),
        ByteField("hour", 0),
        ByteField("minute", 0),
        ByteField("second", 0),
        ByteField("sec_fractions", 0),
    ]


RelativeTimeField = IntField  # PIPG-36
