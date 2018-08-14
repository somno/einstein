"""
Common Data Types - PIPG-36
"""

from scapy.all import *

from .const import *


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


def OIDTypeField(name, default):  # PIPG-37
    """
    Currently this is a simple ShortEnumField.
    The reality is more complex.
    From PIPG-37: "Values for the OIDType (the nomenclature) are listed at the end of the section "Attribute Data Types and Constants Used" on page 75. Independent value ranges (partitions) exist, e.g. for physiological identifiers, alert condition identifiers, units of measurement etc."
    These partitions overlap: 61696 is NOM_ATTR_NET_ADDR_INFO in NOM_PART_OBJ and NOM_SAT_O2_VEN_CENT in NOM_PART_SCADA.
    So the actual enum is context dependent, either because it's embedded in a TYPE object, or contextually.

    TODO: Implement partition support
    """
    return ShortEnumField(name, default, ENUM_IDENTIFIERS)


PrivateOidField = ShortField  # PIPG-37


def NomPartitionField(name, default):  # PIPG-37
    enum = {
        NOM_PART_OBJ: "NOM_PART_OBJ",
        NOM_PART_SCADA: "NOM_PART_SCADA",
        NOM_PART_EVT: "NOM_PART_EVT",
        NOM_PART_DIM: "NOM_PART_DIM",
        NOM_PART_PGRP: "NOM_PART_PGRP",
        NOM_PART_INFRASTRUCT: "NOM_PART_INFRASTRUCT",
    }
    return ShortEnumField(name, default, enum)


class TYPE(NonContainerPacket):  # PIPG-37
    name = "TYPE"
    fields_desc = [
        NomPartitionField("partition", 0),
        OIDTypeField("code", 0),
    ]


HandleField = ShortField  # PIPG-38


MdsContextField = ShortField  # PIPG-38


class GlbHandle(NonContainerPacket):  # PIPG-38
    name = "GlbHandle"
    fields_desc = [
        MdsContextField("context_id", 0),
        HandleField("handle", 0),
    ]


class ManagedObjectId(NonContainerPacket):  # PIPG-38
    name = "ManagedObjectId"
    fields_desc = [
        OIDTypeField("m_obj_class", 0),
        PacketField("m_obj_inst", GlbHandle(), GlbHandle),
    ]


class AVAType(Packet):  # PIPG-38
    name = "AVAType"
    fields_desc = [
        OIDTypeField("attribute_id", 0),
        LenField("length", None),
    ]

    def extract_padding(self, p):
        return p[:self.length], p[self.length:]


class AttributeList(NonContainerPacket):  # PIPG-39
    name = "AttributeList"
    fields_desc = [
        FieldLenField("count", 0, count_of="value"),
        FieldLenField("length", 0, length_of="value"),
        PacketListField("value", [], AVAType, length_from=lambda p: p.length, count_from=lambda p: p.count),
    ]


class String(Packet):  # PIPG-39
    pass  # TODO
