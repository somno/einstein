"""
Protocol Commands - PIPG-52
"""

from scapy.all import *

from .protocol_command_structure import *


class Nomenclature(Packet):  # PIPG-53
    name = "Nomenclature"
    fields_desc = [
        ShortField("Magic", 0),
        ByteField("MajorVersion", 0),
        ByteField("MinorVersion", 0),
    ]


def ConnectIndication():  # PIPG-53
    return Nomenclature() / ROapdus() / ROIVapdu() / EventReportArgument() / AttributeList()


class MDSCreateInfo(NonContainerPacket):  # PIPG-54
    name = "MDSCreateInfo"
    fields_desc = [
        PacketField("managed_object", ManagedObjectId(), ManagedObjectId),
        PacketField("attribute_list", AttributeList(), AttributeList),
    ]


def MDSCreateEventReport():  # PIPG-54
    return SPpdu() / ROapdus() / ROIVapdu() / EventReportArgument() / MDSCreateInfo()
