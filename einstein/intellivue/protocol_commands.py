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


class PollMdibDataReq(NonContainerPacket):  # PIPG-55
    name = "PollMdibDataReq"
    fields_desc = [
        ShortField("poll_number", 0),
        PacketField("polled_obj_type", TYPE(), TYPE),
        OIDTypeField("polled_attr_grp", 0),
    ]


class ObservationPoll(NonContainerPacket):  # PIPG-58
    name = "ObservationPoll"
    fields_desc = [
        HandleField("obj_handle", 0),
        PacketField("attributes", AttributeList(), AttributeList),
    ]


class SingleContextPoll(NonContainerPacket):  # PIPG-58
    """
    This inlines the poll_info structure, but it doesn't seem to be used elsewhere
    """
    name = "SingleContextPoll"
    fields_desc = [
        MdsContextField("context_id", 0),
        FieldLenField("count", 0, count_of="value"),
        FieldLenField("length", 0, length_of="value"),
        PacketListField("value", [], ObservationPoll, length_from=lambda p: p.length),
    ]


class PollInfoList(Packet):  # PIPG-57
    name = "PollInfoList"
    fields_desc = [
        FieldLenField("count", 0, count_of="value"),
        FieldLenField("length", 0, length_of="value"),
        PacketListField("value", [], SingleContextPoll, length_from=lambda p: p.length),
    ]


class PollMdibDataReply(Packet):  # PIPG-56
    name = "PollMdibDataReply"
    fields_desc = [
        ShortField("poll_number", 0),
        RelativeTimeField("rel_time_stamp", 0),
        PacketField("abs_time_stamp", AbsoluteTime(), AbsoluteTime),
        PacketField("polled_obj_type", TYPE(), TYPE),
        OIDTypeField("polled_attr_grp", 0),
        PacketField("poll_info_list", PollInfoList(), PollInfoList),
    ]

class PollMdibDataReqExt(Packet):  # PIPG-59
    name = "PollMdibDataReqExt"
    fields_desc = [
        ShortField("poll_number", 0),
        PacketField("polled_obj_type", TYPE(), TYPE),
        OIDTypeField("polled_attr_grp", None),
        PacketField("poll_ext_attr", AttributeList(), AttributeList),
    ]

class PollMdibDataReplyExt(Packet):  # PIPG-62
    name = "PollMdibDataReplyExt"
    fields_desc = [
        ShortField("poll_number", None),
        ShortField("sequence_no", None),
        RelativeTimeField("rel_time_stamp", None),
        PacketField("abs_time_stamp", AbsoluteTime(), AbsoluteTime),
        PacketField("polled_obj_type", TYPE(), TYPE),
        OIDTypeField("polled_attr_grp", 0),
        PacketField("poll_info_list", PollInfoList(), PollInfoList),
    ]
