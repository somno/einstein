"""
Protocol Command Structure - PIPG-41
"""

from .common import *


class SPpdu(Packet):  # PIPG-42
    name = "SPpdu"
    fields_desc = [
        ShortField("session_id", 0xE100), # "This field identifies a Protocol message. The field contains a fixed value 0xE100"
        ShortField("context_id", 2), # If a Computer Client encodes the Association Control protocol commands as suggested in "Definition of the Association Control Protocol" on page 65, the context_id for the Data Export protocol commands is 2.
    ]


def ROTypeField(name, default):
    enum = {
        ROIV_APDU: "ROIV_APDU",
        RORS_APDU: "RORS_APDU",
        ROER_APDU: "ROER_APDU",
        ROLRS_APDU: "ROLRS_APDU",
    }
    return ShortEnumField(name, default, enum)


class ROapdus(Packet):  # PIPG-42
    name = "ROapdus"
    fields_desc = [
        ROTypeField("ro_type", 0),
        LenField("length", None),
    ]


def CMDTypeField(name, default):  # PIPG-47
    enum = {
        CMD_EVENT_REPORT: "CMD_EVENT_REPORT",
        CMD_CONFIRMED_EVENT_REPORT: "CMD_CONFIRMED_EVENT_REPORT",
        CMD_GET: "CMD_GET",
        CMD_SET: "CMD_SET",
        CMD_CONFIRMED_SET: "CMD_CONFIRMED_SET",
        CMD_CONFIRMED_ACTION: "CMD_CONFIRMED_ACTION",
    }
    return ShortEnumField(name, default, enum)


class ROIVapdu(Packet):  # PIPG-43
    name = "ROIVapdu"
    fields_desc = [
        ShortField("invoke_id", 0),
        CMDTypeField("command_type", 0),
        LenField("length", None),
    ]


class RORSapdu(Packet):  # PIPG-43
    name = "RORSapdu"
    fields_desc = [
        ShortField("invoke_id", 0),
        CMDTypeField("command_type", 0),
        LenField("length", None),
    ]


class RorlsId(NonContainerPacket):  # PIPG-44
    name = "RorlsId"
    fields_desc = [
        ByteField("state", 0),  # TODO Enum
        ByteField("count", 0),
    ]


class ROLRSapdu(Packet):  # PIPG-44
    name = "ROLRSapdu"
    fields_desc = [
        PacketField("linked_id", RorlsId(), RorlsId),
        ShortField("invoke_id", 0),
        CMDTypeField("command_type", 0),
        LenField("length", None),
    ]


def ErrorValueField(name, default):  # PIPG-45
    enum = {
        NO_SUCH_OBJECT_CLASS: "NO_SUCH_OBJECT_CLASS",
        NO_SUCH_OBJECT_INSTANCE: "NO_SUCH_OBJECT_INSTANCE",
        ACCESS_DENIED: "ACCESS_DENIED",
        GET_LIST_ERROR: "GET_LIST_ERROR",
        SET_LIST_ERROR: "SET_LIST_ERROR",
        NO_SUCH_ACTION: "NO_SUCH_ACTION",
        PROCESSING_FAILURE: "PROCESSING_FAILURE",
        INVALID_ARGUMENT_VALUE: "INVALID_ARGUMENT_VALUE",
        INVALID_SCOPE: "INVALID_SCOPE",
        INVALID_OBJECT_INSTANCE: "INVALID_OBJECT_INSTANCE",
    }
    return ShortEnumField(name, default, enum)


class ROERapdu(NonContainerPacket):  # PIPG-45
    name = "ROERapdu"
    fields_desc = [
        ShortField("invoke_id", 0),
        ErrorValueField("error_value", 0),
        LenField("length", None),
    ]


class EventReportArgument(Packet):  # PIPG-48
    name = "EventReportArgument"
    fields_desc = [
        PacketField("managed_object", ManagedObjectId(), ManagedObjectId),
        RelativeTimeField("event_time", 0),
        OIDTypeField("event_type", 0),
        LenField("length", None),
    ]


class EventReportResult(NonContainerPacket):  # PIPG-48
    name = "EventReportResult"
    fields_desc = [
        PacketField("managed_object", ManagedObjectId(), ManagedObjectId),
        RelativeTimeField("current_time", 0),
        OIDTypeField("event_type", 0),
        LenField("length", None),
    ]
