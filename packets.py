from scapy.all import *

PORT_CONNECTION_INDICATION = 24005  # PIPG-279
PORT_PROTOCOL = 24105  # PIPG-29

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


class Nomenclature(NonContainerPacket):
    name = "Nomenclature"
    fields_desc = [
        ShortField("Magic", 0),
        ByteField("MajorVersion", 0),
        ByteField("MinorVersion", 0),
    ]


ROIV_APDU = 1
RORS_APDU = 2
ROER_APDU = 3
ROLRS_APDU = 5

def ROTypeField(name, default):
    enum = {
        ROIV_APDU: "ROIV_APDU",
        RORS_APDU: "RORS_APDU",
        ROER_APDU: "ROER_APDU",
        ROLRS_APDU: "ROLRS_APDU",
    }
    return ShortEnumField(name, default, enum)


class ROapdus(NonContainerPacket):
    name = "ROapdus"
    fields_desc = [
        ROTypeField("ro_type", 0),
        ShortField("length", 0),
    ]

    def extract_padding(self, p):
        return "", p

CMD_EVENT_REPORT = 0
CMD_CONFIRMED_EVENT_REPORT = 1
CMD_GET = 3
CMD_SET = 4
CMD_CONFIRMED_SET = 5
CMD_CONFIRMED_ACTION = 7

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


class ROIVapdu(NonContainerPacket):
    name = "ROIVapdu"
    fields_desc = [
        ShortField("invoke_id", 0),
        CMDTypeField("command_type", 0),
        ShortField("length", 0),
    ]

    def extract_padding(self, p):
        return "", p


class RORSapdu(NonContainerPacket):  # PIPG-43
    name = "RORSapdu"
    fields_desc = [
        ShortField("invoke_id", 0),
        CMDTypeField("command_type", 0),
        ShortField("length", 0),
    ]


NO_SUCH_OBJECT_CLASS = 0
NO_SUCH_OBJECT_INSTANCE = 1
ACCESS_DENIED = 2
GET_LIST_ERROR = 7
SET_LIST_ERROR = 8
NO_SUCH_ACTION = 9
PROCESSING_FAILURE = 10
INVALID_ARGUMENT_VALUE = 15
INVALID_SCOPE = 16
INVALID_OBJECT_INSTANCE = 17

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
        ShortField("length", 0),
    ]


OIDTypeField = ShortField

MdsContextField = ShortField

HandleField = ShortField

class GlbHandle(NonContainerPacket):
    name = "GlbHandle"
    fields_desc = [
        MdsContextField("context_id", 0),
        HandleField("handle", 0),
    ]


class ManagedObjectId(NonContainerPacket):
    name = "ManagedObjectId"
    fields_desc = [
        OIDTypeField("m_obj_class", 0),
        PacketField("m_obj_inst", GlbHandle(), GlbHandle),
    ]


RelativeTimeField = IntField

class EventReportArgument(NonContainerPacket):
    name = "EventReportArgument"
    fields_desc = [
        PacketField("managed_object", ManagedObjectId(), ManagedObjectId),
        RelativeTimeField("event_time", 0),
        OIDTypeField("event_type", 0),
        ShortField("length", 0),
    ]


class EventReportResult(NonContainerPacket):
    name = "EventReportResult"
    fields_desc = [
        PacketField("managed_object", ManagedObjectId(), ManagedObjectId),
        RelativeTimeField("current_time", 0),
        OIDTypeField("event_type", 0),
        ShortField("length", 0),
    ]


class AVAType(NonContainerPacket):
    name = "AVAType"
    fields_desc = [
        OIDTypeField("attribute_id", 0),
        FieldLenField("length", 0, length_of="attribute_val"),
        StrLenField("attribute_val", "", length_from=lambda p: p.length),
    ]


class AttributeList(Packet):
    name = "AttributeList"
    fields_desc = [
        FieldLenField("count", 0, count_of="value"),
        FieldLenField("length", 0, length_of="value"),
        PacketListField("value", [], AVAType, length_from=lambda p: p.length),
    ]


class ConnectIndication(NonContainerPacket):
    name = "ConnectIndication"
    fields_desc = [
        PacketField("Nomenclature", "", Nomenclature),
        PacketField("ROapdus", "", ROapdus),
        PacketField("ROIVapdu", "", ROIVapdu),
        PacketField("EventReportArgument", "", EventReportArgument),
        PacketField("ConnectIndInfo", "", AttributeList),
    ]


class SPpdu(NonContainerPacket):
    name = "SPpdu"
    fields_desc = [
        ShortField("session_id", 0xE100), # "This field identifies a Protocol message. The field contains a fixed value 0xE100"
        ShortField("context_id", 0),
    ]


class MDSCreateInfo(NonContainerPacket):
    name = "MDSCreateInfo"
    fields_desc = [
        PacketField("managed_object", ManagedObjectId(), ManagedObjectId),
        PacketField("attribute_list", AttributeList(), AttributeList),
    ]


class MDSCreateEventReport(NonContainerPacket):
    name = "MDSCreateEventReport"
    fields_desc = [
        PacketField("SPpdu", SPpdu(), SPpdu),
        PacketField("ROapdus", ROapdus(), ROapdus),
        PacketField("ROIVapdu", ROIVapdu(), ROIVapdu),
        PacketField("EventReportArgument", EventReportArgument(), EventReportArgument),
        PacketField("MDSCreateInfo", MDSCreateInfo(), MDSCreateInfo),
    ]


"""
The LI field contains the length of the appended data (including all presentation data). The length
encoding uses the following rules:
* If the length is smaller or equal 254 bytes, LI is one byte containing the actual length.
* If the length is greater than 254 bytes, LI is three bytes, the first being 0xff, the following two bytes
containing the actual length.
Examples:
L = 15 is encoded as 0x0f
L = 256 is encoded as {0xff,0x01,0x00}
"""
LIField = ShortField  # TODO


class SessionHeader(NonContainerPacket):
    name = "SessionHeader"
    fields_desc = [
        ByteEnumField("type", 0, {}), #TODO
        LIField("length", 0),
    ]


class AssocReqSessionHeader(NonContainerPacket):
    name = "AssocReqSessionHeader"
    fields_desc = [
        PacketField("SessionHeader", SessionHeader(), SessionHeader),
    ]


class AssocReqSessionData(NonContainerPacket):
    name = "AssocReqSessionData"
    fields_desc = [
        StrField("data", "\x05\x08\x13\x01\x00\x16\x01\x02\x80\x00\x14\x02\x00\x02"),  # Couldn't find a definition in the PIPG, this is copied from the example on page 298
    ]

class AssocReqPresentationHeader(NonContainerPacket):
    name = "AssocReqPresentationHeader"
    fields_desc = [
        # Couldn't find a definition in the PIPG, this is copied from the example on page 298
        StrField("", ""),
        LIField("LI", 0),
        StrField("data", ""),
    ]

class AssocReqUserData(NonContainerPacket): # TODO
    pass

class AssocReqPresentationTrailer(NonContainerPacket): # TODO
    pass


class AssociationRequestMessage(NonContainerPacket):
    name = "AssociationRequestMessage"
    fields_desc = [
        PacketField("AssocReqSessionHeader", AssocReqSessionHeader(), AssocReqSessionHeader),
        PacketField("AssocReqSessionData", AssocReqSessionData(), AssocReqSessionData),
        PacketField("AssocReqPresentationHeader", AssocReqPresentationHeader(), AssocReqPresentationHeader),
        PacketField("AssocReqUserData", AssocReqUserData(), AssocReqUserData),
        PacketField("AssocReqPresentationTrailer", AssocReqPresentationTrailer(), AssocReqPresentationTrailer),
    ]


class MDSCreateInfo(NonContainerPacket):  # PIPG-54
    name = "MDSCreateInfo"
    fields_desc = [
        PacketField("managed_object", ManagedObjectId(), ManagedObjectId),
        PacketField("attribute_list", AttributeList(), AttributeList),
    ]


class MDSCreateEventReport(NonContainerPacket):  # PIPG-54
    name = "MDSCreateEventReport"
    fields_desc = [
        PacketField("SPpdu", SPpdu(), SPpdu),
        PacketField("ROapdus", ROapdus(), ROapdus),
        PacketField("ROIVapdu", ROIVapdu(command_type=CMD_CONFIRMED_EVENT_REPORT), ROIVapdu),
        PacketField("EventReportArgument", EventReportArgument(), EventReportArgument),
        PacketField("MDSCreateInfo", MDSCreateInfo(), MDSCreateInfo),
    ]

class MDSCreateEventResult(NonContainerPacket):  # PIPG-55
    name = "MDSCreateEventResult"
    fields_desc = [
        PacketField("SPpdu", SPpdu(), SPpdu),
        PacketField("ROapdus", ROapdus(ro_type=RORS_APDU), ROapdus),
        PacketField("RORSapdu", RORSapdu(), RORSapdu),
        PacketField("EventReportResult", EventReportResult(), EventReportResult),
    ]


if __name__ == '__main__':
    cieDump = '\x00\x00\x01\x00\x00\x01\x01\xc2\x00\x00\x00\x00\x01\xbc\x00#\x00\x00\x00\x00\x00\xd6\xd4\x00\r\x17\x01\xae\x00\x0b\x01\xaa\t \x00\x04\x00\x03\x00\x00\t\x86\x00\x04\x00\x01\x11M\t7\x00\x08\x06\x08\x06\x08\x00\x01\x00\x0b\xf1Z\x00\x04\x00\x00\x00\x02\xf16\x00\x04\x00\x00\x00\x00\xf2|\x00\x1a\x00\x01\x80\x00\x00\x01\x00\x12\xf1\x00\x00\x0e\x00\t\xfb\tw\xbd\n\r%\x02\xff\xff\xff\x00\xf15\x00"\x00E\x00C\x00C\x00 \x00M\x00O\x00N\x00 \x00R\x00M\x001\x005\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf1\x00\x00\x0e\x00\t\xfb\tw\xbd\n\r%\x02\xff\xff\xff\x00\xf1\x01\x00,\x00\x05\x00(\x00\x01\x00\x03]\xc0\x00\x00\x00\x02\x00\x03]\xc0\x00\x00\x00\x01\x00\x01^)\x00\x00\x00\x05\x00\x01^)\x00\x00\x00\x08\x00\x01\x825\x00\x00\t-\x00\xdc\x00\x06\x00d\x00\x01\x00\x08\x00\x0cDE22713007\x00\t\x00\x02\x00\x08\x00\x0eM8007A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x08\x00\x08 B.00.05\x00\x05\x00x\x00\x08--------\x00\x02\x00X\x00\x0eS-M4046-1701A \x00\x04\x00X\x00\x08G.01.78 \x00\x07\x00\x86\x00\x01\x00\x08\x00\x0cDE22713007\x00\t\x00\x02\x00\x08\x00\x0eM8007A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x08\x00\x08 B.00.05\x00\x05\x00x\x00\x08--------\x00\x02\x00X\x00\x0eS-M4046-1701A \x00\x04\x00X\x00\x08G.01.78 \x00\x02\x00X\x00\x0eS-M404\t(\x00\x14\x00\x08Philips\x00\x00\x07M8007A\x00\x00'

    print cieDump

    cie = ConnectIndication()
    cie.dissect(cieDump)
    cie.show()
