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


class Nomenclature(NonContainerPacket):
    name = "Nomenclature"
    fields_desc = [
        ShortField("Magic", 0),
        ByteField("MajorVersion", 0),
        ByteField("MinorVersion", 0),
    ]



class ROapdus(NonContainerPacket):
    name = "ROapdus"
    fields_desc = [
        ShortField("ro_type", 0), # TODO Enum?
        ShortField("length", 0),
    ]

    def extract_padding(self, p):
        return "", p

# TODO Make this an Int Enum Field of some sort
CMDTypeField = ShortField

class ROIVapdu(NonContainerPacket):
    name = "ROIVapdu"
    fields_desc = [
        ShortField("invoke_id", 0),
        CMDTypeField("command_type", 0),
        ShortField("length", 0),
    ]

    def extract_padding(self, p):
        return "", p


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


if __name__ == '__main__':
    cieDump = '\x00\x00\x01\x00\x00\x01\x01\xc2\x00\x00\x00\x00\x01\xbc\x00#\x00\x00\x00\x00\x00\xd6\xd4\x00\r\x17\x01\xae\x00\x0b\x01\xaa\t \x00\x04\x00\x03\x00\x00\t\x86\x00\x04\x00\x01\x11M\t7\x00\x08\x06\x08\x06\x08\x00\x01\x00\x0b\xf1Z\x00\x04\x00\x00\x00\x02\xf16\x00\x04\x00\x00\x00\x00\xf2|\x00\x1a\x00\x01\x80\x00\x00\x01\x00\x12\xf1\x00\x00\x0e\x00\t\xfb\tw\xbd\n\r%\x02\xff\xff\xff\x00\xf15\x00"\x00E\x00C\x00C\x00 \x00M\x00O\x00N\x00 \x00R\x00M\x001\x005\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf1\x00\x00\x0e\x00\t\xfb\tw\xbd\n\r%\x02\xff\xff\xff\x00\xf1\x01\x00,\x00\x05\x00(\x00\x01\x00\x03]\xc0\x00\x00\x00\x02\x00\x03]\xc0\x00\x00\x00\x01\x00\x01^)\x00\x00\x00\x05\x00\x01^)\x00\x00\x00\x08\x00\x01\x825\x00\x00\t-\x00\xdc\x00\x06\x00d\x00\x01\x00\x08\x00\x0cDE22713007\x00\t\x00\x02\x00\x08\x00\x0eM8007A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x08\x00\x08 B.00.05\x00\x05\x00x\x00\x08--------\x00\x02\x00X\x00\x0eS-M4046-1701A \x00\x04\x00X\x00\x08G.01.78 \x00\x07\x00\x86\x00\x01\x00\x08\x00\x0cDE22713007\x00\t\x00\x02\x00\x08\x00\x0eM8007A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x08\x00\x08 B.00.05\x00\x05\x00x\x00\x08--------\x00\x02\x00X\x00\x0eS-M4046-1701A \x00\x04\x00X\x00\x08G.01.78 \x00\x02\x00X\x00\x0eS-M404\t(\x00\x14\x00\x08Philips\x00\x00\x07M8007A\x00\x00'

    print cieDump

    cie = ConnectIndication()
    cie.dissect(cieDump)
    cie.show()
