from scapy import *

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
LIField = LenField  # TODO


CN_SPDU_SI = 0x0D  # PIPG-67 "CN_SPDU_SI: A Session Connect header. The message contains an Association Request"
AC_SPDU_SI = 0x0E  # PIPG-67 "AC_SPDU_SI: A Session Accept header. The message contains an Association Response, indicating that the association has been established."
RF_SPDU_SI = 0x0C  # PIPG-67 "RF_SPDU_SI: A Session Refuse header. An association could not be established."
FN_SPDU_SI = 0x09  # PIPG-67 "FN_SPDU_SI: A Session Finish header. The message contains a Release Request, indicating that the association should be terminated."
DN_SPDU_SI = 0x0A  # PIPG-67 "DN_SPDU_SI: A Session Disconnect header. The message contains a Release Response, indicating that the association has been terminated."
AB_SPDU_SI = 0x19  # PIPG-67 "AB_SPDU_SI: A Session Abort header. The message contains an Abort message, indicating the immediate termination of the association."


def SessionHeaderTypeField(name, default):  # PIPG-67
    enum = {
        CN_SPDU_SI: "CN_SPDU_SI",
        AC_SPDU_SI: "AC_SPDU_SI",
        RF_SPDU_SI: "RF_SPDU_SI",
        FN_SPDU_SI: "FN_SPDU_SI",
        DN_SPDU_SI: "DN_SPDU_SI",
        AB_SPDU_SI: "AB_SPDU_SI",
    }
    return ByteEnumField(name, default, enum)


class SessionHeader(Packet):
    name = "SessionHeader"
    fields_desc = [
        SessionHeaderTypeField("type", 0),
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
