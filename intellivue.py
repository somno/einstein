"""
Core structures / functionality for interfacing with a Philips IntelliVue Patient Monitor.

Based on the Philips Data Export Interface Programming Guide - id 4535 642 59271 - the "Philips Interface Programming Guide".
"""

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


class Nomenclature(Packet):
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


class ROapdus(Packet):
    name = "ROapdus"
    fields_desc = [
        ROTypeField("ro_type", 0),
        LenField("length", None),
    ]


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


class ROIVapdu(Packet):
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
        LenField("length", None),
    ]


NOM_DIM_PERCENT = 544
NOM_ATTR_GRP_METRIC_VAL_OBS = 2051
NOM_ATTR_NU_VAL_OBS = 2384
NOM_ATTR_TIME_STAMP_ABS = 2448
NOM_DIM_BEAT_PER_MIN = 2720
NOM_DIM_RESP_PER_MIN = 2784
NOM_ACT_POLL_MDIB_DATA = 3094
NOM_NOTI_MDS_CREAT = 3334
NOM_NOTI_CONN_INDIC = 3351
NOM_NOTI_MDS_CONNECT_INDIC = NOM_NOTI_CONN_INDIC  # These appear to be the same based on experimental data / PIPG-53
NOM_DEV_PULS_VMD = 5138
NOM_ECG_CARD_BEAT_RATE = 16770
NOM_ECG_V_P_C_CNT = 16993
NOM_PLETH_PULS_RATE = 18466
NOM_PULS_OXIM_PERF_REL = 19376
NOM_PULS_OXIM_SAT_O2 = 19384
NOM_RESP_RATE = 20490
NOM_SAT_O2_TONE_FREQ = 61448
NOM_PRESS_BLD_NONINV_PULS_RATE = 61669
NOM_ATTR_NET_ADDR_INFO = 61696

def OIDTypeField(name, default):
    """
    Currently this is a simple ShortEnumField.
    The reality is more complex.
    From PIPG-37: "Values for the OIDType (the nomenclature) are listed at the end of the section "Attribute Data Types and Constants Used" on page 75. Independent value ranges (partitions) exist, e.g. for physiological identifiers, alert condition identifiers, units of measurement etc."
    These partitions overlap: 61696 is NOM_ATTR_NET_ADDR_INFO in NOM_PART_OBJ and NOM_SAT_O2_VEN_CENT in NOM_PART_SCADA.
    So the actual enum is context dependent, either because it's embedded in a TYPE object, or contextually.

    TODO: Implement partition support
    """
    enum = {
        NOM_DIM_PERCENT: "NOM_DIM_PERCENT",
        NOM_ATTR_GRP_METRIC_VAL_OBS: "NOM_ATTR_GRP_METRIC_VAL_OBS",
        NOM_ATTR_NU_VAL_OBS: "NOM_ATTR_NU_VAL_OBS",
        NOM_ATTR_TIME_STAMP_ABS: "NOM_ATTR_TIME_STAMP_ABS",
        NOM_DIM_BEAT_PER_MIN: "NOM_DIM_BEAT_PER_MIN",
        NOM_DIM_RESP_PER_MIN: "NOM_DIM_RESP_PER_MIN",
        NOM_ACT_POLL_MDIB_DATA: "NOM_ACT_POLL_MDIB_DATA",
        NOM_NOTI_MDS_CREAT: "NOM_NOTI_MDS_CREAT",
        NOM_NOTI_CONN_INDIC: "NOM_NOTI_CONN_INDIC",
        NOM_DEV_PULS_VMD: "NOM_DEV_PULS_VMD",
        NOM_ECG_CARD_BEAT_RATE: "NOM_ECG_CARD_BEAT_RATE",
        NOM_ECG_V_P_C_CNT: "NOM_ECG_V_P_C_CNT",
        NOM_PLETH_PULS_RATE: "NOM_PLETH_PULS_RATE",
        NOM_PULS_OXIM_PERF_REL: "NOM_PULS_OXIM_PERF_REL",
        NOM_PULS_OXIM_SAT_O2: "NOM_PULS_OXIM_SAT_O2",
        NOM_RESP_RATE: "NOM_RESP_RATE",
        NOM_SAT_O2_TONE_FREQ: "NOM_SAT_O2_TONE_FREQ",
        NOM_PRESS_BLD_NONINV_PULS_RATE: "NOM_PRESS_BLD_NONINV_PULS_RATE",
        NOM_ATTR_NET_ADDR_INFO: "NOM_ATTR_NET_ADDR_INFO",
    }
    return ShortEnumField(name, default, enum)


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


class AbsoluteTime(NonContainerPacket):
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


class EventReportArgument(Packet):
    name = "EventReportArgument"
    fields_desc = [
        PacketField("managed_object", ManagedObjectId(), ManagedObjectId),
        RelativeTimeField("event_time", 0),
        OIDTypeField("event_type", 0),
        LenField("length", None),
    ]


class EventReportResult(NonContainerPacket):
    name = "EventReportResult"
    fields_desc = [
        PacketField("managed_object", ManagedObjectId(), ManagedObjectId),
        RelativeTimeField("current_time", 0),
        OIDTypeField("event_type", 0),
        LenField("length", None),
    ]


INVALID = 0x8000
QUESTIONABLE = 0x4000
UNAVAILABLE = 0x2000
CALIBRATION_ONGOING = 0x1000
TEST_DATA = 0x0800
DEMO_DATA = 0x0400
MEASUREMENT_STATE_UNDEFINED1 = 0x0200
MEASUREMENT_STATE_UNDEFINED2 = 0x0100
VALIDATED_DATA = 0x0080
EARLY_INDICATION = 0x0040
MSMT_ONGOING = 0x0020
MEASUREMENT_STATE_UNDEFINED3 = 0x0010
MEASUREMENT_STATE_UNDEFINED4 = 0x0008
MEASUREMENT_STATE_UNDEFINED5 = 0x0004
MSMT_STATE_IN_ALARM = 0x0002
MSMT_STATE_AL_INHIBITED = 0x0001


def MeasurementStateField(name, default):  # PIPG-76
    enum = {
        INVALID: "INVALID",
        QUESTIONABLE: "QUESTIONABLE",
        UNAVAILABLE: "UNAVAILABLE",
        CALIBRATION_ONGOING: "CALIBRATION_ONGOING",
        TEST_DATA: "TEST_DATA",
        DEMO_DATA: "DEMO_DATA",
        MEASUREMENT_STATE_UNDEFINED1: "MEASUREMENT_STATE_UNDEFINED1",
        MEASUREMENT_STATE_UNDEFINED2: "MEASUREMENT_STATE_UNDEFINED2",
        VALIDATED_DATA: "VALIDATED_DATA",
        EARLY_INDICATION: "EARLY_INDICATION",
        MSMT_ONGOING: "MSMT_ONGOING",
        MEASUREMENT_STATE_UNDEFINED3: "MEASUREMENT_STATE_UNDEFINED3",
        MEASUREMENT_STATE_UNDEFINED4: "MEASUREMENT_STATE_UNDEFINED4",
        MEASUREMENT_STATE_UNDEFINED5: "MEASUREMENT_STATE_UNDEFINED5",
        MSMT_STATE_IN_ALARM: "MSMT_STATE_IN_ALARM",
        MSMT_STATE_AL_INHIBITED: "MSMT_STATE_AL_INHIBITED",
    }
    flags = [v for (_, v) in sorted(enum.items())]
    return FlagsField(name, default, 16, flags)


FLOATTypeField = XIntField  # TODO


class NuObsValue(NonContainerPacket):
    name = "NuObsValue"
    fields_desc = [
        OIDTypeField("physio_id", 0),
        MeasurementStateField("state", 0),
        OIDTypeField("unit_code", 0),
        FLOATTypeField("value", 0),
    ]

    def measurementIsValid(self):  # PIPG-77
        """
        "The measurement is valid if the first octet of the state is all 0."
        """
        return self.state < 0x1000


class IpAddressInfo(Packet):
    name = "IpAddressInfo"
    fields_desc = [
        MACField("mac_address", 0),
        IPField("ip_address", 0),
        IPField("subnet_mask", 0),
    ]


PrivateOidField = ShortField  # PIPG-37


class VariableLabel(Packet):
    name = "VariableLabel"
    fields_desc = [
        FieldLenField("length", 0, length_of="value"),
        StrLenField("value", "", length_from="length"),
    ]


class AVAType(Packet):
    name = "AVAType"
    fields_desc = [
        OIDTypeField("attribute_id", 0),
        LenField("length", None),
    ]

    def extract_padding(self, p):
        return p[:self.length], p[self.length:]


class AttributeList(NonContainerPacket):
    name = "AttributeList"
    fields_desc = [
        FieldLenField("count", 0, count_of="value"),
        FieldLenField("length", 0, length_of="value"),
        PacketListField("value", [], AVAType, length_from=lambda p: p.length, count_from=lambda p: p.count),
    ]


def ConnectIndication():
    return Nomenclature() / ROapdus() / ROIVapdu() / EventReportArgument() / AttributeList()


class SPpdu(Packet):  # PIPG-42
    name = "SPpdu"
    fields_desc = [
        ShortField("session_id", 0xE100), # "This field identifies a Protocol message. The field contains a fixed value 0xE100"
        ShortField("context_id", 2), # If a Computer Client encodes the Association Control protocol commands as suggested in "Definition of the Association Control Protocol" on page 65, the context_id for the Data Export protocol commands is 2.
    ]


class MDSCreateInfo(NonContainerPacket):
    name = "MDSCreateInfo"
    fields_desc = [
        PacketField("managed_object", ManagedObjectId(), ManagedObjectId),
        PacketField("attribute_list", AttributeList(), AttributeList),
    ]


def MDSCreateEventReport():
    return SPpdu() / ROapdus() / ROIVapdu() / EventReportArgument() / MDSCreateInfo()


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

def MDSCreateEventResult():  # PIPG-55
    name = "MDSCreateEventResult"
    fields_desc = [
        PacketField("SPpdu", SPpdu(), SPpdu),
        PacketField("ROapdus", ROapdus(ro_type=RORS_APDU), ROapdus),
        PacketField("RORSapdu", RORSapdu(command_type=CMD_CONFIRMED_EVENT_REPORT), RORSapdu),
        PacketField("EventReportResult", EventReportResult(), EventReportResult),
    ]


class ActionArgument(Packet):
    name = "ActionArgument"
    fields_desc = [
        PacketField("managed_object", ManagedObjectId(), ManagedObjectId),
        IntField("scope", 0),
        OIDTypeField("action_type", 0),
        LenField("length", None),
    ]


NOM_PART_OBJ = 1
NOM_PART_SCADA = 2
NOM_PART_EVT = 3
NOM_PART_DIM = 4
NOM_PART_PGRP = 6
NOM_PART_INFRASTRUCT = 8


def NomPartitionField(name, default):
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


class PollMdibDataReq(NonContainerPacket):
    name = "PollMdibDataReq"
    fields_desc = [
        ShortField("poll_number", 0),
        PacketField("polled_obj_type", TYPE(), TYPE),
        OIDTypeField("polled_attr_grp", 0),
    ]


class ActionResult(Packet):
    name = "ActionResult"
    fields_desc = [
        PacketField("managed_object", ManagedObjectId(), ManagedObjectId),
        OIDTypeField("action_type", 0),
        LenField("length", None),
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


class PollInfoList(Packet):
    name = "PollInfoList"
    fields_desc = [
        FieldLenField("count", 0, count_of="value"),
        FieldLenField("length", 0, length_of="value"),
        PacketListField("value", [], SingleContextPoll, length_from=lambda p: p.length),
    ]


class PollMdibDataReply(Packet):
    name = "PollMdibDataReply"
    fields_desc = [
        ShortField("poll_number", 0),
        RelativeTimeField("rel_time_stamp", 0),
        PacketField("abs_time_stamp", AbsoluteTime(), AbsoluteTime),
        PacketField("polled_obj_type", TYPE(), TYPE),
        OIDTypeField("polled_attr_grp", 0),
        PacketField("poll_info_list", PollInfoList(), PollInfoList),
    ]


ReleaseRequest = "\x09\x18\xC1\x16\x61\x80\x30\x80\x02\x01\x01\xA0\x80\x62\x80\x80\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # PIPG-301


# TODO Relocate / flesh these out
NOM_MOC_VMO_METRIC_NU = 6
NOM_MOC_VMS_MDS = 33

bind_layers(Nomenclature, ROapdus)
bind_layers(SPpdu, ROapdus)
bind_layers(ROapdus, RORSapdu, ro_type=RORS_APDU)
bind_layers(ROapdus, ROIVapdu, ro_type=ROIV_APDU)
bind_layers(ROapdus, ROERapdu, ro_type=ROER_APDU)
bind_layers(ROapdus, ROLRSapdu, ro_type=ROLRS_APDU)
bind_layers(ROIVapdu, EventReportArgument, command_type=CMD_EVENT_REPORT)
bind_layers(ROIVapdu, EventReportArgument, command_type=CMD_CONFIRMED_EVENT_REPORT)
bind_layers(ROIVapdu, ActionArgument, command_type=CMD_CONFIRMED_ACTION)
bind_layers(RORSapdu, EventReportResult, command_type=CMD_CONFIRMED_EVENT_REPORT)
bind_layers(RORSapdu, ActionResult, command_type=CMD_CONFIRMED_ACTION)
bind_layers(ROLRSapdu, ActionResult, command_type=CMD_CONFIRMED_ACTION)
bind_layers(EventReportArgument, MDSCreateInfo, event_type=NOM_NOTI_MDS_CREAT)
bind_layers(ActionArgument, PollMdibDataReq, action_type=NOM_ACT_POLL_MDIB_DATA)
bind_layers(ActionResult, PollMdibDataReply, action_type=NOM_ACT_POLL_MDIB_DATA)
bind_layers(EventReportArgument, AttributeList, event_type=NOM_NOTI_MDS_CONNECT_INDIC)
bind_layers(AVAType, NuObsValue, attribute_id=NOM_ATTR_NU_VAL_OBS)
bind_layers(AVAType, AbsoluteTime, attribute_id=NOM_ATTR_TIME_STAMP_ABS)
bind_layers(AVAType, IpAddressInfo, attribute_id=NOM_ATTR_NET_ADDR_INFO)


if __name__ == '__main__':
    cieDump = '\x00\x00\x01\x00\x00\x01\x01\xc2\x00\x00\x00\x00\x01\xbc\x00#\x00\x00\x00\x00\x00\xd6\xd4\x00\r\x17\x01\xae\x00\x0b\x01\xaa\t \x00\x04\x00\x03\x00\x00\t\x86\x00\x04\x00\x01\x11M\t7\x00\x08\x06\x08\x06\x08\x00\x01\x00\x0b\xf1Z\x00\x04\x00\x00\x00\x02\xf16\x00\x04\x00\x00\x00\x00\xf2|\x00\x1a\x00\x01\x80\x00\x00\x01\x00\x12\xf1\x00\x00\x0e\x00\t\xfb\tw\xbd\n\r%\x02\xff\xff\xff\x00\xf15\x00"\x00E\x00C\x00C\x00 \x00M\x00O\x00N\x00 \x00R\x00M\x001\x005\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf1\x00\x00\x0e\x00\t\xfb\tw\xbd\n\r%\x02\xff\xff\xff\x00\xf1\x01\x00,\x00\x05\x00(\x00\x01\x00\x03]\xc0\x00\x00\x00\x02\x00\x03]\xc0\x00\x00\x00\x01\x00\x01^)\x00\x00\x00\x05\x00\x01^)\x00\x00\x00\x08\x00\x01\x825\x00\x00\t-\x00\xdc\x00\x06\x00d\x00\x01\x00\x08\x00\x0cDE22713007\x00\t\x00\x02\x00\x08\x00\x0eM8007A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x08\x00\x08 B.00.05\x00\x05\x00x\x00\x08--------\x00\x02\x00X\x00\x0eS-M4046-1701A \x00\x04\x00X\x00\x08G.01.78 \x00\x07\x00\x86\x00\x01\x00\x08\x00\x0cDE22713007\x00\t\x00\x02\x00\x08\x00\x0eM8007A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x08\x00\x08 B.00.05\x00\x05\x00x\x00\x08--------\x00\x02\x00X\x00\x0eS-M4046-1701A \x00\x04\x00X\x00\x08G.01.78 \x00\x02\x00X\x00\x0eS-M404\t(\x00\x14\x00\x08Philips\x00\x00\x07M8007A\x00\x00'

    print(cieDump)

    n = Nomenclature()
    n.dissect(cieDump)
    n.show()
