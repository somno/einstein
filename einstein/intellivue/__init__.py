"""
Core structures / functionality for interfacing with a Philips IntelliVue Patient Monitor.

Based on the Philips Data Export Interface Programming Guide - id 4535 642 59271 - the "Philips Interface Programming Guide".
"""

from scapy.all import *
import float_type
from .const import *
from .common import *
from .protocol_command_structure import *

PORT_CONNECTION_INDICATION = 24005  # PIPG-279
PORT_PROTOCOL = 24105  # PIPG-29

class Nomenclature(Packet):
    name = "Nomenclature"
    fields_desc = [
        ShortField("Magic", 0),
        ByteField("MajorVersion", 0),
        ByteField("MinorVersion", 0),
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


def ConnectIndication():
    return Nomenclature() / ROapdus() / ROIVapdu() / EventReportArgument() / AttributeList()


class MDSCreateInfo(NonContainerPacket):
    name = "MDSCreateInfo"
    fields_desc = [
        PacketField("managed_object", ManagedObjectId(), ManagedObjectId),
        PacketField("attribute_list", AttributeList(), AttributeList),
    ]


def MDSCreateEventReport():
    return SPpdu() / ROapdus() / ROIVapdu() / EventReportArgument() / MDSCreateInfo()


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


class PollMdibDataReq(NonContainerPacket):
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
