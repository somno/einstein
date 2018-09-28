"""
Attribute Data Types - PIPG-75
"""

from scapy.all import *
from .common import *


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


ENUM_MEASUREMENT_STATE = {
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

def MeasurementStateField(name, default):  # PIPG-76
    flags = [v for (_, v) in sorted(ENUM_MEASUREMENT_STATE.items())]
    return FlagsField(name, default, 16, flags)


class NuObsValue(NonContainerPacket):  # PIPG-76
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


class IpAddressInfo(Packet):  # PIPG-109
    name = "IpAddressInfo"
    fields_desc = [
        MACField("mac_address", 0),
        IPField("ip_address", 0),
        IPField("subnet_mask", 0),
    ]
