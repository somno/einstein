from .protocol_commands import *

def test_basic_connect_indication():
    p = ConnectIndication()
    p.build()


def test_basic_mds_create_event_report():
    p = MDSCreateEventReport()
    p.build()
