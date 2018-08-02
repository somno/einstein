from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.web import server
import api
import datetime
import json
import socket
import intellivue as packets
import treq
import web
import vscapture
from util import json_serialize
import attr

ASSOCIATION_REQUEST_MESSAGE = vscapture.aarq_msg

class IntellivueInterface(DatagramProtocol):
    """
    Handles communication with a Philips IntelliVue

    Currently a demo implementation - listens for existence announcements,
    associates, connects, and polls all connected monitors for basic data.

    The MAC address is the canonical form of monitor id;
    it's an (effectively) immutable property of the device.
    The IP address is what's actually used internally,
    because that's the layer things run at,
    but it's not exposed via the web API,
    and instead an internal DIY "ARP-alike" mapping is maintained.
    """

    def __init__(self, monitors=None, subscriptions=None):
        self.monitors = monitors
        if self.monitors is None:
            self.monitors = {}  # Mapping of MAC -> api.Monitor

        self.subscriptions = subscriptions
        if self.subscriptions is None:
            self.subscriptions = {}  # Mapping of MAC -> [Subscriber URL]

        self.host_to_mac = {}
        self.associations = set()
        self.connections = set()


    def datagramReceived(self, data, (host, port)):
        print("Datagram received!")

        if port == packets.PORT_CONNECTION_INDICATION:
            self.handleConnectionIndication(data, (host, port))
        else:
            if data[0:2] == '\xe1\x00':  # PIPG-42
                self.handleProtocolMessage(data, (host, port))
            else:
                self.handleAssociationMessage(data, (host, port))


    def handleConnectionIndication(self, data, (host, port)):
        ci = packets.ConnectIndication()
        ci.dissect(data)

        mac_address = ""
        if packets.IpAddressInfo in ci:
            mac_address = ci[packets.IpAddressInfo].mac_address
        else:
            print("Could not extract MAC address from ConnectionIndication packet from %s:%s: %s" % (host, port, data))
            return

        print("Received ConnectionIndication message from %s / %s / %d" % (mac_address, host, port))

        self.host_to_mac[host] = mac_address

        if self.monitors is not None:
            self.monitors[mac_address] = api.Monitor(mac_address=mac_address, host=host, port=port, last_seen=datetime.datetime.now())

        if host not in self.associations:
            print("No association found for %s / %s, associating!" % (mac_address, host))
            self.transport.write(ASSOCIATION_REQUEST_MESSAGE, (host, packets.PORT_PROTOCOL))


    def handleAssociationMessage(self, data, (host, port)):
        print("Received Association message from %s" % host)

        associationMessage = packets.SessionHeader()
        associationMessage.dissect(data)
        associationMessage.show()

        print("Assuming it's a valid association confirmation from %s!" % host)
        self.associations.add(host)

        # TODO Properly validate response, rejection, etc.


    def handleProtocolMessage(self, data, (host, port)):
        print("Received Protocol message, handling")
        message = packets.SPpdu()
        message.dissect(data)

        if packets.ROIVapdu in message:
            roivapdu = message[packets.ROIVapdu]

            if roivapdu.command_type == packets.CMD_CONFIRMED_EVENT_REPORT:
                print("Received MDSCreateEventReport, sending MDSCreateEventResult")

                # Ok! Now to reply!

                mdsceResult = packets.SPpdu()
                mdsceResult = mdsceResult / packets.ROapdus(ro_type=packets.RORS_APDU)
                mdsceResult = mdsceResult / packets.RORSapdu(
                    command_type=packets.CMD_CONFIRMED_EVENT_REPORT,
                    invoke_id=message[packets.ROIVapdu].invoke_id,
                )
                mdsceResult = mdsceResult / packets.EventReportResult(
                    managed_object=message[packets.EventReportArgument].managed_object,
                    event_type=packets.NOM_NOTI_MDS_CREAT,
                )

                self.transport.write(str(mdsceResult), (host, port))

                self.connections.add(host)
            else:
                print("Unknown command_type in roivapdu!")
                roivapdu.show()
        elif packets.ROLRSapdu in message:
            # TODO Implement support for rolling up Remote Operation Linked Results
            print("ROLRSapdu!")
            # message.show()
            self.handleResult(host, message)
        elif packets.ROERapdu in message:
            # Error
            message[packets.ROERapdu].show()
        elif packets.RORSapdu in message:
            print("Results!")
            # message.show()
            self.handleResult(host, message)
        else:
            print("Unknown message!")
            message.show()


    def pollConnectedHostsForData(self):
        for host in self.connections:
            self.pollForData((host, packets.PORT_PROTOCOL))


    def pollForData(self, (host, port)):
        pollAction = packets.SPpdu()  # PIPG-55
        pollAction /= packets.ROapdus(ro_type=packets.ROIV_APDU)
        pollAction /= packets.ROIVapdu(command_type=packets.CMD_CONFIRMED_ACTION)
        pollAction /= packets.ActionArgument(
            managed_object=packets.ManagedObjectId(m_obj_class=packets.NOM_MOC_VMS_MDS),
            action_type=packets.NOM_ACT_POLL_MDIB_DATA,
        )
        pollAction /= packets.PollMdibDataReq(
            polled_obj_type=packets.TYPE(
                partition=packets.NOM_PART_OBJ,
                code=packets.NOM_MOC_VMO_METRIC_NU,  # Numerics, i.e. numbers about attached patient
            ),
            polled_attr_grp=packets.NOM_ATTR_GRP_METRIC_VAL_OBS,  # Observed values of the "object" (patient)
        )

        # pollAction.show2()

        self.transport.write(str(pollAction), (host, port))


    def displayResult(self, message):
        """
        This is quick and nasty and ignores all kinds of context, just focussing on ObservationPolls with data
        """

        poll_info_list = message[packets.PollInfoList]

        for single_context_poll in poll_info_list.value:
            for observation_poll in single_context_poll.value:
                for attribute_list in observation_poll.attributes:
                    for attribute in attribute_list.value:
                        if attribute.attribute_id == packets.NOM_ATTR_NU_VAL_OBS:
                            obsValue = attribute[packets.NuObsValue]
                            if obsValue.measurementIsValid():
                                obsValue.show()

    def handleResult(self, host, message):
        """
        We have results! Send appropriate webhooks
        """

        observations = []
        for single_context_poll in message[packets.PollInfoList].value:
            for observation_poll in single_context_poll.value:
                for attribute_list in observation_poll.attributes:
                    for attribute in attribute_list.value:
                        if attribute.attribute_id == packets.NOM_ATTR_NU_VAL_OBS:
                            obsValue = attribute[packets.NuObsValue]
                            if obsValue.measurementIsValid():
                                observation = api.Observation(
                                    physio_id=packets.ENUM_IDENTIFIERS[obsValue.physio_id],
                                    # TODO Encode "state": obsValue.state,
                                    unit_code=packets.ENUM_IDENTIFIERS[obsValue.unit_code],
                                    value=obsValue.value,
                                )
                                observations.append(observation)

        mac = self.host_to_mac[host]

        payload = api.Payload(
            monitor_id=mac,
            datetime=datetime.datetime.now(),
            observations=observations
        )

        for subscriber in self.subscriptions.get(mac, []):
            treq.post(subscriber, data=json.dumps(attr.asdict(payload), default=json_serialize))


    def startProtocol(self):
        self.loop = LoopingCall(self.pollConnectedHostsForData)
        self.loop.start(2)


    def stopProtocol(self):
        if self.loop is not None:
            self.loop.stop()


if __name__ == '__main__':
    monitors = {}
    subscriptions = {}
    w = web.EinsteinWebServer(monitors=monitors, subscriptions=subscriptions).app.resource()
    reactor.listenTCP(8080, server.Site(w))
    i = IntellivueInterface(monitors=monitors, subscriptions=subscriptions)
    reactor.listenUDP(packets.PORT_CONNECTION_INDICATION, i)

    print("Starting...")
    reactor.run()
