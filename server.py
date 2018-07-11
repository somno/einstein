from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
import socket
import packets
import vscapture

ASSOCIATION_REQUEST_MESSAGE = vscapture.aarq_msg

class EinsteinServer(DatagramProtocol):
    """
    Handles communication with a Philips IntelliVue
    """

    def datagramReceived(self, data, (host, port)):
        """
        Note this assumes `data` contains a complete packet - I have no
        evidence nor reason to assume that is an invalid assumption, but it
        is not clear that it isn't just coincidence either.
        """

        print("Datagram received!")

        if port == packets.PORT_CONNECTION_INDICATION:
            self.handleConnectionIndication(data, (host, port))
        else:
            if data[0:2] == '\xe1\x00':  # PIPG-42
                self.handleProtocolMessage(data, (host, port))
            else:
                self.handleAssociationMessage(data, (host, port))


    def handleConnectionIndication(self, data, (host, port)):
        print("Received ConnectionIndication message, associating")
        ci = packets.ConnectIndication()
        ci.dissect(data)

        # TODO Store for later usage, don't just blindly
        self.transport.write(ASSOCIATION_REQUEST_MESSAGE, (host, packets.PORT_PROTOCOL))


    def handleAssociationMessage(self, data, (host, port)):
        print("Received Association message: %s" % ''.join(x.encode('hex') for x in data))
        # TODO Properly validate response, rejection, etc.


    def handleProtocolMessage(self, data, (host, port)):
        print("Received Protocol message, handling")
        sppdu = packets.SPpdu()
        sppdu.dissect(data)
        remainder = sppdu.load

        roapdus = packets.ROapdus()
        roapdus.dissect(remainder)
        remainder = roapdus.load

        if roapdus.ro_type == packets.ROIV_APDU:
            roivapdu = packets.ROIVapdu()
            roivapdu.dissect(remainder)
            remainder = roivapdu.load

            if roivapdu.command_type == packets.CMD_CONFIRMED_EVENT_REPORT:
                mdscer = packets.MDSCreateEventReport()
                mdscer.dissect(data)
                mdscer.show()
            else:
                print("Unknown command_type in roivapdu!")
                roivapdu.show()
        else:
            print("Unknown ro_type in roapdus!")
            roapdus.show()


reactor.listenUDP(packets.PORT_CONNECTION_INDICATION, EinsteinServer())
print("Starting...")
reactor.run()
