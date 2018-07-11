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
        ci = packets.ConnectIndication()
        ci.dissect(data)

        # TODO Store for later usage, don't just blindly
        self.transport.write(ASSOCIATION_REQUEST_MESSAGE, (host, packets.PORT_PROTOCOL))


    def handleAssociationMessage(self, data, (host, port)):
        print("Association message: %s" % ''.join(x.encode('hex') for x in data))
        # TODO Properly validate response, rejection, etc.


    def handleProtocolMessage(self, data, (host, port)):
        # TODO Don't assume message type
        mdscer = packets.MDSCreateEventReport()
        mdscer.dissect(data)
        mdscer.show()


reactor.listenUDP(packets.PORT_CONNECTION_INDICATION, EinsteinServer())
print("Starting...")
reactor.run()
