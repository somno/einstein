from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
import socket
import packets

class SomnoDeviceDiscoveryDumper(DatagramProtocol):

    def datagramReceived(self, data, (host, port)):
        ci = packets.ConnectIndication()
        ci.dissect(data)
        ci.show()


reactor.listenUDP(packets.PORT_CONNECTION_INDICATION, SomnoDeviceDiscoveryDumper())
reactor.run()
