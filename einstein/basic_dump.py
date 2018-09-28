from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
import socket
import intellivue

class SomnoDeviceDiscoveryDumper(DatagramProtocol):

    def datagramReceived(self, data, (host, port)):
        ci = intellivue.ConnectIndication()
        ci.dissect(data)
        ci.show()


if __name__ == "__main__":
    reactor.listenUDP(intellivue.PORT_CONNECTION_INDICATION, SomnoDeviceDiscoveryDumper())
    reactor.run()
