from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
import socket

class SomnoDeviceDiscoveryDumper(DatagramProtocol):

    def datagramReceived(self, data, (host, port)):
        print "received %r from %s:%d" % (data, host, port)


reactor.listenUDP(24005, SomnoDeviceDiscoveryDumper())
reactor.run()
