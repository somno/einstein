from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.web import server
import datetime
import socket
import intellivue
import web
import vscapture


class DummyIntellivueMonitor(DatagramProtocol):
    """
    Acts as a fake IntelliVue Monitor for testing purposes.
    """

    def startProtocol(self):
        self.loop = LoopingCall(self.broadcastConnectionIndicationEvent)
        self.loop.start(2)


    def broadcastConnectionIndicationEvent(self):
        ci = intellivue.ConnectIndication()
        self.transport.write(str(ci), (self.transport.getHost().host, intellivue.PORT_CONNECTION_INDICATION)) 


if __name__ == '__main__':
    reactor.listenUDP(intellivue.PORT_PROTOCOL, DummyIntellivueMonitor())

    print("Starting...")
    reactor.run()
