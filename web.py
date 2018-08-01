from klein import Klein
import json


class EinsteinWebServer(object):

    app = Klein()

    def __init__(self, monitors=None, subscriptions=None):
        self.monitors = monitors
        if self.monitors is None:
            self.monitors = {}

        self.subscriptions = subscriptions
        if self.subscriptions is None:
            self.subscriptions = {}


    @app.route('/monitors')
    def monitors(self, request):
        request.setHeader('Content-Type', 'application/json')
        return json.dumps(self.monitors)


    @app.route('/subscriptions')
    def subscriptions(self, request):
        request.setHeader('Content-Type', 'application/json')
        return json.dumps(self.subscriptions)


if __name__ == "__main__":
    from twisted.internet import reactor
    from twisted.web import server

    reactor.listenTCP(8080, server.Site(EinsteinWebServer().app.resource()))
    reactor.run()
