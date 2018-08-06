from klein import Klein
import json
from util import json_serialize
import attr
import api


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
        monitors = [attr.asdict(monitor) for monitor in self.monitors.values()]
        return json.dumps(monitors, default=json_serialize)


    @app.route('/subscriptions')
    def subscriptions(self, request):
        request.setHeader('Content-Type', 'application/json')
        return json.dumps([attr.asdict(s) for s in self.subscriptions.values()])


    @app.route('/monitor/<string:monitor_id>/subscribe', methods=['POST'])
    def subscribe(self, request, monitor_id):
        # TODO Validate monitor_id
        # TODO Validate body
        body = json.load(request.content)
        url = body["url"]
        sub = api.Subscription(monitor_id=monitor_id, url=url)
        self.subscriptions[monitor_id] = sub

        request.setHeader('Content-Type', 'application/json')
        return json.dumps(attr.asdict(sub))


if __name__ == "__main__":
    from twisted.internet import reactor
    from twisted.web import server

    reactor.listenTCP(8080, server.Site(EinsteinWebServer().app.resource()))
    reactor.run()
