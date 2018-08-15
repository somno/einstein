"""
Sample/testing webservice for working with Einstein webhooks
"""

from klein import Klein
import json
import structlog
import api

logger = structlog.get_logger()


class HookServer(object):

    app = Klein()


    def __init__(self):
        self.latest_observations = {}


    @app.route("/")
    def list(self, request):
        return str(self.latest_observations.values())


    @app.route("/hook", methods=["POST"])
    def hook(self, request):
        logger.info("Got hook!", request=request)

        body = json.load(request.content)
        for observation in body["observations"]:
            o = api.Observation(
                physio_id=observation["physio_id"],
                unit_code=observation["unit_code"],
                value=observation["value"],
            )
            self.latest_observations[o.physio_id] = o


if __name__ == "__main__":
    from twisted.internet import reactor
    from twisted.web import server

    reactor.listenTCP(8081, server.Site(HookServer().app.resource()))
    reactor.run()
