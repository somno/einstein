from klein import Klein


app = Klein()


@app.route('/')
def hello(request):
    return "Hello, world!"


if __name__ == "__main__":
    from twisted.internet import reactor
    from twisted.web import server

    reactor.listenTCP(8080, server.Site(app.resource()))
    reactor.run()
