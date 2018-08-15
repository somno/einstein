import attr
import datetime
import intellivue
import uuid


@attr.s
class Monitor(object):
    mac_address = attr.ib(default="ff:ff:ff:ff:ff:ff")
    host = attr.ib(default="127.0.0.1")
    port = attr.ib(default=intellivue.PORT_PROTOCOL)
    last_seen = attr.ib(factory=datetime.datetime.now)


@attr.s
class Observation(object):
    physio_id = attr.ib(default="")
    state = attr.ib(default=[])
    unit_code = attr.ib(default="")
    value = attr.ib(default=0)


@attr.s
class Payload(object):
    monitor_id = attr.ib()
    datetime = attr.ib(factory=datetime.datetime.now)
    observations = attr.ib(factory=list)

@attr.s
class Subscription(object):
    monitor_id = attr.ib()
    url = attr.ib()
    subscription_id = attr.ib(factory=lambda: str(uuid.uuid4()))
