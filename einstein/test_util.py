import datetime
import json

import util


def test_json_serialize_datetime():
    d = {"dt": datetime.datetime.now()}
    s = json.dumps(d, default=util.json_serialize)  # Without the custom serialiser, this would be unable to serialise the datetime
