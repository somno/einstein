import datetime


def json_serialize(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()


