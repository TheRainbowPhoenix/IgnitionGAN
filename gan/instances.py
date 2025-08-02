# instances.py
import javaobj.v2 as javaobj
from javaobj.v2.beans import JavaInstance

class ServerMessageHeaderInstance(JavaInstance):
    def __init__(self):
        super(ServerMessageHeaderInstance, self).__init__()
        self.codecName = None
        self.intentName = None
        self.intentVersion = None
        self.headersValues = {}

    def load_from_instance(self, indent=0):
        # field_data is a dict mapping JavaClassDesc -> { fieldDesc: value, ... }
        # There is only one classdesc here; collapse to flat
        for classdesc, fields in self.field_data.items():
            # fields is a dict of field descriptor -> value
            for field_desc, value in fields.items():
                name = field_desc.name  # e.g. "codecName", "intentName", etc.
                if name == "codecName":
                    self.codecName = value
                elif name == "intentName":
                    self.intentName = value
                elif name == "intentVersion":
                    self.intentVersion = value
                elif name == "headersValues":
                    # headersValues is likely a java.util.HashMap; default transformer gives dict
                    self.headersValues = value  # Should already be a dict if default map transformer applied

        return True  # signal successful post-processing

    def dump(self):
        return {
            "codecName": self.codecName,
            "intentName": self.intentName,
            "intentVersion": self.intentVersion,
            "headersValues": self.headersValues,
        }

class ServerIdInstance(JavaInstance):
    def __init__(self):
        super(ServerIdInstance, self).__init__()
        self.address = None
        self.role = None  # enum constant, probably a string like "Master"

    def load_from_instance(self, indent=0):
        # Fields: address (String), role (enum)
        for classdesc, fields in self.field_data.items():
            for field_desc, value in fields.items():
                name = field_desc.name
                if name == "address":
                    self.address = value  # native Python str from javaobj
                elif name == "role":
                    # Enum constant is serialized as its name; javaobj.v2 typically gives an object representing it
                    # It might come through as a javaobj.v2.beans.JavaEnum or similar; safe to str() it.
                    self.role = str(value.value)
        return True

    def dump(self):
        return {
            "address": self.address,
            "role": self.role,
        }


class ServerRouteDetailsInstance(JavaInstance):
    def __init__(self):
        super(ServerRouteDetailsInstance, self).__init__()
        self.serverAddress = None  # will be a ServerIdInstance
        self.routeDistance = None

    def load_from_instance(self, indent=0):
        for classdesc, fields in self.field_data.items():
            for field_desc, value in fields.items():
                name = field_desc.name
                if name == "serverAddress":
                    self.serverAddress = value  # should be a ServerIdInstance
                elif name == "routeDistance":
                    self.routeDistance = value
        return True

    def dump(self):
        return {
            "serverAddress": self.serverAddress.dump() if self.serverAddress else None,
            "routeDistance": self.routeDistance,
        }
