from javaobj.v2 import loads, load
import javaobj.v2 as javaobj2
from javaobj.v2.beans import JavaInstance
from javaobj import JavaObjectUnmarshaller
from javaobj.v2.api import ObjectTransformer
import io
from dataclasses import dataclass

@dataclass
class J_ServerMessageHeader:
    codecName: str
    intentName: str
    intentVersion: int
    headersValues: any

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

class HeaderTransformer(ObjectTransformer):
    def create_instance(self, classdesc):
        # classdesc.name may include versioned intent in other contexts; check the raw class name
        if classdesc.name.endswith("ServerMessage$ServerMessageHeader") or classdesc.name.endswith("ServerMessageHeader"):
            return ServerMessageHeaderInstance()
        return None

class ServerMessageHeader:
    def __init__(self, intent_version, codec_name, headers_values, intent_name):
        self.intent_version = intent_version
        self.codec_name = codec_name
        self.headers_values = headers_values
        self.intent_name = intent_name

    def __repr__(self):
        return f"<ServerMessageHeader intent={self.intent_name}, version={self.intent_version}, codec={self.codec_name}, headers={self.headers_values}>"

# with open("post_msg.bin", "rb") as f:
with open("POST_data1754159679.527987.bin", "rb") as f:
    # f.seek(0x97)
    f.seek(0x8C)
    obj_1 = f.read(374)
    # obj_1 = f.read(376)
    obj_2 = f.read()

    p_header: ServerMessageHeaderInstance = load(io.BytesIO(obj_1), HeaderTransformer())
    p_routes: JavaInstance = loads(obj_1)

    # assert p_header.classdesc.name == 'com.inductiveautomation.metro.impl.transport.ServerMessage$ServerMessageHeader'

    # _marshall_header = JavaObjectUnmarshaller(io.BytesIO(obj_1))
    # o_header: J_ServerMessageHeader = _marshall_header.readObject()

    # print(o_header.headersValues)

    print(p_header.dump())
    print(p_header.intentVersion)
    print(p_header.headersValues)

    


