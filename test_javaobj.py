import javaobj
from javaobj.v2 import loads
from javaobj.v2.beans import JavaInstance

class ServerMessageHeader:
    def __init__(self, intent_version, codec_name, headers_values, intent_name):
        self.intent_version = intent_version
        self.codec_name = codec_name
        self.headers_values = headers_values
        self.intent_name = intent_name

    def __repr__(self):
        return f"<ServerMessageHeader intent={self.intent_name}, version={self.intent_version}, codec={self.codec_name}, headers={self.headers_values}>"

with open("post_msg.bin", "rb") as f:
    f.seek(0x97)
    obj_1 = f.read(376)
    obj_2 = f.read()

    pobj_1: JavaInstance = loads(obj_1)
    pobj_2: JavaInstance = loads(obj_1)


    for pobj in [pobj_1, pobj_2]:

        classdesc = pobj.classdesc

        items = list(pobj.field_data.items())
        if len(items) == 1:
            classdesc, field_values = items[0]

            java_field_names = classdesc.fields_names
            python_field_map = {}

            for field_obj, value in field_values.items():
                # field_obj.name gives the field name
                python_field_map[field_obj.name] = value
            
            print(python_field_map)

            header = ServerMessageHeader(
                intent_version=python_field_map['intentVersion'],
                codec_name=python_field_map['codecName'],
                headers_values=python_field_map['headersValues'],
                intent_name=python_field_map['intentName']
            )

            print(header)



