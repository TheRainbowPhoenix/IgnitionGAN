# load_routes.py
import struct
import javaobj.v2 as javaobj

from gan.instances import ServerMessageHeaderInstance, ServerRouteDetailsInstance
from gan.transformers import ServerIdTransformer, ServerRouteDetailsTransformer, HeaderTransformer

import io

from metroparser import ProtocolHeader

with open("POST_data1754159679.527987.bin", "rb") as f:
    d = f.read(0x40)
    size_end = d.find(b'\r\n')
    if size_end > 0 and size_end < 8:  # TODO: 8 is guesstimated. Maybe more ? It's plain text hex of the length
        length = int(d[:size_end], 16)
        f.seek(size_end + 2)
        ia_obj = f.read(length)

        stream = io.BytesIO(bytes(ia_obj))

        ia_head = ProtocolHeader.decode(None, stream)
        print(ia_head)

        version, header_size = struct.unpack('>II', stream.read(8))
        obj_1 = stream.read(header_size)
        obj_2 = stream.read()
        


    else:
        # f.seek(0x97)
        f.seek(0x8C)
        # objs = f.read()
        obj_1 = f.read(374)
        obj_2 = f.read()

p_header: ServerMessageHeaderInstance = javaobj.load(io.BytesIO(obj_1), HeaderTransformer())

print(p_header.dump())
print(p_header.intentVersion)
print(p_header.headersValues)

p_routes: ServerRouteDetailsInstance = javaobj.load(io.BytesIO(obj_2), ServerRouteDetailsTransformer(), ServerIdTransformer())

print(p_routes)

# The top-level object is ServerRouteDetails[] array
if isinstance(p_routes, list):
    for i, route in enumerate(p_routes):
        try:
            print(f"[{i}] RouteDetails:", route.dump())
        except AttributeError:
            print(f"[{i}] (unexpected type)", route)
