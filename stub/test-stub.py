import sys
sys.path.append("./metro-stub.jar")

from com.inductiveautomation.metro.impl.transport.ServerMessage import ServerMessageHeader

def make_header(remoteSystemId):
    hdr = ServerMessageHeader("MyGateway|42", "_js_")
    hv = hdr.getHeadersValues()
    hv.put("_source_", remoteSystemId)
    hv.put("replyrequested", "true")
    blob = hdr.toSerializedHeaderBlob()
    print("Header object:", hdr)
    return blob


def modify_existing(path_in, path_out, remoteSystemId):
    # Assume input is raw stream with header + payload; you would need to parse it in Python or Java.
    # Here's just regenerating a header as an example:
    blob = make_header(remoteSystemId)
    with open(path_out, "wb") as f:
        f.write(blob)
    print("Wrote new header to", path_out)

from com.inductiveautomation.metro.impl import ServerRouteDetails
from com.inductiveautomation.metro.api import ServerId

from java.io import ByteArrayOutputStream, ObjectOutputStream

def serialize_java(obj):
    bos = ByteArrayOutputStream()
    oos = ObjectOutputStream(bos)
    oos.writeObject(obj)
    oos.flush()
    oos.close()
    return bos.toByteArray()

def make_serverRouteDetails():
    sid = ServerId("myserver.example", ServerId.Role.Master)
    route = ServerRouteDetails(sid, 42)
    print("RouteDetails:", route)
    blob = serialize_java(route)
    print("Serialized size:", len(blob))
    return blob

if __name__ == "__main__":
    # Example usage: create header and dump
    hdr_blob = make_header("_0:1:Ignition-COBBLESTONE")
    f = open("header_2.bin", "wb")
    f.write(hdr_blob)
    f.close()
    
    print("Serialized header length:", len(hdr_blob))

    srd_blob = make_serverRouteDetails()
    f = open("srd_1.bin", "wb")
    f.write(srd_blob)
    f.close()