import sys
sys.path.append("./metro-stub.jar")  # adjust path if needed

from com.inductiveautomation.metro.impl.transport.ServerMessage import ServerMessageHeader
from com.inductiveautomation.metro.impl import ServerRouteDetails
from com.inductiveautomation.metro.api import ServerId

from java.io import (
    ByteArrayInputStream,
    DataInputStream,
    ObjectInputStream,
    FileInputStream,
    BufferedInputStream
)

# --- helpers ------------------------------------------------

def read_server_message_header_from_blob(blob_bytes):
    """
    Matches the encode from toSerializedHeaderBlob: [int version=1][int length][serialized header object]
    Returns the deserialized ServerMessageHeader instance.
    """
    bis = ByteArrayInputStream(blob_bytes)
    dis = DataInputStream(bis)
    try:
        version = dis.readInt()
        if version != 1:
            print("Warning: unexpected header version {}".format(version))
        length = dis.readInt()
        inner = bytearray(length)
        dis.readFully(inner)
        inner_bis = ByteArrayInputStream(inner)
        ois = ObjectInputStream(inner_bis)
        try:
            hdr = ois.readObject()
        finally:
            ois.close()
        return hdr
    finally:
        dis.close()


def read_server_route_details_from_blob(blob_bytes):
    """
    Directly deserialize a serialized ServerRouteDetails (no extra wrapper).
    """
    bis = ByteArrayInputStream(blob_bytes)
    ois = ObjectInputStream(bis)
    try:
        route = ois.readObject()
        return route
    finally:
        ois.close()

# --- pretty printers ---------------------------------------

def dump_header(hdr):
    print("ServerMessageHeader:")
    print("  IntentName:", hdr.getIntentName())
    print("  IntentVersion:", hdr.getIntentVersion())
    print("  CodecName:", hdr.getCodecName())
    headers = hdr.getHeadersValues()
    print("  HeadersValues:")
    for entry in headers.entrySet().toArray():
        # entry is a java.util.Map$Entry
        key = entry.getKey()
        val = entry.getValue()
        print("    {} = {}".format(key, val))

def dump_route_details(route):
    print("ServerRouteDetails:")
    print("  ServerAddress:", route.getServerAddress())
    print("    .getServerName():", route.getServerAddress().getServerName())
    print("    .getRole():", route.getServerAddress().getRole())
    print("  RouteDistance:", route.getRouteDistance())
    print("  toString():", route.toString())

# --- main --------------------------------------------------

if __name__ == "__main__":
    # Load message
    # with open("../post_msg.bin", "rb") as f:
    #     f.seek(0x97)
    #     hdr_bytes = f.read()
    # hdr = read_server_message_header_from_blob(hdr_bytes)
    # dump_header(hdr)

    # load header blob
    # with open("header_2.bin", "rb") as f:
    #     f.seek(8)
    #     hdr_bytes = f.read()
    # hdr = read_server_message_header_from_blob(hdr_bytes)
    # dump_header(hdr)

    # load route details blob
    with open("srd_1.bin", "rb") as f:
        srd_bytes = f.read()
    route = read_server_route_details_from_blob(srd_bytes)
    dump_route_details(route)
