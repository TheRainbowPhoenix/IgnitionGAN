import sys
sys.path.append("./metro-stub.jar")

from com.inductiveautomation.metro.impl.transport.ServerMessage import ServerMessageHeader

def make_header(remoteSystemId):
    hdr = ServerMessageHeader("_conn_svr", "_js_")
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

if __name__ == "__main__":
    # Example usage: create header and dump
    hdr_blob = make_header("_0:1:Ignition-COBBLESTONE")
    f = open("header_2.bin", "wb")
    f.write(hdr_blob)
    f.close()
    
    print("Serialized header length:", len(hdr_blob))