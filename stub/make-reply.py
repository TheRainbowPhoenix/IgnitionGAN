import sys
sys.path.append("./metro-stub.jar")  # adjust path if needed

import io
import struct
import jarray

from com.inductiveautomation.metro.impl.transport.ServerMessage import ServerMessageHeader
from com.inductiveautomation.metro.impl import ServerRouteDetails
from com.inductiveautomation.metro.api import ServerId

from java.io import ByteArrayOutputStream, ObjectOutputStream


# ---- protocol framing from your code ----
class OpCodes:
    OK = 1
    PING = 2
    MSG_SEND = 3
    ERROR = 4
    WAIT = 5
    SHUTDOWN = 7
    ACCESS_DENIED = 8

    _names = {v: k for k, v in vars().items() if not k.startswith('_')}

    @classmethod
    def get_name(cls, code):
        return cls._names.get(code, "UNKNOWN")

class ProtocolHeader:
    MAGIC_BYTES = 18753  # 0x4901?
    PROTOCOL_VERSION = 1

    def __init__(self):
        self.message_id = 1
        self.opcode = 0
        self.subcode = 0
        self.flags = 0
        self.sender_id = ""
        self.target_address = ""
        self.sender_url = ""

    @classmethod
    def decode(cls, raw_bytes, stream=None):
        header = cls()
        if not stream:
            stream = io.BytesIO(raw_bytes)
        magic, version, msg_id, opcode, subcode, flags = struct.unpack('>IIHIIB', stream.read(19))
        if magic != cls.MAGIC_BYTES:
            raise ValueError("Invalid magic {}".format(magic))
        if version != cls.PROTOCOL_VERSION:
            raise ValueError("Unsupported version {}".format(version))
        header.message_id = msg_id
        header.opcode = opcode
        header.subcode = subcode
        header.flags = flags
        header.sender_id = cls._decode_string(stream)
        header.target_address = cls._decode_string(stream)
        header.sender_url = cls._decode_string(stream)
        return header

    def encode(self):
        packed = struct.pack('>IIHIIB',
                             self.MAGIC_BYTES,
                             self.PROTOCOL_VERSION,
                             self.message_id,
                             self.opcode,
                             self.subcode,
                             self.flags)
        return packed + self._encode_string(self.sender_id) + self._encode_string(self.target_address) + self._encode_string(self.sender_url)

    @staticmethod
    def _decode_string(stream):
        length = struct.unpack('>H', stream.read(2))[0]
        if length == 0:
            return ""
        return stream.read(length * 2).decode('utf-16-be')

    @staticmethod
    def _encode_string(s):
        if not s:
            return struct.pack('>H', 0)
        encoded = s.encode('utf-16-be')
        length = len(s)
        return struct.pack('>H', length) + encoded

    def __repr__(self):
        name = OpCodes.get_name(self.opcode)
        return "<ProtocolHeader id:{} opcode:{} sender:'{}'>".format(self.message_id, name, self.sender_id)


# ---- Java serialization helpers ----

"""
# svrSet.toArray(new ServerRouteDetails[svrSet.size()]));
ServerMessage createFor("_conn_svr", Object data) throws Exception {
MessageCodecFactory.CodecEncoder codec = MessageCodecFactory.get().getCodecEncoderFor(data);
return createFor("_conn_svr", codec.getId(), codec);

# ID ? _svcres_ ? 

ServerMessage createFor("_conn_svr", String codecName, InputStreamProvider dataStreamProvider) {
new ServerMessage(new ServerMessageHeader("_conn_svr", codecName), dataStreamProvider);
"""

def serialize_java(obj):
    bos = ByteArrayOutputStream()
    oos = ObjectOutputStream(bos)
    oos.writeObject(obj)
    oos.flush()
    oos.close()
    return bos.toByteArray()

def make_header(my_server_id, ask_for_reply=False):
    hdr = ServerMessageHeader("_conn_svr", "_js_") # _svcres_ ?
    hv = hdr.getHeadersValues()
    hv.put("_source_", my_server_id) # _0:0:Ignition-Forge-DEV ?
    if ask_for_reply:
        hv.put("replyrequested", "true")
    return hdr

def make_route_array(route_entries):
    # route_entries: list of tuples [(serverName, role, distance), ...]
    routes = []
    for serverName, role_enum, distance in route_entries:
        sid = ServerId(serverName, getattr(ServerId.Role, role_enum))
        route = ServerRouteDetails(sid, distance)
        routes.append(route)
    # Java array
    arr = jarray.array(routes, ServerRouteDetails)
    return arr

def build_server_message(my_server_id, routable_list, ask_for_reply=True):
    header_obj = make_header(my_server_id, ask_for_reply)
    route_array = make_route_array(routable_list)

    header_blob = header_obj.toSerializedHeaderBlob() # version+length+serialized header

    # Payload array
    routes = []
    for serverName, role_enum, distance in routable_list:
        sid = ServerId(serverName, getattr(ServerId.Role, role_enum))
        route = ServerRouteDetails(sid, distance)
        routes.append(route)
    arr = jarray.array(routes, ServerRouteDetails)
    payload_blob = serialize_java(arr)

    # SequenceInputStream(header, payload) is just concatenation
    return header_blob + payload_blob




    # # Serialize payload array
    # payload_blob = serialize_java(route_array)

    # # Now need to craft the full ServerMessage send stream:
    # # The Java code does SequenceInputStream(header.getAsInputStream(), payload)
    # header_stream_blob = header_obj.getAsInputStream().readAllBytes() if hasattr(header_obj, "getAsInputStream") else serialize_java(header_obj)
    # # In Jython: header_obj.getAsInputStream() is a Java InputStream; readAllBytes may not exist, use fallback
    # try:
    #     header_bytes = header_obj.getAsInputStream().readAllBytes()
    # except AttributeError:
    #     # manual drain
    #     is_stream = header_obj.getAsInputStream()
    #     header_bytes = bytearray()
    #     buf = bytearray(1024)
    #     while True:
    #         read = is_stream.read(buf, 0, len(buf))
    #         if read <= 0:
    #             break
    #         header_bytes.extend(buf[:read])
    # full_message_payload = bytes(header_bytes) + bytes(payload_blob)
    # return full_message_payload  # this is what goes after the protocol header

def to_python_bytes(java_byte_array):
    # Convert a Java byte[] (or Jython array) to Python bytes
    try:
        # If it's already a Python bytes/bytearray, just return it
        if isinstance(java_byte_array, (bytes, bytearray)):
            return bytes(java_byte_array)
        # Some Jython arrays support the buffer protocol:
        return bytes(bytearray(java_byte_array))
    except Exception:
        # Fallback: iterate and mask to 0-255
        return bytes([int(b) & 0xFF for b in java_byte_array])

# ---- assemble reply frame ----
def build_reply_frame(remote_source_id, local_server_id, routable_servers):
    # remote_source_id: what they used as _source_ in their header, also target_address
    # local_server_id: your own id to put into _source_
    protocol = ProtocolHeader()
    protocol.message_id = 2  # new ID; could also reuse their ID if needed
    protocol.opcode = OpCodes.MSG_SEND
    protocol.subcode = 0
    protocol.flags = 0
    protocol.sender_id = local_server_id
    protocol.target_address = remote_source_id
    protocol.sender_url = ""  # optional, can be left blank

    # Build Java server message (_conn_svr with route details)
    # Example routable_servers = [("Ignition-COBBLESTONE", "Master", 0)]
    java_payload = build_server_message(local_server_id, routable_servers, ask_for_reply=False)

    # Combine protocol header + java payload
    proto_bytes = to_python_bytes(protocol.encode())
    java_bytes = to_python_bytes(java_payload)

    final = bytearray()
    # final.extend(proto_bytes)
    final.extend(java_bytes)
    return bytes(final), protocol

if __name__ == "__main__":
    # Example usage: reply to a peer whose _source_ was "_0:0:Ignition-Forge-DEV"
    remote_source = "_0:0:Ignition-Forge-DEV"
    local_id = "_0:0:my-python-sniffer"
    routes = [("my-python-sniffer", "Master", 0)]  # you expose this as available
    frame_bytes, hdr = build_reply_frame(remote_source, local_id, routes)

    print("Built reply:", hdr)
    with open("reply_frame.bin", "wb") as f:
        f.write(frame_bytes)
    print("Wrote reply_frame.bin (length)", len(frame_bytes))