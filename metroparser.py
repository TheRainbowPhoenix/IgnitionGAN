import struct
import io

class OpCodes:
    OK = 1
    PING = 2
    MSG_SEND = 3
    ERROR = 4
    WAIT = 5
    # RESERVED/UNUSED? = 6
    SHUTDOWN = 7
    ACCESS_DENIED = 8

    _names = {v: k for k, v in vars().items() if not k.startswith('_')}

    @classmethod
    def get_name(cls, code):
        return cls._names.get(code, "UNKNOWN")

class ProtocolHeader:
    MAGIC_BYTES = 18753
    PROTOCOL_VERSION = 1

    def __init__(self):
        self.message_id = 0
        self.opcode = 0
        self.subcode = 0
        self.flags = 0
        self.sender_id = ""
        self.sender_url = ""
        self.target_address = ""

    @classmethod
    def decode(cls, raw_bytes, stream=None):
        """Decodes a byte string into a ProtocolHeader object."""
        header = cls()
        if not stream:
            stream = io.BytesIO(raw_bytes)

        # Read the fixed-size part of the header
        magic, version, msg_id, opcode, subcode, flags = struct.unpack('>IIHIIB', stream.read(19))

        if magic != cls.MAGIC_BYTES:
            raise ValueError("Invalid magic bytes in protocol header")
        if version != cls.PROTOCOL_VERSION:
            raise ValueError("Unsupported protocol version")

        header.message_id = msg_id
        header.opcode = opcode
        header.subcode = subcode
        header.flags = flags

        # Read the length-prefixed strings
        header.sender_id = cls._decode_string(stream)
        header.target_address = cls._decode_string(stream)
        header.sender_url = cls._decode_string(stream)

        return header

    def encode(self):
        """Encodes the ProtocolHeader object into a byte string."""
        # Pack the fixed-size part
        packed_header = struct.pack('>IIHIIB', self.MAGIC_BYTES, self.PROTOCOL_VERSION,
                                    self.message_id, self.opcode, self.subcode, self.flags)

        # Encode and append the length-prefixed strings
        encoded_sender_id = self._encode_string(self.sender_id)
        encoded_target_address = self._encode_string(self.target_address)
        encoded_sender_url = self._encode_string(self.sender_url)

        return packed_header + encoded_sender_id + encoded_target_address + encoded_sender_url

    @staticmethod
    def _decode_string(stream):
        """Reads a length-prefixed, UTF-16BE encoded string from the stream."""
        length = struct.unpack('>H', stream.read(2))[0]
        if length == 0:
            return ""
        # Java's writeChars is 2 bytes per char (UTF-16BE)
        return stream.read(length * 2).decode('utf-16-be')

    @staticmethod
    def _encode_string(s):
        """Encodes a string into a length-prefixed, UTF-16BE byte string."""
        if not s:
            return struct.pack('>H', 0)
        encoded_str = s.encode('utf-16-be')
        # The length in the header is the number of characters, not bytes
        length = len(s)
        return struct.pack('>H', length) + encoded_str

    def __repr__(self):
        opcode_name = OpCodes.get_name(self.opcode)
        return f"ProtocolHeader[opCode={opcode_name}, subCode={self.subcode}, flags={self.flags}, messageId={self.message_id}, senderId='{self.sender_id}', targetAddress='{self.target_address}']"
        # return ("<ProtocolHeader id:%d opcode:%s sender:'%s'>" %
        #         (self.message_id, opcode_name, self.sender_id))

if __name__ == '__main__':
    raw_frame = b'\x00\x00IA\x00\x00\x00\x01\x00\xcf\x00\x00\x00\x02\x15\xba\xbb\xae\x01\x00\x12\x00i\x00g\x00n\x00i\x00t\x00i\x00o\x00n\x00-\x00f\x00o\x00r\x00g\x00e\x00-\x00d\x00e\x00v\x00\x00\x00\x1f\x00h\x00t\x00t\x00p\x00:\x00/\x00/\x001\x007\x002\x00.\x001\x009\x00.\x002\x000\x008\x00.\x001\x00:\x008\x000\x008\x008\x00/\x00s\x00y\x00s\x00t\x00e\x00m'
    header = ProtocolHeader.decode(raw_frame)
    print(header.opcode)
