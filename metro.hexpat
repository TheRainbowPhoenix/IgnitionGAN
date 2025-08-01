#pragma once
#include <std/string.pat>

// Define the OpCodes as an enumeration for easy identification
enum OpCode : u32 {
    OK = 1,
    PING = 2,
    MSG_SEND = 3,
    ERROR = 4,
    WAIT = 5,
    SHUTDOWN = 7,
    ACCESS_DENIED = 8
};

struct MetroString {
    be u16 length;
    if (length > 0) {
        // char16 is ImHex's type for 2-byte UTF-16 characters
        char16 value[length];
    }
};

struct ProtocolHeader {
    be u32 magicBytes;
    be u32 protocolVersion;
    be u16 messageId;
    be u32 opCode;
    be u32 subCode;
    u8  flags;

    MetroString senderId;
    MetroString targetAddress;
    MetroString senderUrl;
};

struct MetroFrame {
    ProtocolHeader header;

    // Any data that comes after the header is the message body.
    // For PING frames, this will be empty.
    u8 body[];
};

MetroFrame mf0 @0x0;