#pragma author "PC, ChatGPT"
#pragma description Java serialized ServerMessageHeader (dynamic field descriptors)
#pragma endian big
#pragma pattern_limit 100000000
#pragma once
#include <std/io.pat>
#include <std/string.pat>


using u1 = u8;
using u2 = u16;
using u4 = u32;
using _u8 = u64;
using f4 = float;

#define COL_CLASSDESC "88CCFF"
#define COL_FIELD "AAFF88"
#define COL_ARRAY "DFAEFF"
#define COL_TAG "FFAA55"
#define COL_LEN "FFF88A"
#define COL_STR "78F4FA"

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

struct MetroMessage {
     be u32 unk1;
     be u32 unk2;
};

// Outer header (version + length)
struct JavaStreamHeader {
    u4 version [[color(COL_LEN)]];
    u4 object_length [[color(COL_LEN)]];
} [[name("Outer header (version + length)")]];

// Java serialization magic
struct SerializationStreamHeader {
    u2 magic    [[color(COL_TAG)]];    // AC ED
    u2 version  [[color(COL_TAG)]];  // 00 05
} [[name("Java serialization magic/version")]];

enum TC : u1 {
    TC_NULL             = 0x70,
    TC_REFERENCE        = 0x71,
    TC_CLASSDESC        = 0x72,
    TC_OBJECT           = 0x73,
    TC_STRING           = 0x74,
    TC_ARRAY            = 0x75,
    TC_CLASS            = 0x76,
    TC_BLOCKDATA        = 0x77,
    TC_ENDBLOCKDATA     = 0x78,
    TC_RESET            = 0x79,
    TC_BLOCKDATALONG    = 0x7A,
    TC_EXCEPTION        = 0x7B,
    TC_LONGSTRING       = 0x7C,
    TC_PROXYCLASSDESC   = 0x7D,
    TC_ENUM             = 0x7E
};

enum FieldType : u1 {
    I = 0x49, // Int
    L = 0x4C, // Object
    LBracket = 0x5B // Array
};

struct JavaString {
    u1 tag                                  [[color(COL_STR)]]; // TC_STRING (0x74) or TC_REFERENCE (0x71) etc.
    if (tag == TC::TC_STRING) {
        u2 length                           [[color(COL_STR)]];
        char value[length]                  [[color(COL_STR), string]];
    } else if (tag == TC::TC_REFERENCE) {
        u4 handle                           [[color(COL_STR)]];
    } else if (tag == TC::TC_LONGSTRING) {
        _u8 length                          [[color(COL_STR)]];
        char value[length]                  [[color(COL_STR), string]];
    } else if (tag == TC::TC_NULL) {
        // pass
    }
} [[comment("java.lang.String (value or reference)")]];

struct CString {
    u2 length                               [[color(COL_STR)]];
    char bytes[length]                      [[color(COL_STR), string]];
} [[comment("C String")]];


struct FieldInfo {
    u1 type_code        [[color(COL_TAG)]];               // e.g., 'I','L','[', etc.
    CString field_name;
    // if object or array, there is a className1 UTF string
    match (type_code) {
        (FieldType::L): JavaString string;
        (FieldType::LBracket): JavaString string;
    }
};

struct ClassDescBody {
    // Only when preceded by TC_CLASSDESC
    CString class_name;
    _u8 serialVersionUID    [[color(COL_CLASSDESC)]];
    u1 classDescFlags       [[color(COL_TAG)]];
    u2 fieldCount           [[color(COL_LEN)]];
    FieldInfo fields[fieldCount]    [[color(COL_FIELD)]];
    // classAnnotations: sequence ending with TC_ENDBLOCKDATA
    u1 annotation_start     [[color(COL_TAG)]];
    // consume until TC_ENDBLOCKDATA
    /* while (annotation_start != TC::TC_ENDBLOCKDATA) {
        u1 next;
        annotation_start = next;
    } */
    u1 end_block_marker     [[color(COL_TAG)]]; // should be 0x78
    
    if (end_block_marker == TC::TC_CLASSDESC) {
        ClassDescBody sub;
    }
    // u1 super_classdesc;
    // ObjectStreamClassDesc super_classdesc; // recursive: could be null/ref/another classdesc
} [[name("ClassDescBody")]];

struct ObjectStreamClassDesc {
    u1 tag      [[color(COL_TAG)]]; // could be TC_NULL, TC_REFERENCE, TC_CLASSDESC, TC_PROXYCLASSDESC
    if (tag == TC::TC_NULL) {
        // nothing
    } else if (tag == TC::TC_REFERENCE) {
        u4 handle       [[color(COL_LEN)]];
    } else if (tag == TC::TC_CLASSDESC) {
        ClassDescBody body  [[color(COL_CLASSDESC)]];
    } else if (tag == TC::TC_PROXYCLASSDESC) {
        // For simplicity, skip proxy class internals here; you can expand if needed
        u2 interface_count      [[color(COL_LEN)]];
        JavaString interfaces[interface_count];
        // then similar annotation/superclass chain...
        // (omitted for brevity)
    }
} [[name("ObjectStreamClassDesc (recursive)")]];



// Class descriptor + fields
struct ClassDesc {
    u1 tc_object;             // TC_OBJECT (usually 0x73)
    u1 tc_classdesc;          // TC_CLASSDESC (0x72)
    u2 class_name_length;
    char class_name[class_name_length] [[string]];
    _u8 serialVersionUID;
    u1 classDescFlags;
    u2 fieldCount;

    // dynamic array of field descriptors; each entry adapts based on its type_code
    FieldInfo fields[fieldCount];

    // classAnnotations (usually terminated by TC_ENDBLOCKDATA)
    u1 classAnnotation; // expect 0x78 for end of annotation
    // super class descriptor (e.g., TC_NULL or nested desc)
    u1 super_classdesc;
} [[name("Object + Base ClassDesc")]];

struct HashMapItem {
    JavaString key;
    JavaString value;
};

struct HashMap {
    ClassDesc classdesc;
    f4 loadFactor;        // default 0.75
    u4 threshold;
    
    u1 tag;
    
    if (tag == TC::TC_BLOCKDATA) {
        u1 count;
        u4 modCount;
        u4 size;
        
        HashMapItem items[size];
    }
    
    u1 classAnnotation;
    
} [[name("HashMap serialized entries")]];

struct ServerMessageHeader {
    u1 element_tag;
    ObjectStreamClassDesc classdesc;

    u4 intentVersion;
    JavaString codecName;
    HashMap hash_map;
    JavaString intentName;
};

struct ServerId_Role {
    u1 element_tag;

    if (element_tag == TC::TC_ENUM) {
        ObjectStreamClassDesc classdesc;
        JavaString value;
    }
    // ObjectStreamClassDesc classdesc; // TODO: this should be an Enum desc not class 
    
};

struct ServerId {
    u1 element_tag;

    if (element_tag == TC::TC_OBJECT) {
        ObjectStreamClassDesc classdesc;
        JavaString address;
        ServerId_Role role;
    }
};

struct ServerRouteDetails {
    ObjectStreamClassDesc classdesc;

    // TODO: should be a "each fields => determine what type to read"
    std::print("{}", classdesc.body.fieldCount);

    if (classdesc.body.fieldCount == 3) {
        u4 routeDistance;
        JavaString routePath;
        ServerId serverAddress;
    } else {
        u4 routeDistance;
        ServerId serverAddress;
    
    }

};

struct BaseSerializedObject {
    ObjectStreamClassDesc classdesc;
} [[name("Serialized Java Object")]];

struct SerializedArrayElement<T> {
    u1 element_tag;
    if (element_tag == TC::TC_NULL) {
        // nothing
    } else if (element_tag == TC::TC_REFERENCE) {
        u4 handle;
    } else if (element_tag == TC::TC_OBJECT) {
        T element_object;
    } else {
        // other tag types (e.g., primitive wrappers or strings)
        u1 raw;
    }
};

struct SerializedArray<T> {
    ObjectStreamClassDesc array_classdesc; // describes the array type, e.g. "[L...;"
    u4 length;
    // each element is parsed generically: could be object/null/reference/etc.
    SerializedArrayElement<T> elements[length];
} [[name("Serialized Java Array Instance")]];


struct ServerRouteDetailsMessage {
    SerializationStreamHeader magic;
    // ServerRouteDetails smh;
    u1 tc_object;              // TC_OBJECT, should be TC_ARRAY
    if (tc_object == TC::TC_ARRAY) {
        SerializedArray<ServerRouteDetails> array;
    }
} [[name("Serialized ServerRouteDetails[]")]];


// Top-level envelope
struct ServerMessageHeaderMessage {
    JavaStreamHeader header;
    SerializationStreamHeader magic;
    ServerMessageHeader smh;
    ServerRouteDetailsMessage srd;
    // (after this comes instance data)
} [[name("Serialized ServerMessageHeader envelope")]];


struct MetroFrame {
    ProtocolHeader header;

    // Any data that comes after the header is the message body.
    // For PING frames, this will be empty.
    if (header.opCode == 3) {
        // MetroMessage msg;
       ServerMessageHeaderMessage root;
    }
};


// ServerMessageHeaderMessage root @ 0x0;
MetroFrame mf0 @0x05;
// ServerMessageHeaderMessage root @ 0x84;