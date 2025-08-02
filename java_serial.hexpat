#pragma author ChatGPT
#pragma description Java serialized ServerMessageHeader (dynamic field descriptors)
#pragma endian big
#pragma pattern_limit 100000000

using u1 = u8;
using u2 = u16;
using u4 = u32;
using _u8 = u64;
using f4 = float;

// Outer header (version + length)
struct JavaStreamHeader {
    u4 version;
    u4 object_length;
} [[name("Outer header (version + length)")]];

// Java serialization magic
struct SerializationStreamHeader {
    u2 magic;    // AC ED
    u2 version;  // 00 05
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
    baseWireHandle      = 0x7E
};

struct JavaString {
    u1 tag;               // TC_STRING (0x74) or TC_REFERENCE (0x71) etc.
    if (tag == TC::TC_STRING) {
        u2 length;
        char value[length] [[string]];
    } else if (tag == TC::TC_REFERENCE) {
        u4 handle;
    } else if (tag == TC::TC_LONGSTRING) {
        u8 length;
        char value[length] [[string]];
    } else if (tag == TC::TC_NULL) {
        // pass
    }
} [[name("java.lang.String (value or reference)")]];

enum FieldType : u1 {
    I = 0x49,
    L = 0x4C,
    LBracket = 0x5B
};

struct FieldInfo {
    u1 type_code;               // e.g., 'I','L','[', etc.
    u2 field_name_length;
    char field_name[field_name_length] [[string]];
    // if object or array, there is a className1 UTF string
    match (type_code) {
        (FieldType::L): JavaString string;
        (FieldType::LBracket): JavaString string;
    }
};

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
    ClassDesc classdesc;

    u4 intentVersion;
    JavaString codecName;
    HashMap hash_map;
    JavaString intentName;
};

// Top-level envelope
struct JavaSerializedHeader {
    JavaStreamHeader header;
    SerializationStreamHeader magic;
    ServerMessageHeader smh;
    // (after this comes instance data)
} [[name("Serialized ServerMessageHeader envelope")]];

JavaSerializedHeader root @ 0x0;