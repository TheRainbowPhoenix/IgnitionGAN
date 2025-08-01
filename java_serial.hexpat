
#pragma description Java Serialized Object explorer
#pragma endian big
#pragma pattern_limit 100000000

// Helper types
using u1 = u8;
using u2 = u16;
using u4 = u32;

struct JavaStreamHeader {
    u4 version;                // 1
    u4 object_length;         // length of following serialized object
} [[name("Outer header (version + length)")]];

struct SerializationStream {
    u2 magic;                 // 0xACED
    u2 version;               // 0x0005

    // Next is usually TC_OBJECT (0x73) then TC_CLASSDESC (0x72) ...
    u1 tc_object;
    u1 tc_classdesc;
    u2 class_name_length;
    char class_name[class_name_length] [[string]];
    // The rest is not fully parsed here; you can extend as needed.
} [[name("Java serialization stream")]];


struct JavaSerialized {
    JavaStreamHeader jsh;
    SerializationStream ss;
};

JavaSerialized jsr @0x0;