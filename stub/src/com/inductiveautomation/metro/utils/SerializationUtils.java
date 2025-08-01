package com.inductiveautomation.metro.utils;

import java.io.*;

public class SerializationUtils {
    public static byte[] serialize(Serializable o) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(o);
        oos.flush();
        oos.close();
        return bos.toByteArray();
    }
}
