package com.inductiveautomation.metro.impl.transport;

import com.inductiveautomation.metro.api.CallableEntityUtils;
import com.inductiveautomation.metro.utils.SerializationUtils;

import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class ServerMessage {
    public static class ServerMessageHeader implements Serializable {
        static final long serialVersionUID = 2202843438899545127L;
        private static final Set WHITELIST = Set.of(ServerMessageHeader.class, String.class, Map.class, HashMap.class, Integer.class, Long.class);
        private String intentName;
        private String codecName;
        private Map headersValues;
        private int intentVersion;

        public ServerMessageHeader() {
            this.intentVersion = 0;
            this.headersValues = new HashMap();
        }

        public ServerMessageHeader(String intent, String codec) {
            this();
            this.setIntentName(intent);
            this.codecName = codec;
            this.headersValues.put("_ver_", "2");
        }

        public Map getHeadersValues() {
            return this.headersValues;
        }

        public String getCodecName() {
            return this.codecName;
        }

        public void setCodecName(String codecName) {
            this.codecName = codecName;
        }

        public String getIntentName() {
            return this.intentName;
        }

        public void setIntentName(String intentName) {
            this.intentName = CallableEntityUtils.getBaseName(intentName);
            this.intentVersion = CallableEntityUtils.getVersion(intentName);
        }

        public int getIntentVersion() {
            return this.intentVersion;
        }

        public byte[] toSerializedHeaderBlob() throws IOException {
            // replicates getAsInputStream behavior: version int, length int, then serialized object
            byte[] rawbytes = SerializationUtils.serialize(this);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bos);
            out.writeInt(1);
            out.writeInt(rawbytes.length);
            out.write(rawbytes);
            out.flush();
            return bos.toByteArray();
        }

        @Override
        public String toString() {
            return String.format("[intent=%s, iversion=%d, codec=%s, headers=%s]", this.intentName, this.intentVersion, this.codecName, this.headersValues);
        }
    }
}