package com.inductiveautomation.metro.api;

public class CallableEntityUtils {
    // example: if intent is "foo.v3" you might parse version; adjust to real logic if necessary
    public static String getBaseName(String intent) {
        if (intent == null) return null;
        int idx = intent.lastIndexOf(".v");
        if (idx != -1) {
            return intent.substring(0, idx);
        }
        return intent;
    }

    public static int getVersion(String intent) {
        if (intent == null) return 0;
        int idx = intent.lastIndexOf(".v");
        if (idx != -1) {
            try {
                return Integer.parseInt(intent.substring(idx + 2));
            } catch (NumberFormatException e) {
                return 0;
            }
        }
        return 0;
    }

    public static String getVersionedName(String base, int version) {
        return base + ".v" + version;
    }
}
