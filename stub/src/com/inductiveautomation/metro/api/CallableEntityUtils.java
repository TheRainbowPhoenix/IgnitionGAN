package com.inductiveautomation.metro.api;

public class CallableEntityUtils {
    // example: if intent is "foo|3" you might parse version
    public static String getBaseName(String intent) {
        if (intent == null) return null;
        int idx = intent.lastIndexOf("|");
        return idx > 0 ? intent.substring(0, idx) : intent;
    }

    public static int getVersion(String intent) {
        if (intent == null) return 0;
        int idx = intent.lastIndexOf("|");
        if (idx > 0) {
            try {
                return Integer.parseInt(intent.substring(idx + 2));
            } catch (NumberFormatException e) {
                return 0;
            }
        }
        return 0;
    }

    public static String getVersionedName(String base, int version) {
        return String.format("%s|%d", base, version);
    }
}
