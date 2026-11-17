package com.tracefinder;

import java.time.format.DateTimeFormatter;
import java.time.format.ResolverStyle;


public final class TimestampFormats {

    public static final DateTimeFormatter LOG_TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss").withResolverStyle(ResolverStyle.STRICT);

    private TimestampFormats() {
        // no instances; this is just a holder for the constant
    }
}