package com.adobe.ids.dim.security;

import org.apache.kafka.common.protocol.types.Field;

public class IMSException extends Exception {

    public IMSException(String message) {
        super(message);
    }

    public IMSException(int errCode, String message) {
        super("ErrorCode : " + String.valueOf(errCode) +", Error message: " + message);
    }

}
