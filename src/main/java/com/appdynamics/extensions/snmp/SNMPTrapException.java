/*
 *   Copyright 2018. AppDynamics LLC and its affiliates.
 *   All Rights Reserved.
 *   This is unpublished proprietary source code of AppDynamics LLC and its affiliates.
 *   The copyright notice above does not evidence any actual or intended publication of such source code.
 *
 */

package com.appdynamics.extensions.snmp;


public class SNMPTrapException extends RuntimeException{
    public SNMPTrapException(String message, Throwable cause) {
        super(message, cause);
    }

    public SNMPTrapException(String message) {
        super(message);
    }
}
