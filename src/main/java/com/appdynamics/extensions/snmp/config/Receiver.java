/*
 *
 *  *
 *  *  * Copyright 2018. AppDynamics LLC and its affiliates.
 *  *  * All Rights Reserved.
 *  *  * This is unpublished proprietary source code of AppDynamics LLC and its affiliates.
 *  *  * The copyright notice above does not evidence any actual or intended publication of such source code.
 *  *  *
 * /
 */

package com.appdynamics.extensions.snmp.config;


public class Receiver {

    private String host;
    private int port;

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }
}
