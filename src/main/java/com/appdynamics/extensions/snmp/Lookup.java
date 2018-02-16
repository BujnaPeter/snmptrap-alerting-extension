/*
 *   Copyright 2018. AppDynamics LLC and its affiliates.
 *   All Rights Reserved.
 *   This is unpublished proprietary source code of AppDynamics LLC and its affiliates.
 *   The copyright notice above does not evidence any actual or intended publication of such source code.
 *
 */




package com.appdynamics.extensions.snmp;

import java.util.HashMap;

/**
 * Creates a lookup or each attribute of SNMP and assigns an OID value
 */
public class Lookup
{
    private static String baseOID = "1.3.6.1.4.1.40684.1.1.1.1.";
    private static HashMap<String, String> map = new HashMap<String, String>();
    private static String[] names = {
            "application",
            "triggeredBy",
            "nodes",
            "txns",
            "machines",
            "tiers",
            "eventTime",
            "severity",
            "type",
            "subtype",
            "summary",
            "link",
            "tag",
            "eventType",
            "ipAddresses",
            "incidentId",
            "accountId"
    };

    public Lookup()
    {
        if(map.size() == 0)
        {
            int idx = 1;

            for (String name : names)
            {
                map.put(name, baseOID + idx++);
            }
        }
    }

    public String getOID(String name)
    {
        String val = map.get(name);
        return val;
    }
}

