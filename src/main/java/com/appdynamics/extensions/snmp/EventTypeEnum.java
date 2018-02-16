/*
 *   Copyright 2018. AppDynamics LLC and its affiliates.
 *   All Rights Reserved.
 *   This is unpublished proprietary source code of AppDynamics LLC and its affiliates.
 *   The copyright notice above does not evidence any actual or intended publication of such source code.
 *
 */

package com.appdynamics.extensions.snmp;


public enum EventTypeEnum {

    POLICY_OPEN_WARNING,
    POLICY_OPEN_CRITICAL,
    POLICY_CLOSE_WARNING,
    POLICY_CLOSE_CRITICAL,
    POLICY_UPGRADED,
    POLICY_DOWNGRADED,
    POLICY_CANCELED_WARNING,
    POLICY_CANCELED_CRITICAL,
    POLICY_CONTINUES_CRITICAL,
    POLICY_CONTINUES_WARNING,
    POLICY_CANCELED,
    POLICY_CLOSE
}
