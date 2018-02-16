/*
 *   Copyright 2018. AppDynamics LLC and its affiliates.
 *   All Rights Reserved.
 *   This is unpublished proprietary source code of AppDynamics LLC and its affiliates.
 *   The copyright notice above does not evidence any actual or intended publication of such source code.
 *
 */



package org.snmp4j.log;

/**
 * The <code>Log4jLogFactory</code> implements a SNMP4J LogFactory for
 * Log4J. In order to use Log4J for logging SNMP4J log messages the
 * static {@link org.snmp4j.log.LogFactory#setLogFactory} method has to be used before
 * any SNMP4J class is referenced or instantiated.
 *
 * @author Frank Fock
 * @version 1.7
 * @since 1.6
 */
public class ConsoleLogFactory extends LogFactory {

  public ConsoleLogFactory() {
  }

  protected LogAdapter createLogger(Class c) {
    return new ConsoleLogAdapter();
  }

  protected LogAdapter createLogger(String className) {
    return new ConsoleLogAdapter();
  }

}
