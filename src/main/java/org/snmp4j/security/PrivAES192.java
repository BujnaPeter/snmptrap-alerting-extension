/*
 *   Copyright 2018. AppDynamics LLC and its affiliates.
 *   All Rights Reserved.
 *   This is unpublished proprietary source code of AppDynamics LLC and its affiliates.
 *   The copyright notice above does not evidence any actual or intended publication of such source code.
 *
 */

package org.snmp4j.security;

import org.snmp4j.smi.OID;

/**
 * Encryption class for AES 192.
 *
 * @author Jochen Katz
 * @version 1.11
 */
public class PrivAES192 extends PrivAES {

  private static final long serialVersionUID = -3496699866363408441L;

  /**
   * Unique ID of this privacy protocol.
   */
  public static final OID ID = new OID(" 1.3.6.1.4.1.4976.2.2.1.1.1");

  /**
   * Constructor.
   */
  public PrivAES192() {
    super(24);
  }
  /**
   * Gets the OID uniquely identifying the privacy protocol.
   * @return
   *    an <code>OID</code> instance.
   */
  public OID getID() {
        return (OID) ID.clone();
  }

}
