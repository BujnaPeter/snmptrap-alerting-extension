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
 * Encryption class for AES 256.
 *
 * @author Jochen Katz
 * @version 1.11
 */
public class PrivAES256 extends PrivAES {

  private static final long serialVersionUID = -4678800188622949146L;

  /**
   * Unique ID of this privacy protocol.
   */
  public static final OID ID = new OID(" 1.3.6.1.4.1.4976.2.2.1.1.2");

  /**
   * Constructor.
   */
  public PrivAES256() {
    super(32);
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
