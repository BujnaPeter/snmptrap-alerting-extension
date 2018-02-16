/*
 *   Copyright 2018. AppDynamics LLC and its affiliates.
 *   All Rights Reserved.
 *   This is unpublished proprietary source code of AppDynamics LLC and its affiliates.
 *   The copyright notice above does not evidence any actual or intended publication of such source code.
 *
 */

package org.snmp4j.util;

import java.io.*;
import java.util.*;

import org.snmp4j.*;
import org.snmp4j.event.*;
import org.snmp4j.log.*;
import org.snmp4j.mp.*;
import org.snmp4j.smi.*;

public class TreeUtils extends AbstractSnmpUtility {

  private static final LogAdapter logger =
      LogFactory.getLogger(TreeUtils.class);

  private int maxRepetitions = 10;
  private boolean ignoreLexicographicOrder;

  /**
   * Creates a <code>TreeUtils</code> instance. The created instance is thread
   * safe as long as the supplied <code>Session</code> and
   * <code>PDUFactory</code> are thread safe.
   *
   * @param snmpSession
   *    a SNMP <code>Session</code> instance.
   * @param pduFactory
   *    a <code>PDUFactory</code> instance that creates the PDU that are used
   *    by this instance to retrieve MIB tree data using GETBULK/GETNEXT
   *    operations.
   */
  public TreeUtils(Session snmpSession, PDUFactory pduFactory) {
    super(snmpSession, pduFactory);
  }

  /**
   * Gets a subtree with GETNEXT (SNMPv1) or GETBULK (SNMP2c, SNMPv3) operations
   * from the specified target synchronously.
   *
   * @param target
   *    a <code>Target</code> that specifies the target command responder
   *    including its network transport address.
   * @param rootOID
   *    the OID that specifies the root of the sub-tree to retrieve
   *    (not included).
   * @return
   *    a possibly empty List of <code>TreeEvent</code> instances where each
   *    instance carries zero or more values (or an error condition)
   *    in depth-first-order.
   */
  public List getSubtree(Target target, OID rootOID) {
    List l = new LinkedList();
    TreeListener listener = new InternalTreeListener(l);
    synchronized (listener) {
      walk(target, rootOID, rootOID, null, listener);
      try {
        listener.wait();
      }
      catch (InterruptedException ex) {
        logger.warn("Tree retrieval interrupted: " + ex.getMessage());
      }
    }
    return l;
  }

  /**
   * Gets a subtree with GETNEXT (SNMPv1) or GETBULK (SNMP2c, SNMPv3) operations
   * from the specified target asynchronously.
   *
   * @param target
   *    a <code>Target</code> that specifies the target command responder
   *    including its network transport address.
   * @param rootOID
   *    the OID that specifies the root of the sub-tree to retrieve
   *    (not included).
   * @param userObject
   *    an optional user object that will be transparently handed over to the
   *    supplied <code>TreeListener</code>.
   * @param listener
   *    the <code>TreeListener</code> that processes the {@link org.snmp4j.util.TreeEvent}s
   *    generated by this method. Each event object may carry zero or more
   *    object instances from the sub-tree in depth-first-order.
   */
  public void getSubtree(Target target, OID rootOID,
                         Object userObject, TreeListener listener) {
    walk(target, rootOID, rootOID, userObject, listener);
  }

  private void walk(Target target, OID rootOID,
                    OID startOID, Object userObject,
                    TreeListener listener) {
    PDU request = pduFactory.createPDU(target);
    request.add(new VariableBinding(startOID));
    if (target.getVersion() == SnmpConstants.version1) {
      request.setType(PDU.GETNEXT);
    }
    else if (request.getType() != PDU.GETNEXT) {
      request.setType(PDU.GETBULK);
      request.setMaxRepetitions(maxRepetitions);
    }
    TreeRequest treeRequest =
        new TreeRequest(listener, rootOID, target, userObject, request);
    treeRequest.send();
  }

  /**
   * Sets the maximum number of the variable bindings per <code>TreeEvent</code>
   * returned by this instance.
   * @param maxRepetitions
   *    the maximum repetitions used for GETBULK requests. For SNMPv1 this
   *    values has no effect (it is then implicitly one).
   */
  public void setMaxRepetitions(int maxRepetitions) {
    this.maxRepetitions = maxRepetitions;
  }

  /**
   * Set the ignore lexicographic order errors flage value.
   * @param ignoreLexicographicOrder
   *    <code>true</code> to ignore lexicographic order errors,
   *    <code>false</code> otherwise (default).
   * @since 1.10.1
   */
  public void setIgnoreLexicographicOrder(boolean ignoreLexicographicOrder) {
    this.ignoreLexicographicOrder = ignoreLexicographicOrder;
  }

  /**
   * Gets the maximum number of the variable bindings per <code>TreeEvent</code>
   * returned by this instance.
   * @return
   *    the maximum repetitions used for GETBULK requests. For SNMPv1 this
   *    values has no effect (it is then implicitly one).
   */
  public int getMaxRepetitions() {
    return maxRepetitions;
  }

  /**
   * Return the ignore lexicographic order errors flage value.
   * @return
   *    <code>true</code> if lexicographic order errors are ignored,
   *    <code>false</code> otherwise (default).
   * @since 1.10.1
   */
  public boolean isIgnoreLexicographicOrder() {
    return ignoreLexicographicOrder;
  }

  class TreeRequest implements ResponseListener {

    private TreeListener listener;
    private Object userObject;
    private PDU request;
    private OID rootOID;
    private Target target;

    public TreeRequest(TreeListener listener, OID rootOID, Target target,
                       Object userObject, PDU request) {
      this.listener = listener;
      this.userObject = userObject;
      this.request = request;
      this.rootOID = rootOID;
      this.target = target;
    }

    public void send() {
      try {
        session.send(request, target, null, this);
      }
      catch (IOException iox) {
        listener.finished(new TreeEvent(this, userObject, iox));
      }
    }

    public void onResponse(ResponseEvent event) {
      session.cancel(event.getRequest(), this);
      PDU respPDU = event.getResponse();
      if (respPDU == null) {
        listener.finished(new TreeEvent(this, userObject,
                                        RetrievalEvent.STATUS_TIMEOUT));
      }
      else if (respPDU.getErrorStatus() != 0) {
        listener.finished(new TreeEvent(this, userObject,
                                        respPDU.getErrorStatus()));
      }
      else if (respPDU.getType() == PDU.REPORT) {
        listener.finished(new TreeEvent(this, userObject, respPDU));
      }
      else {
        List l = new ArrayList(respPDU.size());
        OID lastOID = request.get(0).getOid();
        boolean finished = false;
        for (int i = 0; (!finished) && (i < respPDU.size()); i++) {
          VariableBinding vb = respPDU.get(i);
          if ((vb.getOid() == null) ||
              (vb.getOid().size() < rootOID.size()) ||
              (rootOID.leftMostCompare(rootOID.size(), vb.getOid()) != 0)) {
            finished = true;
          }
          else if (Null.isExceptionSyntax(vb.getVariable().getSyntax())) {
            finished = true;
          }
          else if (!ignoreLexicographicOrder &&
                   (vb.getOid().compareTo(lastOID) <= 0)) {
            listener.finished(new TreeEvent(this, userObject,
                                            RetrievalEvent.STATUS_WRONG_ORDER));
            finished = true;
            break;
          }
          else {
            lastOID = vb.getOid();
            l.add(vb);
          }
        }
        if (respPDU.size() == 0) {
          finished = true;
        }
        VariableBinding[] vbs =
            (VariableBinding[]) l.toArray(new VariableBinding[l.size()]);
        if (finished) {
          listener.finished(new TreeEvent(this, userObject, vbs));
        }
        else {
          if (listener.next(new TreeEvent(this, userObject, vbs))) {
            VariableBinding next =
                (VariableBinding) respPDU.get(respPDU.size() - 1).clone();
            next.setVariable(new Null());
            request.set(0, next);
            request.setRequestID(new Integer32(0));
            send();
            return;
          }
          else {
            finished = true;
          }
        }
      }
    }
  }

  class InternalTreeListener implements TreeListener {

    private List collectedEvents;
    private volatile boolean finished = false;

    public InternalTreeListener(List eventList) {
      collectedEvents = eventList;
    }

    public synchronized boolean next(TreeEvent event) {
      collectedEvents.add(event);
      return true;
    }

    public synchronized void finished(TreeEvent event) {
      collectedEvents.add(event);
      finished = true;
      notify();
    }

    public List getCollectedEvents() {
      return collectedEvents;
    }

    public boolean isFinished() {
      return finished;
    }
  }
}
