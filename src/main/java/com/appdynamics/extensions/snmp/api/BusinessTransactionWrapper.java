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

package com.appdynamics.extensions.snmp.api;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.List;


@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "business-transactions")
public class BusinessTransactionWrapper {

    @XmlElement(name="business-transaction")
    private List<BusinessTransaction> businessTransactions;

    public List<BusinessTransaction> getBusinessTransactions() {
        return businessTransactions;
    }

    public void setBusinessTransactions(List<BusinessTransaction> businessTransactions) {
        this.businessTransactions = businessTransactions;
    }
}
