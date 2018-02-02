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



import java.util.List;

/**
 * Interface for AppD Controller Rest APIs
 */
public interface IService {

    List<BusinessTransaction> getBTs(HttpClientBuilder httpClientBuilder, String endpoint) throws ServiceException;

    List<Node> getNodes(HttpClientBuilder httpClientBuilder, String endpoint) throws ServiceException;

}
