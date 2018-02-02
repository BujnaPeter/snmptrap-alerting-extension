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
@XmlRootElement(name = "nodes")
public class NodeWrapper {

    @XmlElement(name="node")
    private List<Node> nodes;

    public List<Node> getNodes() {
        return nodes;
    }

    public void setNodes(List<Node> nodes) {
        this.nodes = nodes;
    }
}
