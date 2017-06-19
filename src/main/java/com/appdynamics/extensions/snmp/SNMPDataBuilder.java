package com.appdynamics.extensions.snmp;


import com.appdynamics.extensions.alerts.customevents.*;
import com.appdynamics.extensions.snmp.api.*;
import com.appdynamics.extensions.snmp.config.Configuration;
import com.appdynamics.extensions.snmp.config.ControllerConfig;
import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import org.apache.log4j.Logger;

import java.util.List;

public class SNMPDataBuilder {

    private static final Joiner JOIN_ON_COMMA = Joiner.on(",");
    private Configuration config;
    private IService service = new ServiceImpl();
    private final HttpClientBuilder clientBuilder;
    private final EndpointBuilder endpointBuilder;

    private static Logger logger = Logger.getLogger(SNMPDataBuilder.class);


    SNMPDataBuilder(Configuration config) {
        this.config = config;
        ControllerConfig controller = config.getController();
        clientBuilder = new HttpClientBuilder(controller.isUseSsl(), controller.getUserAccount(), controller.getPassword(), controller.getConnectTimeoutInSeconds() * 1000, controller.getSocketTimeoutInSeconds() * 1000);
        endpointBuilder = new EndpointBuilder();
    }


    ADSnmpData buildFromHealthRuleViolationEvent(HealthRuleViolationEvent violationEvent){
        ADSnmpData snmpData = new ADSnmpData();
        snmpData.setApplication(violationEvent.getAppName());
        snmpData.setTriggeredBy(violationEvent.getHealthRuleName());
        snmpData.setEventTime(violationEvent.getPvnAlertTime());
        snmpData.setSeverity(violationEvent.getSeverity());
        snmpData.setType(violationEvent.getAffectedEntityType());
        snmpData.setSubtype(" ");
        snmpData.setSummary(violationEvent.getSummaryMessage());
        if (config.getController() != null) {
            snmpData.setLink(CommonUtils.getAlertUrl(violationEvent));
        }
        snmpData.setTag(violationEvent.getTag());
        snmpData.setEventType(violationEvent.getEventType());
        snmpData.setIncidentId(violationEvent.getIncidentID());
        snmpData.setAccountId(CommonUtils.cleanUpAccountInfo(violationEvent.getAccountId()));
        //get BTs
        List<String> affectedBTs = getBTs(violationEvent);
        snmpData.setTxns( JOIN_ON_COMMA.join((affectedBTs)));
        //get nodes
        List<String> affectedNodes = getNodes(violationEvent);
        snmpData.setNodes( JOIN_ON_COMMA.join((affectedNodes)));
        //get tiers
        List<String> affectedTiers = getTiers(violationEvent);
        snmpData.setTiers( JOIN_ON_COMMA.join((affectedTiers)));

        //get ip addresses and populate ip addresses, machine names
        if(config.isFetchMachineInfoFromApi()){
            populateMachineInfo(violationEvent, affectedNodes, affectedTiers, snmpData);
        } else {
            snmpData.setMachines(" ");
            snmpData.setIpAddresses(" ");
        }
        return snmpData;
    }


    private void populateMachineInfo(HealthRuleViolationEvent violationEvent, List<String> affectedNodes, List<String> affectedTiers, ADSnmpData snmpData) {
        logger.debug("Affected Tiers : " + affectedTiers);
        logger.debug("Affected Nodes : " + affectedNodes);
        List<String> machines = Lists.newArrayList();
        List<String> ipAddresses = Lists.newArrayList();
        List<Node> nodesInAffectedTiers = null;
        if(!affectedTiers.isEmpty()){
            nodesInAffectedTiers  = getAllNodesFromTiers(Integer.parseInt(violationEvent.getAppID()),affectedTiers);
            collectMachineInfo(machines, ipAddresses, nodesInAffectedTiers);
        }
        if(!affectedNodes.isEmpty()){
            for(String affectedNode : affectedNodes){
                List<Node> nodes = getNodeFromNodeName(Integer.parseInt(violationEvent.getAppID()),affectedNode);
                collectMachineInfo(machines, ipAddresses, nodes);
            }
        }
        snmpData.setMachines(JOIN_ON_COMMA.join(machines));
        snmpData.setIpAddresses(JOIN_ON_COMMA.join(ipAddresses));
    }

    private void collectMachineInfo(List<String> machines, List<String> ipAddresses, List<Node> nodesInAffectedTiers) {
        for(Node aNode : nodesInAffectedTiers){
            machines.add(aNode.getMachineName());
            ipAddresses.addAll(aNode.getIpAddresses());
        }
    }

    private List<Node> getNodeFromNodeName(int appId, String affectedNode) {
        ControllerConfig controller = config.getController();
        String endpoint = endpointBuilder.getANodeEndpoint(controller,appId,affectedNode);
        List<Node> nodes = service.getNodes(clientBuilder,endpoint);
        return nodes;
    }

    private List<Node> getAllNodesFromTiers(int applicationId,List<String> tiers) {
        List<Node> nodes = Lists.newArrayList();
        for(String tier:tiers){
            nodes.addAll(getAllNodesInTier(applicationId,tier));
        }
        return nodes;
    }

    private List<Node> getAllNodesInTier(int applicationId,String tier) {
        ControllerConfig controller = config.getController();
        String endpoint = endpointBuilder.getNodesFromTierEndpoint(controller,applicationId,tier);
        List<Node> nodes = service.getNodes(clientBuilder,endpoint);
        return nodes;
    }


    private String getTiersFromBTApi(HealthRuleViolationEvent violationEvent) {
        ControllerConfig controller = config.getController();
        String endpoint = endpointBuilder.buildBTsEndpoint(controller,Integer.parseInt(violationEvent.getAppID()));
        List<BusinessTransaction> bts = service.getBTs(clientBuilder,endpoint);
        for(BusinessTransaction bt : bts){
            if(bt.getId() == Integer.parseInt(violationEvent.getAffectedEntityID())){
                return bt.getTierName();
            }
        }
        return "";
    }


    ADSnmpData buildFromOtherEvent(OtherEvent otherEvent){
        ADSnmpData snmpData = new ADSnmpData();
        snmpData.setApplication(otherEvent.getAppName());
        snmpData.setTriggeredBy(otherEvent.getEventNotificationName());
        snmpData.setNodes(" ");
        snmpData.setTxns(" ");
        snmpData.setEventTime(otherEvent.getEventNotificationTime());
        snmpData.setSeverity(otherEvent.getSeverity());
        snmpData.setType(getTypes(otherEvent));
        snmpData.setSubtype(" ");
        snmpData.setSummary(getSummary(otherEvent));
        if(config.getController() != null) {
            snmpData.setLink(CommonUtils.getAlertUrl(otherEvent));
        }
        snmpData.setTag(otherEvent.getTag());
        snmpData.setEventType("NON_POLICY_EVENT");
        snmpData.setIncidentId(otherEvent.getEventNotificationId());
        snmpData.setAccountId(CommonUtils.cleanUpAccountInfo(otherEvent.getAccountId()));
        return snmpData;
    }



    private List<String> getNodes(HealthRuleViolationEvent violationEvent) {
        List<String> nodes = Lists.newArrayList();
        if(isAffectedEntityType(violationEvent, "APPLICATION_COMPONENT_NODE")){
            nodes.add(violationEvent.getAffectedEntityName());
        }
        else if(violationEvent.getEvaluationEntity() != null) {
            for (EvaluationEntity evaluationEntity : violationEvent.getEvaluationEntity()) {
                if (evaluationEntity.getType().equalsIgnoreCase("APPLICATION_COMPONENT_NODE")) {
                    nodes.add(evaluationEntity.getName());
                }
            }
        }
        return nodes;
    }

    private boolean isAffectedEntityType(HealthRuleViolationEvent violationEvent, String type) {
        if(type.equalsIgnoreCase(violationEvent.getAffectedEntityType())){
            return true;
        }
        return false;
    }

    private List<String> getBTs(HealthRuleViolationEvent violationEvent) {
        List<String> bts = Lists.newArrayList();
        if(isAffectedEntityType(violationEvent, "BUSINESS_TRANSACTION")){
            bts.add(violationEvent.getAffectedEntityName());
        }
        else if(violationEvent.getEvaluationEntity() != null) {
            for (EvaluationEntity evaluationEntity : violationEvent.getEvaluationEntity()) {
                if (evaluationEntity.getType().equalsIgnoreCase("BUSINESS_TRANSACTION")) {
                    bts.add(evaluationEntity.getName());
                }
            }
        }
        return bts;
    }

    private List<String> getTiers(HealthRuleViolationEvent violationEvent) {
        List<String> tiers = Lists.newArrayList();
        if(isAffectedEntityType(violationEvent, "APPLICATION_COMPONENT")){
            tiers.add(violationEvent.getAffectedEntityName());
        }
        else if(violationEvent.getEvaluationEntity() != null) {
            for (EvaluationEntity evaluationEntity : violationEvent.getEvaluationEntity()) {
                if (evaluationEntity.getType().equalsIgnoreCase("APPLICATION_COMPONENT")) {
                    tiers.add(evaluationEntity.getName());
                }
            }
        }
        //for BTs, when the health rule is configured to be triggered when the condition fails on
        // avergae number of nodes in the tier, the controller doesn't pass tier name but just the application name.
        //In such cases, tier name needs to be pulled from API.
        if(tiers.isEmpty() && isAffectedEntityType(violationEvent,"BUSINESS_TRANSACTION")){
            String btTiers = getTiersFromBTApi(violationEvent);
            if(!Strings.isNullOrEmpty(btTiers)){
                tiers.add(btTiers);
            }
        }
        return tiers;
    }




    private String getSummary(OtherEvent otherEvent) {
        StringBuilder summaries = new StringBuilder("");
        if(otherEvent.getEventSummaries() != null){
            for(EventSummary eventSummary : otherEvent.getEventSummaries()){
                summaries.append(eventSummary.getEventSummaryString()).append(" ");
            }
        }
        return summaries.toString();
    }


    private String getTypes(OtherEvent otherEvent) {
        StringBuilder types = new StringBuilder("");
        if(otherEvent.getEventTypes() != null){
            for(EventType eventType : otherEvent.getEventTypes()){
                types.append(eventType.getEventType()).append(" ");
            }
        }
        return types.toString();
    }




}
