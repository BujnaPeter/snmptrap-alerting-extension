package com.appdynamics.extensions.snmp.api;


import com.appdynamics.extensions.snmp.config.ControllerConfig;

import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;

public class EndpointBuilder {

    public static final String HTTPS = "https://";
    public static final String HTTP = "http://";
    public static final String APP_ID_HOLDER = "<#APP_ID#>";
    public static final String TIER_HOLDER = "<#TIER#>";
    public static final String NODE_HOLDER = "<#NODE#>";
    public static final String BT_ENDPOINT = "/controller/rest/applications/"+ APP_ID_HOLDER + "/business-transactions";
    public static final String NODES_ENDPOINT = "/controller/rest/applications/"+ APP_ID_HOLDER + "/nodes";
    public static final String NODES_FROM_TIER_ENDPOINT = "/controller/rest/applications/"+ APP_ID_HOLDER + "/tiers/" + TIER_HOLDER + "/nodes";
    public static final String A_NODE_ENDPOINT = "/controller/rest/applications/"+ APP_ID_HOLDER + "/nodes/" + NODE_HOLDER;

    public String buildBTsEndpoint(ControllerConfig controller,int applicationId) {
        StringBuffer sb = getHost(controller).append(BT_ENDPOINT);
        String endpoint =  sb.toString();
        return endpoint.replaceFirst(APP_ID_HOLDER,Integer.toString(applicationId));
    }

    public String buildNodesEndpoint(ControllerConfig controller,int applicationId) {
        StringBuffer sb = getHost(controller).append(NODES_ENDPOINT);
        String endpoint =  sb.toString();
        return endpoint.replaceFirst(APP_ID_HOLDER,Integer.toString(applicationId));
    }

    public String getNodesFromTierEndpoint(ControllerConfig controller,int applicationId,String tier) throws UnsupportedEncodingException {
        StringBuffer sb = getHost(controller).append(NODES_FROM_TIER_ENDPOINT);
        String endpoint = sb.toString();
        endpoint = endpoint.replaceFirst(APP_ID_HOLDER,Integer.toString(applicationId));
        endpoint = endpoint.replaceFirst(TIER_HOLDER, URLEncoder.encode(tier,"UTF-8"));
        return endpoint;
    }

    public String getANodeEndpoint(ControllerConfig controller,int applicationId,String node) throws UnsupportedEncodingException {
        StringBuffer sb = getHost(controller).append(A_NODE_ENDPOINT);
        String endpoint = sb.toString();
        endpoint = endpoint.replaceFirst(APP_ID_HOLDER,Integer.toString(applicationId));
        endpoint = endpoint.replaceFirst(NODE_HOLDER,URLEncoder.encode(node,"UTF-8"));
        return endpoint;
    }


    private StringBuffer getHost(ControllerConfig controller){
        StringBuffer sb = new StringBuffer();
        if(controller.isUseSsl()){
            sb.append(HTTPS);
        }
        else{
            sb.append(HTTP);
        }
        sb.append(controller.getHost()).append(":").append(controller.getPort());
        return sb;
    }
}
