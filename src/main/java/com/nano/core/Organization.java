package com.nano.core;

import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric_ca.sdk.HFCAClient;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * Sample Organization Representation
 * 组织表示类
 *
 * Keeps track which resources are defined for the Organization it represents.
 * @author nano
 */
public class Organization {

    /**
     * 组织名称
     */
    final String name;

    /**
     * MSP ID
     */
    final String mspid;

    /**
     * CA客户端
     */
    HFCAClient caClient;

    /**
     * CA名称
     */
    private String caName;

    /**
     * CA路径
     */
    private String caLocation;

    /**
     * CA配置属性
     */
    private Properties caProperties = null;

    /**
     * 用户Map
     */
    Map<String, User> userMap = new HashMap<>();

    /**
     * Peer结点路径Map
     */
    Map<String, String> peerLocationMap = new HashMap<>();

    /**
     * Orderer结点路径Map
     */
    Map<String, String> ordererLocationMap = new HashMap<>();

    /**
     * 事件Hub路径Map
     */
    Map<String, String> eventHubLocationMap = new HashMap<>();

    /**
     * 组织的Admin用户
     */
    private MedicalUser adminUser;

    /**
     * Peer结点中的Admin
     */
    private MedicalUser adminPeer;

    /**
     * 组织域名
     */
    private String domainName;


    @Override
    public String toString() {
        return "SampleOrg{" +
                "name='" + name + '\'' +
                ", mspid='" + mspid + '\'' +
                ", caClient=" + caClient +
                ", caName='" + caName + '\'' +
                ", caLocation='" + caLocation + '\'' +
                ", caProperties=" + caProperties +
                ", userMap=" + userMap +
                ", peerLocations=" + peerLocationMap +
                ", ordererLocations=" + ordererLocationMap +
                ", eventHubLocations=" + eventHubLocationMap +
                ", adminUser=" + adminUser +
                ", adminPeer=" + adminPeer +
                ", domainName='" + domainName + '\'' +
                '}';
    }

    public String getCAName() {
        return caName;
    }

    public Organization(String name, String mspid) {
        this.name = name;
        this.mspid = mspid;
    }

    public MedicalUser getAdminUser() {
        return adminUser;
    }

    public void setAdminUser(MedicalUser adminUser) {
        this.adminUser = adminUser;
    }

    public String getMSPID() {
        return mspid;
    }

    public String getCALocation() {
        return this.caLocation;
    }

    public void setCALocation(String caLocation) {
        this.caLocation = caLocation;
    }

    public void addPeerLocation(String name, String location) {
        peerLocationMap.put(name, location);
    }

    public void addOrdererLocation(String name, String location) {
        ordererLocationMap.put(name, location);
    }

    public void addEventHubLocation(String name, String location) {

        eventHubLocationMap.put(name, location);
    }

    public String getPeerLocation(String name) {
        return peerLocationMap.get(name);

    }

    public String getOrdererLocation(String name) {
        return ordererLocationMap.get(name);

    }

    public String getEventHubLocation(String name) {
        return eventHubLocationMap.get(name);

    }

    public Set<String> getPeerNames() {

        return Collections.unmodifiableSet(peerLocationMap.keySet());
    }


    public Set<String> getOrdererNames() {

        return Collections.unmodifiableSet(ordererLocationMap.keySet());
    }

    public Set<String> getEventHubNames() {

        return Collections.unmodifiableSet(eventHubLocationMap.keySet());
    }

    public HFCAClient getCAClient() {
        return caClient;
    }

    public void setCAClient(HFCAClient caClient) {
        this.caClient = caClient;
    }

    public String getName() {
        return name;
    }

    public void addUser(MedicalUser user) {
        userMap.put(user.getName(), user);
    }

    public User getUser(String name) {
        return userMap.get(name);
    }

    public Collection<String> getOrdererLocationMap() {
        return Collections.unmodifiableCollection(ordererLocationMap.values());
    }

    public Collection<String> getEventHubLocationMap() {
        return Collections.unmodifiableCollection(eventHubLocationMap.values());
    }


    public void setCAProperties(Properties caProperties) {
        this.caProperties = caProperties;
    }

    public Properties getCAProperties() {
        return caProperties;
    }


    public MedicalUser getAdminPeer() {
        return adminPeer;
    }

    public void setAdminPeer(MedicalUser adminPeer) {
        this.adminPeer = adminPeer;
    }

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

    public String getDomainName() {
        return domainName;
    }

    public void setCAName(String caName) {
        this.caName = caName;
    }
}
