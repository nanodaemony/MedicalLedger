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
 *
 */
public class SampleOrg {

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
    Map<String, String> peerLocations = new HashMap<>();

    /**
     * Orderer结点路径Map
     */
    Map<String, String> ordererLocations = new HashMap<>();

    /**
     * 事件Hub路径Map
     */
    Map<String, String> eventHubLocations = new HashMap<>();

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
                ", peerLocations=" + peerLocations +
                ", ordererLocations=" + ordererLocations +
                ", eventHubLocations=" + eventHubLocations +
                ", adminUser=" + adminUser +
                ", adminPeer=" + adminPeer +
                ", domainName='" + domainName + '\'' +
                '}';
    }

    public String getCAName() {
        return caName;
    }

    public SampleOrg(String name, String mspid) {
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

        peerLocations.put(name, location);
    }

    public void addOrdererLocation(String name, String location) {

        ordererLocations.put(name, location);
    }

    public void addEventHubLocation(String name, String location) {

        eventHubLocations.put(name, location);
    }

    public String getPeerLocation(String name) {
        return peerLocations.get(name);

    }

    public String getOrdererLocation(String name) {
        return ordererLocations.get(name);

    }

    public String getEventHubLocation(String name) {
        return eventHubLocations.get(name);

    }

    public Set<String> getPeerNames() {

        return Collections.unmodifiableSet(peerLocations.keySet());
    }


    public Set<String> getOrdererNames() {

        return Collections.unmodifiableSet(ordererLocations.keySet());
    }

    public Set<String> getEventHubNames() {

        return Collections.unmodifiableSet(eventHubLocations.keySet());
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

    public Collection<String> getOrdererLocations() {
        return Collections.unmodifiableCollection(ordererLocations.values());
    }

    public Collection<String> getEventHubLocations() {
        return Collections.unmodifiableCollection(eventHubLocations.values());
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
