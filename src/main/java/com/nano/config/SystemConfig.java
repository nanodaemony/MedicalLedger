/*
 *  Copyright 2016, 2017 IBM, DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.nano.config;

import com.nano.core.Organization;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.sdk.helper.Utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Config allows for a global config of the toolkit. Central location for all
 * toolkit configuration defaults. Has a local config file that can override any
 * property defaults. Config file can be relocated via a system property
 * "org.hyperledger.fabric.sdk.configuration". Any property can be overridden
 * with environment variable and then overridden
 * with a java system property. Property hierarchy goes System property
 * overrides environment variable which overrides config file for default values specified here.
 * Config允许对工具箱进行全局配置。所有人的中心位置工具箱配置默认值。有一个本地配置文件可以重写任何
 * 属性默认值。配置文件可以通过系统属性重新定位"org.hyperledger.fabric.sdk.configuration". 任何属性都可以重写
 * 使用环境变量，然后重写具有java系统属性。属性层次结构变为系统属性
 * 重写环境变量，该变量重写此处指定的默认值的配置文件。
 * <p>
 * 测试配置
 */
public class SystemConfig {

    private static final Log logger = LogFactory.getLog(SystemConfig.class);
    // 默认配置
    private static final String DEFAULT_CONFIG = "src/test/java/org/hyperledger/fabric/sdk/testutils.properties";
    // 配置类
    private static final String ORG_HYPERLEDGER_FABRIC_SDK_CONFIGURATION = "org.hyperledger.fabric.sdktest.configuration";
    private static final String ORG_HYPERLEDGER_FABRIC_SDK_TEST_FABRIC_HOST = "ORG_HYPERLEDGER_FABRIC_SDK_TEST_FABRIC_HOST";
    // Change test to reference another host .. easier config for my testing on Windows !
    // private static final String LOCALHOST = System.getenv(ORG_HYPERLEDGER_FABRIC_SDK_TEST_FABRIC_HOST) == null ? "localhost" : System.getenv(ORG_HYPERLEDGER_FABRIC_SDK_TEST_FABRIC_HOST);
    private static final String SERVER_HOST = "172.20.29.67";
    // 基本路径
    private static final String PROPBASE = "org.hyperledger.fabric.sdktest.";

    private static final String INVOKEWAITTIME = PROPBASE + "InvokeWaitTime";
    private static final String DEPLOYWAITTIME = PROPBASE + "DeployWaitTime";
    private static final String PROPOSALWAITTIME = PROPBASE + "ProposalWaitTime";
    // org.hyperledger.fabric.sdktest.RunIdemixMTTest ORG_HYPERLEDGER_FABRIC_SDKTEST_RUNIDEMIXMTTEST
    private static final String RUNIDEMIXMTTEST = PROPBASE + "RunIdemixMTTest";

    private static final String INTEGRATIONTESTS_ORG = PROPBASE + "integrationTests.org.";
    private static final Pattern orgPat = Pattern.compile("^" + Pattern.quote(INTEGRATIONTESTS_ORG) + "([^\\.]+)\\.mspid$");

    private static final String INTEGRATIONTESTSTLS = PROPBASE + "integrationtests.tls";
    // location switching between fabric cryptogen and configtxgen artifacts for v1.0 and v1.1 in src/test/fixture/sdkintegration/e2e-2Orgs
    // Fabric配置版本
    private String FAB_CONFIG_GEN_VERS;

    // 配置的静态对象
    private static SystemConfig config;
    // SDK属性
    private static final Properties sdkProperties = new Properties();
    // 是否开启TLS
    private boolean runningTLS;
    private final boolean runningFabricCATLS;
    private final boolean runningFabricTLS;

    public boolean isRunningFabricTLS() {
        return runningFabricTLS;
    }

    /**
     * 组织的Map
     */
    private final HashMap<String, Organization> sampleOrgMap = new HashMap<>();

    /**
     * Hyperledger版本
     */
    private static final String ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION
            = System.getenv("ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION") == null ? "1.4.0" : System.getenv("ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION");

    /**
     * 记录Fabric版本
     */
    int[] fabricVersion = new int[3];

    /**
     * 私有构造方法默认初始化执行
     */
    private SystemConfig() {
        final String[] fvs = ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION.split("\\.");
        if (fvs.length != 3) {
            throw new AssertionError("Expected environment variable 'ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION' to be three numbers sperated by dots (1.0.0)  but got: " + ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION);
        }
        // 解析Fabric版本
        fabricVersion[0] = Integer.parseInt(fvs[0].trim());
        fabricVersion[1] = Integer.parseInt(fvs[1].trim());
        fabricVersion[2] = Integer.parseInt(fvs[2].trim());
        // 解析Fabric配置版本
        FAB_CONFIG_GEN_VERS = "v" + fabricVersion[0] + "." + fabricVersion[1];
        if (FAB_CONFIG_GEN_VERS.equalsIgnoreCase("v1.4")) {
            FAB_CONFIG_GEN_VERS = "v1.3";
        }
        // 加载文件
        File loadFile;
        FileInputStream configProps;
        try {
            // ORG_HYPERLEDGER_FABRIC_SDK_CONFIGURATION = "org.hyperledger.fabric.sdktest.configuration"
            // DEFAULT_CONFIG = "src/test/java/org/hyperledger/fabric/sdk/testutils.properties"
            loadFile = new File(System.getProperty(ORG_HYPERLEDGER_FABRIC_SDK_CONFIGURATION, DEFAULT_CONFIG)).getAbsoluteFile();
            logger.debug(String.format("Loading configuration from %s and it is present: %b", loadFile.toString(),
                    loadFile.exists()));
            // 加载配置文件
            configProps = new FileInputStream(loadFile);
            sdkProperties.load(configProps);
        } catch (IOException e) {
            // if not there no worries just use defaults
            // 这里默认打印这一句
            logger.warn(String.format("Failed to load any test configuration from: %s. Using toolkit defaults", DEFAULT_CONFIG));
        } finally {
            // 设置Default values
            defaultProperty(INVOKEWAITTIME, "32000");
            defaultProperty(DEPLOYWAITTIME, "120000");
            defaultProperty(PROPOSALWAITTIME, "120000");
            defaultProperty(RUNIDEMIXMTTEST, "false");

            // INTEGRATIONTESTS_ORG = "org.hyperledger.fabric.sdktest.integrationTests.org."
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.mspid", "Org1MSP");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.domname", "org1.example.com");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.ca_location", "http://" + SERVER_HOST + ":7054");
            System.out.println(INTEGRATIONTESTS_ORG + "************");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.caName", "ca0");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.peer_locations", "peer0.org1.example.com@grpc://" + SERVER_HOST + ":7051, peer1.org1.example.com@grpc://" + SERVER_HOST + ":7056");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.orderer_locations", "orderer.example.com@grpc://" + SERVER_HOST + ":7050");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.eventhub_locations", "peer0.org1.example.com@grpc://" + SERVER_HOST + ":7053,peer1.org1.example.com@grpc://" + SERVER_HOST + ":7058");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg2.mspid", "Org2MSP");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg2.domname", "org2.example.com");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg2.ca_location", "http://" + SERVER_HOST + ":8054");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg2.peer_locations", "peer0.org2.example.com@grpc://" + SERVER_HOST + ":8051,peer1.org2.example.com@grpc://" + SERVER_HOST + ":8056");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg2.orderer_locations", "orderer.example.com@grpc://" + SERVER_HOST + ":7050");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg2.eventhub_locations", "peer0.org2.example.com@grpc://" + SERVER_HOST + ":8053, peer1.org2.example.com@grpc://" + SERVER_HOST + ":8058");

            defaultProperty(INTEGRATIONTESTSTLS, null);

            // 配置是否使用TLS,这里结果为false
            runningTLS = null != sdkProperties.getProperty(INTEGRATIONTESTSTLS, null);
            runningFabricCATLS = runningTLS;
            runningFabricTLS = runningTLS;

            // 这里初始化组织org信息
            // 往Map里面放入组织名称与组织对象
            for (Map.Entry<Object, Object> x : sdkProperties.entrySet()) {
                final String key = x.getKey() + "";
                final String val = x.getValue() + "";
                if (key.startsWith(INTEGRATIONTESTS_ORG)) {
                    Matcher match = orgPat.matcher(key);
                    if (match.matches() && match.groupCount() == 1) {
                        String orgName = match.group(1).trim();
                        // 这里初始化两个组织名称: peerOrg1, peerOrg2
                        sampleOrgMap.put(orgName, new Organization(orgName, val.trim()));
                    }
                }
            }
            // 遍历组织Map进行处理
            for (Map.Entry<String, Organization> org : sampleOrgMap.entrySet()) {
                // 获取组织名称: peerOrg1, peerOrg2
                final String orgName = org.getKey();
                // System.out.println(orgName);
                // 获取对应的组织对象
                final Organization organization = org.getValue();
                // 构造Peer名称
                // peer0.org1.example.com@grpc://localhost:7051, peer1.org1.example.com@grpc://localhost:7056
                // peer0.org2.example.com@grpc://localhost:8051,peer1.org2.example.com@grpc://localhost:8056
                String peerNames = sdkProperties.getProperty(INTEGRATIONTESTS_ORG + orgName + ".peer_locations");
                String[] ps = peerNames.split("[ \t]*,[ \t]*");
                for (String peer : ps) {
                    String[] nl = peer.split("[ \t]*@[ \t]*");
                    // 添加Peer结点的路径到组织对象中
                    organization.addPeerLocation(nl[0], grpcTLSify(nl[1]));
                }
                // 设置组织域名
                // org1.example.com
                // org2.example.com
                final String domainName = sdkProperties.getProperty(INTEGRATIONTESTS_ORG + orgName + ".domname");
                organization.setDomainName(domainName);

                // 设置Orderer名称
                // orderer.example.com@grpc://localhost:7050
                // orderer.example.com@grpc://localhost:7050
                String ordererNames = sdkProperties.getProperty(INTEGRATIONTESTS_ORG + orgName + ".orderer_locations");
                ps = ordererNames.split("[ \t]*,[ \t]*");
                for (String peer : ps) {
                    String[] nl = peer.split("[ \t]*@[ \t]*");
                    // 添加Orderer结点的路径到组织对象中
                    organization.addOrdererLocation(nl[0], grpcTLSify(nl[1]));
                }
                // 判断Fabric是否是1.3之前的版本(这里没有配置)
                if (isFabricVersionBefore("1.3")) { // Eventhubs supported.
                    String eventHubNames = sdkProperties.getProperty(INTEGRATIONTESTS_ORG + orgName + ".eventhub_locations");
                    System.out.println(eventHubNames);
                    ps = eventHubNames.split("[ \t]*,[ \t]*");
                    for (String peer : ps) {
                        String[] nl = peer.split("[ \t]*@[ \t]*");
                        organization.addEventHubLocation(nl[0], grpcTLSify(nl[1]));
                    }
                }
                // 配置CA地址
                // http://localhost:7054
                // http://localhost:8054
                organization.setCALocation(httpTLSify(sdkProperties.getProperty((INTEGRATIONTESTS_ORG + org.getKey() + ".ca_location"))));

                // 配置CA名称
                // ca0与null
                organization.setCAName(sdkProperties.getProperty((INTEGRATIONTESTS_ORG + org.getKey() + ".caName")));

                // 默认runningFabricCATLS为false
                // 如果开启了TLS
                if (true) {
                    // 证书路径
                    // src/test/fixture/sdkintegration/e2e-2Orgs/v1.3/crypto-config/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem
                    // src/test/fixture/sdkintegration/e2e-2Orgs/v1.3/crypto-config/peerOrganizations/org2.example.com/ca/ca.org2.example.com-cert.pem
                    String cert = "src/test/fixture/sdkintegration/e2e-2Orgs/FAB_CONFIG_GEN_VERS/crypto-config/peerOrganizations/DNAME/ca/ca.DNAME-cert.pem"
                            .replaceAll("DNAME", domainName).replaceAll("FAB_CONFIG_GEN_VERS", FAB_CONFIG_GEN_VERS);

                    // 证书文件
                    File certFile = new File(cert);
                    // 判断证书是否存在
                    if (!certFile.exists() || !certFile.isFile()) {
                        throw new RuntimeException("TEST is missing cert file " + certFile.getAbsolutePath());
                    }
                    // 设置CA的属性
                    Properties properties = new Properties();
                    // 设置证书文件的绝对路径
                    properties.setProperty("pemFile", certFile.getAbsolutePath());
                    // D:\code\12_Paper\fabric-sdk-java\src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\peerOrganizations\org1.example.com\ca\ca.org1.example.com-cert.pem
                    // D:\code\12_Paper\fabric-sdk-java\src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\peerOrganizations\org2.example.com\ca\ca.org2.example.com-cert.pem
                    properties.setProperty("allowAllHostNames", "true"); //testing environment only NOT FOR PRODUCTION!
                    // 将CA属性设置到组织属性里面
                    organization.setCAProperties(properties);
                }
                // 打印初始化配置好的组织信息
                // SampleOrg{name='peerOrg1', mspid='Org1MSP', caClient=null, caName='ca0', caLocation='http://localhost:7054', caProperties={allowAllHostNames=true, pemFile=D:\code\12_Paper\fabric-sdk-java\src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\peerOrganizations\org1.example.com\ca\ca.org1.example.com-cert.pem}, userMap={}, peerLocations={peer0.org1.example.com=grpc://localhost:7051, peer1.org1.example.com=grpc://localhost:7056}, ordererLocations={orderer.example.com=grpc://localhost:7050}, eventHubLocations={}, adminUser=null, adminPeer=null, domainName='org1.example.com'}
                // SampleOrg{name='peerOrg2', mspid='Org2MSP', caClient=null, caName='null', caLocation='http://localhost:8054', caProperties={allowAllHostNames=true, pemFile=D:\code\12_Paper\fabric-sdk-java\src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\peerOrganizations\org2.example.com\ca\ca.org2.example.com-cert.pem}, userMap={}, peerLocations={peer0.org2.example.com=grpc://localhost:8051, peer1.org2.example.com=grpc://localhost:8056}, ordererLocations={orderer.example.com=grpc://localhost:7050}, eventHubLocations={}, adminUser=null, adminPeer=null, domainName='org2.example.com'}
                // System.out.println(sampleOrg.toString());
            }
        }
    }

    // 获取Fabric配置版本
    // 打印出V1.3
    public String getFabricConfigGenVers() {
        return FAB_CONFIG_GEN_VERS;
    }

    // 判断版本是否是某版本之后的
    public boolean isFabricVersionAtOrAfter(String version) {

        final int[] vers = parseVersion(version);
        for (int i = 0; i < 3; ++i) {
            if (vers[i] > fabricVersion[i]) {
                return false;
            }
        }
        return true;
    }

    public boolean isFabricVersionBefore(String version) {
        return !isFabricVersionAtOrAfter(version);
    }


    private static int[] parseVersion(String version) {
        if (null == version || version.isEmpty()) {
            throw new AssertionError("Version is bad :" + version);
        }
        String[] split = version.split("[ \\t]*\\.[ \\t]*");
        if (split.length < 1 || split.length > 3) {
            throw new AssertionError("Version is bad :" + version);
        }
        int[] ret = new int[3];
        int i = 0;
        for (; i < split.length; ++i) {
            ret[i] = Integer.parseInt(split[i]);
        }
        for (; i < 3; ++i) {
            ret[i] = 0;
        }
        return ret;
    }

    /**
     * 将普通Grpc换成基于TLS的Grpcs地址
     */
    private String grpcTLSify(String location) {
        location = location.trim();
        Exception e = Utils.checkGrpcUrl(location);
        if (e != null) {
            throw new RuntimeException(String.format("Bad TEST parameters for grpc url %s", location), e);
        }
        return runningFabricTLS ? location.replaceFirst("^grpc://", "grpcs://") : location;
    }

    /**
     * HTTP地址换成HTTPS地址
     */
    private String httpTLSify(String location) {
        location = location.trim();

        return runningFabricCATLS ? location.replaceFirst("^http://", "https://") : location;
    }

    /**
     * GetConfig return back singleton for SDK configuration.
     *
     * @return 全局配置对象
     */
    public static SystemConfig getConfig() {
        if (null == config) {
            config = new SystemConfig();
        }
        return config;
    }


    /**
     * 销毁配置对象
     */
    public void destroy() {
        // config.sampleOrgs = null;
        config = null;
    }

    /**
     * getProperty return back property for the given value.
     *
     * @return String value for the property
     */
    private String getProperty(String property) {
        String pro = sdkProperties.getProperty(property);
        if (null == pro) {
            logger.warn(String.format("No configuration value found for '%s'", property));
        }
        return pro;
    }

    private static void defaultProperty(String key, String value) {
        String ret = System.getProperty(key);
        if (ret != null) {
            sdkProperties.put(key, ret);
        } else {
            String envKey = key.toUpperCase().replaceAll("\\.", "_");
            ret = System.getenv(envKey);
            if (null != ret) {
                sdkProperties.put(key, ret);
            } else {
                if (null == sdkProperties.getProperty(key) && value != null) {
                    sdkProperties.put(key, value);
                }
            }
        }
    }

    public int getTransactionWaitTime() {
        return Integer.parseInt(getProperty(INVOKEWAITTIME));
    }

    public int getDeployWaitTime() {
        return Integer.parseInt(getProperty(DEPLOYWAITTIME));
    }

    public long getProposalWaitTime() {
        return Integer.parseInt(getProperty(PROPOSALWAITTIME));
    }

    public boolean getRunIdemixMTTest() {
        return Boolean.valueOf(getProperty(RUNIDEMIXMTTEST));
    }

    /**
     * 生成用于测试的组织对象
     */
    public Collection<Organization> getIntegrationTestsSampleOrgs() {
        // 复制上面的组织中的值
        return Collections.unmodifiableCollection(sampleOrgMap.values());
    }

    /**
     * 获取指定的组织信息
     */
    public Organization getIntegrationTestsSampleOrg(String name) {
        return sampleOrgMap.get(name);
    }

    public Properties getPeerProperties(String name) {
        return getEndPointProperties("peer", name);
    }

    /**
     * 获取Orderer的属性
     */
    public Properties getOrdererProperties(String name) {
        return getEndPointProperties("orderer", name);
    }

    /**
     * 获取Peer结点属性
     *
     * @param type 类型 Orderer或者Peer
     * @param name 名称
     */
    public Properties getEndPointProperties(final String type, final String name) {
        Properties properties = new Properties();
        // 域名
        final String domainName = getDomainName(name);

        // 获取证书
        File cert = Paths.get(getTestChannelPath(), "crypto-config/ordererOrganizations".replace("orderer", type),
                domainName, type + "s", name, "tls/server.crt").toFile();
        // 证书不存在
        if (!cert.exists()) {
            throw new RuntimeException(String.format("Missing cert file for: %s. Could not find at location: %s", name,
                    cert.getAbsolutePath()));
        }

        // isRunningAgainstFabric10 = false
        // 会进入下面的逻辑
        if (!isRunningAgainstFabric10()) {
            // 客户端证书
            File clientCert;
            // 客户端私钥
            File clientKey;
            // Orderer类型的结点
            if ("orderer".equals(type)) {
                clientCert = Paths.get(getTestChannelPath(), "crypto-config/ordererOrganizations/example.com/users/Admin@example.com/tls/client.crt").toFile();
                clientKey = Paths.get(getTestChannelPath(), "crypto-config/ordererOrganizations/example.com/users/Admin@example.com/tls/client.key").toFile();
                // Peer类型结点
            } else {
                clientCert = Paths.get(getTestChannelPath(), "crypto-config/peerOrganizations/", domainName, "users/User1@" + domainName, "tls/client.crt").toFile();
                clientKey = Paths.get(getTestChannelPath(), "crypto-config/peerOrganizations/", domainName, "users/User1@" + domainName, "tls/client.key").toFile();
            }
            // 文件不存在
            if (!clientCert.exists()) {
                throw new RuntimeException(String.format("Missing  client cert file for: %s. Could not find at location: %s", name, clientCert.getAbsolutePath()));
            }
            if (!clientKey.exists()) {
                throw new RuntimeException(String.format("Missing  client key file for: %s. Could not find at location: %s", name, clientKey.getAbsolutePath()));
            }
            // 设置属性
            properties.setProperty("clientCertFile", clientCert.getAbsolutePath());
            properties.setProperty("clientKeyFile", clientKey.getAbsolutePath());
        }
        // 设置属性
        properties.setProperty("pemFile", cert.getAbsolutePath());
        properties.setProperty("hostnameOverride", name);
        properties.setProperty("sslProvider", "openSSL");
        properties.setProperty("negotiationType", "TLS");

        return properties;
    }

    public Properties getEventHubProperties(String name) {
        // uses same as named peer
        return getEndPointProperties("peer", name);
    }

    public String getTestChannelPath() {
        return "src/test/fixture/sdkintegration/e2e-2Orgs/" + FAB_CONFIG_GEN_VERS;
    }

    public boolean isRunningAgainstFabric10() {
        // false
        return isFabricVersionBefore("1.1");
    }

    /**
     * configtxlator的URL地址
     * url location of configtxlator
     */
    public String getFabricConfigTxLaterLocation() {
        return "http://" + SERVER_HOST + ":7059";
    }

    /**
     * 获取网络配置的YAML文件
     * Returns the appropriate Network Config YAML file based on whether TLS is currently enabled or not
     *
     * @return The appropriate Network Config YAML file
     */
    public File getTestNetworkConfigFileYAML() {
        // 路径名称
        String pathName = "src/test/fixture/sdkintegration/network_configs/";
        // 文件名称:根据是否开启TLS选用不同的YAML配置文件
        String fileName = runningTLS ? "network-config-tls.yaml" : "network-config.yaml";
        File file = new File(pathName, fileName);
        // 进入下面的逻辑
        if (!"localhost".equals(SERVER_HOST) || isFabricVersionAtOrAfter("1.3")) {
            // change on the fly ...
            File temp = null;
            try {
                // 生成临时文件
                temp = File.createTempFile(fileName, "-FixedUp.yaml");
                // For testing start fresh
                if (temp.exists()) {
                    temp.delete();
                }
                byte[] data = Files.readAllBytes(Paths.get(file.getAbsolutePath()));

                // 这里就是生成Source的文件
                String sourceText = new String(data, StandardCharsets.UTF_8);
                sourceText = sourceText.replaceAll("https://localhost", "https://" + SERVER_HOST);
                sourceText = sourceText.replaceAll("http://localhost", "http://" + SERVER_HOST);
                sourceText = sourceText.replaceAll("grpcs://localhost", "grpcs://" + SERVER_HOST);
                sourceText = sourceText.replaceAll("grpc://localhost", "grpc://" + SERVER_HOST);

                if (isFabricVersionAtOrAfter("1.3")) {
                    // eventUrl: grpc://localhost:8053
                    sourceText = sourceText.replaceAll("(?m)^[ \\t]*eventUrl:", "# eventUrl:");
                }
                // 写入文件
                Files.write(Paths.get(temp.getAbsolutePath()), sourceText.getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.CREATE_NEW, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
                if (!Objects.equals("true", System.getenv(ORG_HYPERLEDGER_FABRIC_SDK_TEST_FABRIC_HOST + "_KEEP"))) {
                    temp.deleteOnExit();
                } else {
                    System.err.println("produced new network-config.yaml file at:" + temp.getAbsolutePath());
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            // 返回生成的临时文件
            file = temp;
        }
        return file;
    }

    /**
     * 获取域名
     */
    private String getDomainName(final String name) {
        int dot = name.indexOf(".");
        if (-1 == dot) {
            return null;
        } else {
            return name.substring(dot + 1);
        }
    }

    /**
     * 获取组织的Map
     * @return Map
     */
    public Map<String, Organization> getSampleOrgMap() {
        return sampleOrgMap;
    }

    public static void main(String[] ars) {
        final SystemConfig config = getConfig();
        final boolean runningAgainstFabric10 = config.isRunningAgainstFabric10();
        // false
        System.out.println(runningAgainstFabric10);

        System.out.println(config.getFabricConfigGenVers());
        // src/test/fixture/sdkintegration/e2e-2Orgs/v2.1
        System.out.println(config.getTestChannelPath());
        // C:\Users\nano\AppData\Local\Temp\network-config.yaml3043783252187129749-FixedUp.yaml
        System.out.println(config.getTestNetworkConfigFileYAML());
        System.out.println(config.isRunningAgainstFabric10());
    }

}
