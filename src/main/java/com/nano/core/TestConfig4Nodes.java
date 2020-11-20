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
package com.nano.core;

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
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
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
 * @author nano
 */
public class TestConfig4Nodes {

    // Logger
    private static final Log logger = LogFactory.getLog(TestConfig4Nodes.class);
    // 默认配置
    private static final String DEFAULT_CONFIG = "src/test/java/org/hyperledger/fabric/sdk/testutils.properties";
    // 配置类
    private static final String ORG_HYPERLEDGER_FABRIC_SDK_CONFIGURATION = "org.hyperledger.fabric.sdktest.configuration";
    private static final String ORG_HYPERLEDGER_FABRIC_SDK_TEST_FABRIC_HOST = "ORG_HYPERLEDGER_FABRIC_SDK_TEST_FABRIC_HOST";

    // Server地址
    private static final String LOCALHOST = "172.20.29.67";
    // 基本路径
    private static final String PROPBASE = "org.hyperledger.fabric.sdktest.";
    private static final String INVOKEWAITTIME = PROPBASE + "InvokeWaitTime";
    private static final String DEPLOYWAITTIME = PROPBASE + "DeployWaitTime";
    private static final String PROPOSALWAITTIME = PROPBASE + "ProposalWaitTime";
    // org.hyperledger.fabric.sdktest.RunIdemixMTTest ORG_HYPERLEDGER_FABRIC_SDKTEST_RUNIDEMIXMTTEST
    private static final String RUNIDEMIXMTTEST = PROPBASE + "RunIdemixMTTest";
    private static final String INTEGRATIONTESTS_ORG = PROPBASE + "integrationTests.org.";
    private static final String INTEGRATIONTESTSTLS = PROPBASE + "integrationtests.tls";

    private static final Pattern orgPattern = Pattern.compile("^" + Pattern.quote(INTEGRATIONTESTS_ORG) + "([^\\.]+)\\.mspid$");

    // location switching between fabric cryptogen and configtxgen artifacts for v1.0 and v1.1 in src/test/fixture/sdkintegration/e2e-2Orgs
    // Fabric配置版本
    private String fabConfigGenVers = "v1.3";

    // 配置的静态对象
    private static TestConfig4Nodes config;
    // SDK属性
    private static final Properties systemProperties = new Properties();
    // 是否开启TLS
    private boolean runningTLS;
    private boolean runningFabricCATLS;
    private boolean runningFabricTLS;

    public boolean isRunningFabricTLS() {
        return runningFabricTLS;
    }

    /**
     * 组织的Map
     */
    private final HashMap<String, Organization> organizationMap = new HashMap<>();

    /**
     * Hyperledger版本
     */
    private static final String ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION = "1.4.0";

    /**
     * 记录Fabric版本
     */
    int[] fabricVersion = new int[3];

    /**
     * 私有构造方法默认初始化执行
     */
    private TestConfig4Nodes() {

        // 初始化版本
        initConfigVersion();

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
            systemProperties.load(configProps);
        } catch (IOException e) {
            // if not there no worries just use defaults
            // 这里默认打印这一句
            logger.warn(String.format("Failed to load any test configuration from: %s. Using toolkit defaults", DEFAULT_CONFIG));
        } finally {
            // 初始化系统环境变量(重点配置)
            initSystemEnvironment();

            // 初始化组织信息!!!!!!!!!!
            initOrganizations();
        }
    }

    /**
     * 初始化组织!!!!!
     */
    private void initOrganizations() {
        // 初始化两个组织
        Organization peerOrganization1 = new Organization("peerOrg1", "Org1MSP");
        Organization peerOrganization2 = new Organization("peerOrg2", "Org2MSP");

        peerOrganization1.addPeerLocation("peer0.org1.example.com", "grpcs://172.20.29.31:7051");
        peerOrganization1.addPeerLocation("peer1.org1.example.com", "grpcs://172.20.29.32:7051");
        peerOrganization2.addPeerLocation("peer0.org2.example.com", "grpcs://172.20.29.33:7051");

        // 设置组织域名
        peerOrganization1.setDomainName("org1.example.com");
        peerOrganization2.setDomainName("org2.example.com");

        // 设置Orderer结点地址(注意这里只有一个地址,如果有多个地址可以像上面这样重复添加)
        peerOrganization1.addOrdererLocation("orderer0.example.com", "grpcs://172.20.29.30:7050");
        peerOrganization1.addOrdererLocation("orderer1.example.com", "grpcs://172.20.29.31:7050");
        peerOrganization1.addOrdererLocation("orderer2.example.com", "grpcs://172.20.29.32:7050");
        peerOrganization2.addOrdererLocation("orderer0.example.com", "grpcs://172.20.29.30:7050");
        peerOrganization2.addOrdererLocation("orderer1.example.com", "grpcs://172.20.29.31:7050");
        peerOrganization2.addOrdererLocation("orderer2.example.com", "grpcs://172.20.29.32:7050");

        // 设置CA地址
        peerOrganization1.setCALocation("http://172.20.29.31:7054");
        //peerOrganization2.setCALocation("http://172.20.29.67:8054");

        // 设置CA名称
        peerOrganization1.setCAName("ca0.example.com");
        peerOrganization2.setCAName(null);

        // 如果开启了TLS
        if (true) {
            // 证书路径
            String cert1 = "src/test/fixture/sdkintegration/e2e-2Orgs/v1.33/crypto-config/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem";
            String cert2 = "src/test/fixture/sdkintegration/e2e-2Orgs/v1.33/crypto-config/peerOrganizations/org2.example.com/ca/ca.org2.example.com-cert.pem";

            // 证书文件
            File certFile1 = new File(cert1);
            File certFile2 = new File(cert2);
            // 判断证书是否存在
            if (!certFile1.exists() || !certFile1.isFile() || !certFile2.exists() || !certFile2.isFile()) {
                throw new RuntimeException("TEST is missing cert file." + certFile1.getAbsolutePath() + certFile2.getAbsolutePath());
            }
            // 设置CA的属性
            Properties properties1 = new Properties();
            // 设置证书文件的绝对路径
            properties1.setProperty("pemFile", certFile1.getAbsolutePath());
            // testing environment only NOT FOR PRODUCTION!
            // 仅仅是用于测试环境,不能用于生产环境!!!
            properties1.setProperty("allowAllHostNames", "true");
            // 将CA属性设置到组织属性里面
            peerOrganization1.setCAProperties(properties1);

            // 设置CA的属性
            Properties properties2 = new Properties();
            // 设置证书文件的绝对路径
            properties2.setProperty("pemFile", certFile2.getAbsolutePath());
            // testing environment only NOT FOR PRODUCTION!
            // 仅仅是用于测试环境,不能用于生产环境!!!
            properties2.setProperty("allowAllHostNames", "true");
            // 将CA属性设置到组织属性里面
            peerOrganization2.setCAProperties(properties2);
        }
        // 组织信息加入Map
        organizationMap.put("peerOrg1", peerOrganization1);
        organizationMap.put("peerOrg2", peerOrganization2);
    }


    /**
     * 初始化配置版本(不能少!)
     */
    private void initConfigVersion() {
        final String[] fvs = ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION.split("\\.");
        if (fvs.length != 3) {
            throw new AssertionError("Expected environment variable 'ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION' to be three numbers sperated by dots (1.0.0)  but got: " + ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION);
        }
        // 解析Fabric版本
        fabricVersion[0] = Integer.parseInt(fvs[0].trim());
        fabricVersion[1] = Integer.parseInt(fvs[1].trim());
        fabricVersion[2] = Integer.parseInt(fvs[2].trim());
        // 解析Fabric配置版本
        fabConfigGenVers = "v" + fabricVersion[0] + "." + fabricVersion[1];
        if (fabConfigGenVers.equalsIgnoreCase("v1.4")) {
            fabConfigGenVers = "v1.3";
        }
    }

    /**
     * 初始化系统环境变量
     */
    private void initSystemEnvironment() {
        // 设置系统环境变量
        // 调用等待时间
        defaultEnvironmentProperty(INVOKEWAITTIME, "32000");
        // 部署等待时间
        defaultEnvironmentProperty(DEPLOYWAITTIME, "1200000");
        // 提案等待时间
        defaultEnvironmentProperty(PROPOSALWAITTIME, "1200000");
        // 是否开启IDEMIXM测试
        defaultEnvironmentProperty(RUNIDEMIXMTTEST, "false");

        // 这里设置组织的MSPID信息
        defaultEnvironmentProperty(INTEGRATIONTESTS_ORG + "peerOrg1.mspid", "Org1MSP");
        // 这里设置组织的域名信息
        defaultEnvironmentProperty(INTEGRATIONTESTS_ORG + "peerOrg1.domname", "org1.example.com");
        // 组织1的CA地址信息
        defaultEnvironmentProperty(INTEGRATIONTESTS_ORG + "peerOrg1.ca_location", "http://" + LOCALHOST + ":7054");
        // 组织1的CA名称
        defaultEnvironmentProperty(INTEGRATIONTESTS_ORG + "peerOrg1.caName", "ca0");
        // 组织1的全部Peer结点地址
        defaultEnvironmentProperty(INTEGRATIONTESTS_ORG + "peerOrg1.peer_locations",
                // 这里有两个Peer结点地址
                "peer0.org1.example.com@grpc://" + LOCALHOST + ":7051, " +
                        "peer1.org1.example.com@grpc://" + LOCALHOST + ":7056");
        // 组织1的Order结点地址
        defaultEnvironmentProperty(INTEGRATIONTESTS_ORG + "peerOrg1.orderer_locations", "orderer.example.com@grpc://" + LOCALHOST + ":7050");
        // 组织1的事件Hub地址
        defaultEnvironmentProperty(INTEGRATIONTESTS_ORG + "peerOrg1.eventhub_locations",
                // 这里有两个Peer结点地址
                "peer0.org1.example.com@grpc://" + LOCALHOST + ":7053," +
                        "peer1.org1.example.com@grpc://" + LOCALHOST + ":7058");
        // 下面同样的方式设置组织2的信息
        defaultEnvironmentProperty(INTEGRATIONTESTS_ORG + "peerOrg2.mspid", "Org2MSP");
        defaultEnvironmentProperty(INTEGRATIONTESTS_ORG + "peerOrg2.domname", "org2.example.com");
        defaultEnvironmentProperty(INTEGRATIONTESTS_ORG + "peerOrg2.ca_location", "http://" + LOCALHOST + ":8054");
        defaultEnvironmentProperty(INTEGRATIONTESTS_ORG + "peerOrg2.peer_locations",
                "peer0.org2.example.com@grpc://" + LOCALHOST + ":8051," +
                        "peer1.org2.example.com@grpc://" + LOCALHOST + ":8056");
        defaultEnvironmentProperty(INTEGRATIONTESTS_ORG + "peerOrg2.orderer_locations", "orderer.example.com@grpc://" + LOCALHOST + ":7050");
        defaultEnvironmentProperty(INTEGRATIONTESTS_ORG + "peerOrg2.eventhub_locations",
                "peer0.org2.example.com@grpc://" + LOCALHOST + ":8053, " +
                        "peer1.org2.example.com@grpc://" + LOCALHOST + ":8058");

        // 这里设置是否开启TLS,默认没有开启
        defaultEnvironmentProperty(INTEGRATIONTESTSTLS, null);

        // 配置是否使用TLS,这里结果为false
        runningTLS = null != systemProperties.getProperty(INTEGRATIONTESTSTLS, null);
        runningFabricCATLS = runningTLS;
        runningFabricTLS = runningTLS;
    }

    // 获取Fabric配置版本
    // 打印出V1.3
    public String getFabricConfigGenVers() {
        return fabConfigGenVers;
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

    /**
     * 解析版本
     */
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
    public static TestConfig4Nodes getConfig() {
        if (null == config) {
            config = new TestConfig4Nodes();
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
        String pro = systemProperties.getProperty(property);
        if (null == pro) {
            logger.warn(String.format("No configuration value found for '%s'", property));
        }
        return pro;
    }

    /**
     * 设置系统环境变量
     *
     * @param key 键
     * @param value  值
     */
    private static void defaultEnvironmentProperty(String key, String value) {
        String ret = System.getProperty(key);
        if (ret != null) {
            systemProperties.put(key, ret);
        } else {
            String envKey = key.toUpperCase().replaceAll("\\.", "_");
            ret = System.getenv(envKey);
            if (null != ret) {
                systemProperties.put(key, ret);
            } else {
                if (null == systemProperties.getProperty(key) && value != null) {
                    systemProperties.put(key, value);
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
        return Collections.unmodifiableCollection(organizationMap.values());
    }

    /**
     * 获取指定的组织信息
     */
    public Organization getIntegrationTestsSampleOrg(String name) {
        return organizationMap.get(name);
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
        return "src/test/fixture/sdkintegration/e2e-2Orgs/v1.33";
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
        return "http://" + LOCALHOST + ":7059";
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
        if (!"localhost".equals(LOCALHOST) || isFabricVersionAtOrAfter("1.3")) {
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
                sourceText = sourceText.replaceAll("https://localhost", "https://" + LOCALHOST);
                sourceText = sourceText.replaceAll("http://localhost", "http://" + LOCALHOST);
                sourceText = sourceText.replaceAll("grpcs://localhost", "grpcs://" + LOCALHOST);
                sourceText = sourceText.replaceAll("grpc://localhost", "grpc://" + LOCALHOST);
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
    public Map<String, Organization> getOrganizationMap() {
        return organizationMap;
    }


    /**
     * 获取全部的组织信息
     */
    public Set<Organization> getOrganizationSet() {
        return new HashSet<>(organizationMap.values());
    }

    public static void main(String[] ars) {
        final TestConfig4Nodes config = getConfig();
        final boolean runningAgainstFabric10 = config.isRunningAgainstFabric10();
        // false
        System.out.println(runningAgainstFabric10);

        System.out.println(config.getFabricConfigGenVers());
        // src/test/fixture/sdkintegration/e2e-2Orgs/v2.1
        System.out.println(config.getTestChannelPath());
        // C:\Users\nano\AppData\Local\Temp\network-config.yaml3043783252187129749-FixedUp.yaml
        //System.out.println(config.getTestNetworkConfigFileYAML());
        System.out.println(config.isRunningAgainstFabric10());

    }

}
