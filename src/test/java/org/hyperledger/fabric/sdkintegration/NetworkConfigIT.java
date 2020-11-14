/*
 *  Copyright 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdkintegration;

import java.io.File;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;

import org.hyperledger.fabric.protos.peer.Query.ChaincodeInfo;
import org.hyperledger.fabric.sdk.BlockEvent;
import org.hyperledger.fabric.sdk.BlockEvent.TransactionEvent;
import org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy;
import org.hyperledger.fabric.sdk.ChaincodeID;
import org.hyperledger.fabric.sdk.ChaincodeResponse.Status;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.InstallProposalRequest;
import org.hyperledger.fabric.sdk.InstantiateProposalRequest;
import org.hyperledger.fabric.sdk.NetworkConfig;
import org.hyperledger.fabric.sdk.NetworkConfig.CAInfo;
import org.hyperledger.fabric.sdk.NetworkConfig.UserInfo;
import org.hyperledger.fabric.sdk.Orderer;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.ProposalResponse;
import org.hyperledger.fabric.sdk.QueryByChaincodeRequest;
import org.hyperledger.fabric.sdk.SDKUtils;
import org.hyperledger.fabric.sdk.TestConfigHelper;
import org.hyperledger.fabric.sdk.TransactionProposalRequest;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionEventException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.hyperledger.fabric.sdk.testutils.TestUtils.MockUser;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.HFCAInfo;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.junit.BeforeClass;
import org.junit.Test;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.getMockUser;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.resetConfig;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Integration test for the Network Configuration YAML (/JSON) file
 *
 * <p>
 * This test requires that End2endIT has previously been run in order to set up the channel.
 * It has no dependencies on any of the other integration tests.
 * That is, it can be run with or without having run the other End to End tests (apart from End2EndIT).
 * <br>
 * Furthermore, it can be executed multiple times without having to restart the blockchain.
 * <p>
 * One other requirement is that the network configuration file matches the topology
 * that is set up by End2endIT.
 * <p>
 * It first examines the "foo" channel and checks that CHAIN_CODE_NAME has been instantiated on the channel,
 * and if not it deploys the chaincode with that name.
 */
public class NetworkConfigIT {

    /**
     * 测试配置
     */
    private static final TestConfig testConfig = TestConfig.getConfig();

    /**
     * 组织1
     */
    private static final String TEST_ORG = "Org1";

    private static final String TEST_FIXTURES_PATH = "src/test/fixture";

    private static final String CHAIN_CODE_PATH = "github.com/example_cc";

    /**
     * 使用另一个链码
     */
    private static final String CHAIN_CODE_NAME = "cc-NetworkConfigTest-001";

    private static final String CHAIN_CODE_VERSION = "1";

    private static final String FOO_CHANNEL_NAME = "foo";

    private static final TestConfigHelper configHelper = new TestConfigHelper();

    private static NetworkConfig networkConfig;

    /**
     * 注册的用户Map
     */
    private static Map<String, User> orgRegisteredUserMap = new HashMap<>();

    /**
     * 类加载之前初始化
     */
    @BeforeClass
    public static void doMainSetup() throws Exception {
        print("\n\n\nRUNNING: NetworkConfigIT.\n");
        // 重置配置
        resetConfig();

        configHelper.customizeConfig();

        // Use the appropriate TLS/non-TLS network config file
        // 使用网络配置文件进行配置
        networkConfig = NetworkConfig.fromYamlFile(testConfig.getTestNetworkConfigFileYAML());

        // 获取全部Order名称: orderer.example.com
        networkConfig.getOrdererNames().forEach(ordererName -> {
            try {
                // 获取Order的属性
                Properties ordererProperties = networkConfig.getOrdererProperties(ordererName);
                // 获取Order属性
                Properties testProp = testConfig.getEndPointProperties("orderer", ordererName);
                // 属性转移?
                ordererProperties.setProperty("clientCertFile", testProp.getProperty("clientCertFile"));
                ordererProperties.setProperty("clientKeyFile", testProp.getProperty("clientKeyFile"));
                // 设置Order的属性
                networkConfig.setOrdererProperties(ordererName, ordererProperties);
            } catch (InvalidArgumentException e) {
                throw new RuntimeException(e);
            }
        });

        // 获取全部Peers
        // peer0.org2.example.com
        // peer0.org1.example.com
        // peer1.org1.example.com
        networkConfig.getPeerNames().forEach(peerName -> {
            try {
                // 也就是复制秘钥与证书的路径
                Properties peerProperties = networkConfig.getPeerProperties(peerName);
                Properties testProp = testConfig.getEndPointProperties("peer", peerName);
                peerProperties.setProperty("clientCertFile", testProp.getProperty("clientCertFile"));
                peerProperties.setProperty("clientKeyFile", testProp.getProperty("clientKeyFile"));
                networkConfig.setPeerProperties(peerName, peerProperties);
            } catch (InvalidArgumentException e) {
                throw new RuntimeException(e);
            }
        });

        // eventhubName是空的?
        networkConfig.getEventHubNames().forEach(eventhubName -> {
            try {
                Properties eventHubsProperties = networkConfig.getEventHubsProperties(eventhubName);
                Properties testProp = testConfig.getEndPointProperties("peer", eventhubName);
                eventHubsProperties.setProperty("clientCertFile", testProp.getProperty("clientCertFile"));
                eventHubsProperties.setProperty("clientKeyFile", testProp.getProperty("clientKeyFile"));
                networkConfig.setEventHubProperties(eventhubName, eventHubsProperties);
            } catch (InvalidArgumentException e) {
                throw new RuntimeException(e);
            }
        });

        // Check if we get access to defined CAs!
        // 组织信息
        NetworkConfig.OrgInfo org = networkConfig.getOrganizationInfo("Org1");
        // 获取CA信息
        CAInfo caInfo = org.getCertificateAuthorities().get(0);

        // 使用CA信息实例化CA代理对象
        HFCAClient hfcaClient = HFCAClient.createNewInstance(caInfo);

        assertEquals(hfcaClient.getCAName(), caInfo.getCAName());
        // makes actual REST call.
        HFCAInfo info = hfcaClient.info();
        assertEquals(caInfo.getCAName(), info.getCAName());
        // 获取用户信息
        Collection<UserInfo> registrars = caInfo.getRegistrars();
        assertTrue(!registrars.isEmpty());
        // 获取一个注册用户
        UserInfo user = registrars.iterator().next();
        // 进行Enroll
        user.setEnrollment(hfcaClient.enroll(user.getName(), user.getEnrollSecret()));
        // 模拟用户
        MockUser mockuser = getMockUser(org.getName() + "_mock_" + System.nanoTime(), user.getMspId());

        // 构造注册请求
        RegistrationRequest registrationRequest = new RegistrationRequest(mockuser.getName(), "org1.department1");

        mockuser.setEnrollmentSecret(hfcaClient.register(registrationRequest, user));
        mockuser.setEnrollment(hfcaClient.enroll(mockuser.getName(), mockuser.getEnrollmentSecret()));
        // 模拟用户存入Map中
        orgRegisteredUserMap.put(org.getName(), mockuser);

        // 获取组织Org2
        org = networkConfig.getOrganizationInfo("Org2");
        // 获取CA信息
        caInfo = org.getCertificateAuthorities().get(0);

        hfcaClient = HFCAClient.createNewInstance(caInfo);
        assertEquals(hfcaClient.getCAName(), caInfo.getCAName());
        info = hfcaClient.info(); //makes actual REST call.
        assertEquals(info.getCAName(), "");

        registrars = caInfo.getRegistrars();
        assertTrue(!registrars.isEmpty());
        user = registrars.iterator().next();
        user.setEnrollment(hfcaClient.enroll(user.getName(), user.getEnrollSecret()));
        mockuser = getMockUser(org.getName() + "_mock_" + System.nanoTime(), user.getMspId());
        registrationRequest = new RegistrationRequest(mockuser.getName(), "org1.department1");
        mockuser.setEnrollmentSecret(hfcaClient.register(registrationRequest, user));
        mockuser.setEnrollment(hfcaClient.enroll(mockuser.getName(), mockuser.getEnrollmentSecret()));
        orgRegisteredUserMap.put(org.getName(), mockuser);

        // 看看是否需要安装链码
        deployChaincodeIfRequired();
    }

    /**
     * 看看是否需要安装链码
     * Determines whether or not the chaincode has been deployed and deploys it if necessary
     */
    private static void deployChaincodeIfRequired() throws Exception {

        // 获取代理
        HFClient fabricClient = getTheClient();

        // 构造通道
        Channel channel = constructChannel(fabricClient, FOO_CHANNEL_NAME);

        // 获取Channel里面的任意一个Peer结点
        Peer peer = channel.getPeers().iterator().next();
        if (!checkInstantiatedChaincode(channel, peer, CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION)) {
            // 目标链码没有实例化就进行部署
            deployChaincode(fabricClient, channel, CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION);
        }
    }

    // Returns a new client instance
    private static HFClient getTheClient() throws Exception {

        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        User peerAdmin = getAdminUser(TEST_ORG);
        client.setUserContext(peerAdmin);

        return client;
    }

    private static User getAdminUser(String orgName) throws Exception {

        return networkConfig.getPeerAdmin(orgName);
    }

    @Test
    public void testUpdate1() throws Exception {

        // Setup client and channel instances
        HFClient client = getTheClient();
        Channel channel = constructChannel(client, FOO_CHANNEL_NAME);

        final ChaincodeID chaincodeID = ChaincodeID.newBuilder().setName(CHAIN_CODE_NAME)
                .setVersion(CHAIN_CODE_VERSION)
                .setPath(CHAIN_CODE_PATH).build();

        final String channelName = channel.getName();

        print("Running testUpdate1 - Channel %s", channelName);

        int moveAmount = 5;
        String originalVal = queryChaincodeForCurrentValue(client, channel, chaincodeID);
        String newVal = "" + (Integer.parseInt(originalVal) + moveAmount);

        print("Original value = %s", originalVal);

        //user registered user
        client.setUserContext(orgRegisteredUserMap.get("Org1")); // only using org1

        // Move some assets
        moveAmount(client, channel, chaincodeID, "a", "b", "" + moveAmount, null).thenApply(transactionEvent -> {
            // Check that they were moved
            queryChaincodeForExpectedValue(client, channel, newVal, chaincodeID);
            return null;

        }).thenApply(transactionEvent -> {
            // Move them back
            try {
                return moveAmount(client, channel, chaincodeID, "b", "a", "" + moveAmount, null).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        }).thenApply(transactionEvent -> {
            // Check that they were moved back
            queryChaincodeForExpectedValue(client, channel, originalVal, chaincodeID);
            return null;

        }).exceptionally(e -> {
            if (e instanceof CompletionException && e.getCause() != null) {
                e = e.getCause();
            }
            if (e instanceof TransactionEventException) {
                BlockEvent.TransactionEvent te = ((TransactionEventException) e).getTransactionEvent();
                if (te != null) {

                    e.printStackTrace(System.err);
                    fail(format("Transaction with txid %s failed. %s", te.getTransactionID(), e.getMessage()));
                }
            }

            e.printStackTrace(System.err);
            fail(format("Test failed with %s exception %s", e.getClass().getName(), e.getMessage()));

            return null;

        }).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);

        channel.shutdown(true); // Force channel to shutdown clean up resources.

        print("testUpdate1 - done");
        print("That's all folks!");
    }

    private static void queryChaincodeForExpectedValue(HFClient client, Channel channel, final String expect, ChaincodeID chaincodeID) {

        print("Now query chaincode on channel %s for the value of b expecting to see: %s", channel.getName(), expect);

        String value = queryChaincodeForCurrentValue(client, channel, chaincodeID);
        assertEquals(expect, value);
    }

    // Returns the current value of b's assets
    private static String queryChaincodeForCurrentValue(HFClient client, Channel channel, ChaincodeID chaincodeID) {

        print("Now query chaincode on channel %s for the current value of b", channel.getName());

        QueryByChaincodeRequest queryByChaincodeRequest = client.newQueryProposalRequest();
        queryByChaincodeRequest.setArgs("b");
        queryByChaincodeRequest.setFcn("query");
        queryByChaincodeRequest.setChaincodeID(chaincodeID);

        Collection<ProposalResponse> queryProposals;

        try {
            queryProposals = channel.queryByChaincode(queryByChaincodeRequest);
        } catch (Exception e) {
            throw new CompletionException(e);
        }

        String expect = null;
        for (ProposalResponse proposalResponse : queryProposals) {
            if (!proposalResponse.isVerified() || proposalResponse.getStatus() != Status.SUCCESS) {
                fail("Failed query proposal from peer " + proposalResponse.getPeer().getName() + " status: " + proposalResponse.getStatus() +
                        ". Messages: " + proposalResponse.getMessage()
                        + ". Was verified : " + proposalResponse.isVerified());
            } else {
                String payload = proposalResponse.getProposalResponse().getResponse().getPayload().toStringUtf8();
                print("Query payload of b from peer %s returned %s", proposalResponse.getPeer().getName(), payload);
                if (expect != null) {
                    assertEquals(expect, payload);
                } else {
                    expect = payload;
                }
            }
        }
        return expect;
    }

    private static CompletableFuture<BlockEvent.TransactionEvent> moveAmount(HFClient client, Channel channel, ChaincodeID chaincodeID, String from, String to, String moveAmount, User user) throws Exception {

        Collection<ProposalResponse> successful = new LinkedList<>();
        Collection<ProposalResponse> failed = new LinkedList<>();

        ///////////////
        /// Send transaction proposal to all peers
        TransactionProposalRequest transactionProposalRequest = client.newTransactionProposalRequest();
        transactionProposalRequest.setChaincodeID(chaincodeID);
        transactionProposalRequest.setFcn("move");
        transactionProposalRequest.setArgs(from, to, moveAmount);
        transactionProposalRequest.setProposalWaitTime(testConfig.getProposalWaitTime());
        if (user != null) { // specific user use that
            transactionProposalRequest.setUserContext(user);
        }
        print("sending transaction proposal to all peers with arguments: move(%s,%s,%s)", from, to, moveAmount);

        Collection<ProposalResponse> invokePropResp = channel.sendTransactionProposal(transactionProposalRequest);
        for (ProposalResponse response : invokePropResp) {
            if (response.getStatus() == Status.SUCCESS) {
                print("Successful transaction proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                successful.add(response);
            } else {
                failed.add(response);
            }
        }

        // Check that all the proposals are consistent with each other. We should have only one set
        // where all the proposals above are consistent.
        Collection<Set<ProposalResponse>> proposalConsistencySets = SDKUtils.getProposalConsistencySets(invokePropResp);
        if (proposalConsistencySets.size() != 1) {
            fail(format("Expected only one set of consistent move proposal responses but got %d", proposalConsistencySets.size()));
        }

        print("Received %d transaction proposal responses. Successful+verified: %d . Failed: %d",
                invokePropResp.size(), successful.size(), failed.size());
        if (failed.size() > 0) {
            ProposalResponse firstTransactionProposalResponse = failed.iterator().next();

            throw new ProposalException(format("Not enough endorsers for invoke(move %s,%s,%s):%d endorser error:%s. Was verified:%b",
                    from, to, moveAmount, firstTransactionProposalResponse.getStatus().getStatus(), firstTransactionProposalResponse.getMessage(), firstTransactionProposalResponse.isVerified()));
        }
        print("Successfully received transaction proposal responses.");

        ////////////////////////////
        // Send transaction to orderer
        print("Sending chaincode transaction(move %s,%s,%s) to orderer.", from, to, moveAmount);
        if (user != null) {
            return channel.sendTransaction(successful, user);
        }

        return channel.sendTransaction(successful);
    }

    /**
     * 部署链码
     *
     * @param client 代理对象
     * @param channel 通道
     * @param ccName 名称
     * @param ccPath 路径
     * @param ccVersion 版本
     */
    private static ChaincodeID deployChaincode(HFClient client, Channel channel, String ccName, String ccPath, String ccVersion) throws Exception {

        print("Start to deploy chaincode.");
        ChaincodeID chaincodeID = null;

        try {
            // Channel名称
            final String channelName = channel.getName();
            print("Deploy Chaincode, channelName = " + channelName);
            // 获取Order结点
            Collection<Orderer> orderers = channel.getOrderers();

            Collection<ProposalResponse> responseList;
            Collection<ProposalResponse> successResponseList = new LinkedList<>();
            Collection<ProposalResponse> failedResponseList = new LinkedList<>();

            // 构造链码ID
            chaincodeID = ChaincodeID.newBuilder().setName(ccName)
                    .setVersion(ccVersion)
                    .setPath(ccPath).build();

            print("Creating chaincode install proposal.");
            // 构造链码安装提案
            InstallProposalRequest installProposalRequest = client.newInstallProposalRequest();
            installProposalRequest.setChaincodeID(chaincodeID);
            // 设置链码路径
            installProposalRequest.setChaincodeSourceLocation(new File(TEST_FIXTURES_PATH + "/sdkintegration/gocc/sample1"));
            installProposalRequest.setChaincodeVersion(ccVersion);

            print("Sending install proposal");

            int numInstallProposal = 0;
            // 获取全部Peer结点
            Collection<Peer> peersFromOrg = channel.getPeers();
            // 需要安装的个数
            numInstallProposal = numInstallProposal + peersFromOrg.size();
            // 提交安装提案获取响应
            responseList = client.sendInstallProposal(installProposalRequest, peersFromOrg);

            for (ProposalResponse response : responseList) {
                if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    print("Successful install proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                    successResponseList.add(response);
                } else {
                    failedResponseList.add(response);
                }
            }
            print("Received %d install proposal responses. Successful+verified: %d . Failed: %d", numInstallProposal, successResponseList.size(), failedResponseList.size());
            // 说明有失败
            if (failedResponseList.size() > 0) {
                ProposalResponse first = failedResponseList.iterator().next();
                fail("Not enough endorsers for install :" + successResponseList.size() + ".  " + first.getMessage());
            }

            //////////////////////////////////////////////////////////////////////////////////
            //// 实例化链码
            //////////////////////////////////////////////////////////////////////////////////
            // From the docs:
            // The instantiate transaction invokes the lifecycle System Chaincode (LSCC) to create and initialize a chaincode on a channel
            // After being successfully instantiated, the chaincode enters the active state on the channel and is ready to process any transaction proposals of type ENDORSER_TRANSACTION
            InstantiateProposalRequest instantiateProposalRequest = client.newInstantiationProposalRequest();
            instantiateProposalRequest.setProposalWaitTime(testConfig.getProposalWaitTime());
            instantiateProposalRequest.setChaincodeID(chaincodeID);
            instantiateProposalRequest.setFcn("init");
            instantiateProposalRequest.setArgs("a", "500", "b", "999");

            Map<String, byte[]> tm = new HashMap<>();
            tm.put("HyperLedgerFabric", "InstantiateProposalRequest:JavaSDK".getBytes(UTF_8));
            tm.put("method", "InstantiateProposalRequest".getBytes(UTF_8));
            instantiateProposalRequest.setTransientMap(tm);

            /*
              policy OR(Org1MSP.member, Org2MSP.member) meaning 1 signature from someone in either Org1 or Org2
              See README.md Chaincode endorsement policies section for more details.
            */
            // 指定背书策略
            ChaincodeEndorsementPolicy chaincodeEndorsementPolicy = new ChaincodeEndorsementPolicy();
            chaincodeEndorsementPolicy.fromYamlFile(new File(TEST_FIXTURES_PATH + "/sdkintegration/chaincodeendorsementpolicy.yaml"));
            instantiateProposalRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);
            print("Sending instantiateProposalRequest to all peers...");
            successResponseList.clear();
            failedResponseList.clear();

            // 发送实例化提案
            responseList = channel.sendInstantiationProposal(instantiateProposalRequest);

            for (ProposalResponse response : responseList) {
                if (response.isVerified() && response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    successResponseList.add(response);
                    print("Succesful instantiate proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                } else {
                    failedResponseList.add(response);
                }
            }
            print("Received %d instantiate proposal responses. Successful+verified: %d . Failed: %d", responseList.size(), successResponseList.size(), failedResponseList.size());
            // 实例化失败
            if (failedResponseList.size() > 0) {
                ProposalResponse first = failedResponseList.iterator().next();
                fail("Not enough endorsers for instantiate :" + successResponseList.size() + "endorser failed with " + first.getMessage() + ". Was verified:" + first.isVerified());
            }

            ///////////////////////////////////////////////////////////////////////////////////////
            /// 发送实例化的交易到Order
            ///////////////////////////////////////////////////////////////////////////////////////
            print("Sending instantiateTransaction to orderer...");
            CompletableFuture<TransactionEvent> future = channel.sendTransaction(successResponseList, orderers);

            print("calling get...");
            TransactionEvent event = future.get(30, TimeUnit.SECONDS);
            print("get done...");

            assertTrue(event.isValid()); // must be valid to be here.
            print("Finished instantiate transaction with transaction id %s", event.getTransactionID());

        } catch (Exception e) {
            e.printStackTrace();
            print("Caught an exception running channel %s", channel.getName());
            fail("Test failed with error : " + e.getMessage());
        }

        return chaincodeID;
    }

    /**
     * 构造通道
     *
     * @param client 代理对象
     * @param channelName 通道名
     */
    private static Channel constructChannel(HFClient client, String channelName) throws Exception {

        // Channel newChannel = client.getChannel(channelName);
        // 从配置里面加载Channel
        Channel newChannel = client.loadChannelFromConfig(channelName, networkConfig);
        if (newChannel == null) {
            throw new RuntimeException("Channel " + channelName + " is not defined in the config file!");
        }
        // 进行通道初始化
        return newChannel.initialize();
    }

    /**
     * 判断某个链码是否已经在通道上实例化
     * Determines if the specified chaincode has been instantiated on the channel
     *
     * @param channel 通道
     * @param peer Peer
     * @param chainCodeName 链码名称
     * @param chaincodePath 链码路径
     * @param chaincodeVersion 链码版本
     */
    private static boolean checkInstantiatedChaincode(Channel channel, Peer peer, String chainCodeName, String chaincodePath, String chaincodeVersion) throws InvalidArgumentException, ProposalException {
        print("Checking instantiated chaincode: %s, at version: %s, on peer: %s", chainCodeName, chaincodeVersion, peer.getName());
        // 查询已经实例化的链码
        List<ChaincodeInfo> chaincodeInfoList = channel.queryInstantiatedChaincodes(peer);
        boolean found = false;

        // 逐一对比看看是否找到
        for (ChaincodeInfo chaincodeInfo : chaincodeInfoList) {
            found = chainCodeName.equals(chaincodeInfo.getName())
                    && chaincodePath.equals(chaincodeInfo.getPath())
                    && chaincodeVersion.equals(chaincodeInfo.getVersion());
            if (found) {
                break;
            }
        }
        return found;
    }

    private static void print(String format, Object... args) {
        System.err.flush();
        System.out.flush();
        System.out.println(format(format, args));
        System.err.flush();
        System.out.flush();
    }

}
