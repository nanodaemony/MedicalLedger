/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

package com.nano.core;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.openssl.PEMWriter;
import org.hyperledger.fabric.protos.ledger.rwset.kvrwset.KvRwset;
import org.hyperledger.fabric.sdk.BlockEvent;
import org.hyperledger.fabric.sdk.BlockInfo;
import org.hyperledger.fabric.sdk.BlockchainInfo;
import org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy;
import org.hyperledger.fabric.sdk.ChaincodeEvent;
import org.hyperledger.fabric.sdk.ChaincodeID;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.ChannelConfiguration;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.EventHub;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.InstallProposalRequest;
import org.hyperledger.fabric.sdk.InstantiateProposalRequest;
import org.hyperledger.fabric.sdk.Orderer;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.Peer.PeerRole;
import org.hyperledger.fabric.sdk.ProposalResponse;
import org.hyperledger.fabric.sdk.QueryByChaincodeRequest;
import org.hyperledger.fabric.sdk.SDKUtils;
import org.hyperledger.fabric.sdk.TransactionInfo;
import org.hyperledger.fabric.sdk.TransactionProposalRequest;
import org.hyperledger.fabric.sdk.TransactionRequest.Type;
import org.hyperledger.fabric.sdk.TxReadWriteSetInfo;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionEventException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.HFCAInfo;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static com.nano.core.TestUtils.resetConfig;
import static com.nano.core.TestUtils.testRemovingAddingPeersOrderers;
import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.fabric.sdk.BlockInfo.EnvelopeType.TRANSACTION_ENVELOPE;
import static org.hyperledger.fabric.sdk.Channel.NOfEvents.createNofEvents;
import static org.hyperledger.fabric.sdk.Channel.PeerOptions.createPeerOptions;
import static org.hyperledger.fabric.sdk.Channel.TransactionOptions.createTransactionOptions;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * The full process of the procedure.
 *
 * @author nano
 */
@Component
public class FabricCoreTestJavaChainCode {

    private static Logger logger = LoggerFactory.getLogger("FabricCore");

    /**
     * 测试配置
     */
    private static final TestConfig testConfig = TestConfig.getConfig();

    /**
     * 测试Admin名称
     */
    static final String TEST_ADMIN_NAME = "admin";

    /**
     * 测试用的固定路径
     */
    private static final String TEST_FIXTURES_PATH = "src/test/fixture";

    /**
     * 随机数生成器
     */
    private static final Random random = new Random();

    /**
     * 两个通道名称
     */
    private static final String FOO_CHANNEL_NAME = "foo";
    private static final String BAR_CHANNEL_NAME = "bar";

    /**
     * 部署延迟时间
     */
    private static final int DEPLOYWAITTIME = testConfig.getDeployWaitTime();

    private static final byte[] EXPECTED_EVENT_DATA = "!".getBytes(UTF_8);
    private static final String EXPECTED_EVENT_NAME = "event";
    private static final Map<String, String> TX_EXPECTED;


    /**
     * 链码相关配置
     */
    private static final String CHAIN_CODE_FILEPATH = "sdkintegration/javacc/sample1";
    private static final String CHAIN_CODE_NAME = "example_cc_java";
    private static final String CHAIN_CODE_PATH = null;
    private static final String CHAIN_CODE_VERSION = "1";
    private static final Type CHAIN_CODE_LANG = Type.JAVA;

    // 静态初始化
    static {
        TX_EXPECTED = new HashMap<>();
        TX_EXPECTED.put("readset1", "Missing readset for channel bar block 1");
        TX_EXPECTED.put("writeset1", "Missing writeset for channel bar block 1");
    }

    /***
     * 配置帮助器
     */
    private final TestConfigHelper configHelper = new TestConfigHelper();
    /**
     * 测试的TransactionId
     */
    String testTxID = null;  // save the CC invoke TxID and use in queries

    /**
     * 文件本地键值对存储
     */
    LocalStore localStore = null;

    /**
     * 测试组织集合
     */
    private Set<Organization> organizationSet;

    /**
     * 测试用户
     */
    static String normalUser1 = "user" + System.currentTimeMillis();

    /**
     * Fabric代理对象
     */
    public HFClient fabricClient;

    /**
     * Foo通道对象
     */
    public Channel fooChannel;

    /**
     * 链码ID对象
     */
    public ChaincodeID chaincodeId;

    /**
     * 客户端TLS属性
     */
    Map<String, Properties> clientTLSProperties = new HashMap<>();


    /**
     * 两个组织
     */
    private Organization peerOrganization1;
    private Organization peerOrganization2;


    private static int delta = 0;

    /**
     * 本地文件存储
     */
    // File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");
    File sampleStoreFile = new File("G:\\HFCSampletest.properties");

    // 链码事件列表
    // Test list to capture chaincode events.
    List<ChaincodeEventCapture> chaincodeEventList = new LinkedList<>();
    // 初始化提案的响应集合
    Collection<ProposalResponse> responseList;
    Collection<ProposalResponse> successResponseList = new LinkedList<>();
    Collection<ProposalResponse> failedResponseList = new LinkedList<>();


    String chaincodeEventListenerHandler;

    /**
     * 初始化方法
     */
    public void init() {
        try {
            // 初始化配置
            initConfig();
            // 持久化不是SDK的一部分,生产环境别用SampleFile这个类,需要自己做实现!!!!!!
            // 每次都删除掉之前的存储文件
            if (sampleStoreFile.exists()) {
                sampleStoreFile.delete();
            }
            // 重新创建文件
            localStore = new LocalStore(sampleStoreFile);
            // This enrolls users with fabric ca and setups sample store to get users later.
            // enrollAndRegisterUsers(sampleStore);
            // 分别为两个组织注册用户信息(AdminUser, NormalUser, AdminPeer)
            registerAndEnrollForOrg(localStore, peerOrganization1);
            registerAndEnrollForOrg(localStore, peerOrganization2);
            // Runs Fabric tests with constructing channels, joining peers, exercising chaincode

            // 创建Fabric客户端
            fabricClient = HFClient.createNewInstance();
            // 设置加密套件
            fabricClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

            // 构造FooChannel
            fooChannel = buildChannel("foo");

            // 将创建好的通道对象存入本地
            localStore.saveChannel(fooChannel);

            // 下面的代码只是测试一下Peer结点与Orderer结点能否被添加与移除
            // The following is just a test to see if peers and orderers can be added and removed.
            // not pertinent to the code flow.
            testRemovingAddingPeersOrderers(fabricClient, fooChannel);

            // Register a chaincode event listener that will trigger for any chaincode id and only for EXPECTED_EVENT_NAME event.
            // 注册一个链码事件监听器
            String chaincodeEventListenerHandler = fooChannel.registerChaincodeEventListener(
                    Pattern.compile(".*"),
                    // 期待的事件: EXPECTED_EVENT_NAME = "event"
                    Pattern.compile(Pattern.quote(EXPECTED_EVENT_NAME)),
                    (handler, blockEvent, chaincodeEvent) -> {
                        // 将事件加入列表
                        chaincodeEventList.add(new ChaincodeEventCapture(handler, blockEvent, chaincodeEvent));
                        String es = blockEvent.getPeer() != null ? blockEvent.getPeer().getName() : blockEvent.getEventHub().getName();
                        print("RECEIVED Chaincode event with handle: %s, chaincode Id: %s, chaincode event name: %s, "
                                        + "transaction id: %s, event payload: \"%s\", from eventhub: %s",
                                handler, chaincodeEvent.getChaincodeId(),
                                chaincodeEvent.getEventName(),
                                chaincodeEvent.getTxId(),
                                new String(chaincodeEvent.getPayload()), es);
                    });

            // 初始化链码ID对象
            initChainCodeId();

            // 安装链码
            installChaincode();

            // 实例化链码
            instantiateChaincode();

            // 转账操作哦
            transferMoney();

            // 进行查询
            queryUser();

            // 查询账本信息
            queryLedgerInfo();

            logger.info("You finished the init method.");

        } catch (Exception e) {
            print("Caught an exception running channel %s", fooChannel.getName());
            e.printStackTrace();
            fail("Test failed with error : " + e.getMessage());
        }
    }


    /**
     * 查询区块信息
     */
    private void queryLedgerInfo() throws Exception{
        // 获取通道名称
        final String channelName = fooChannel.getName();
        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        // 通道信息查询
        //////////////////////////////////////////////////////////////////////////////////////////////////////////

        // We can only send channel queries to peers that are in the same org as the SDK user context
        // Get the peers from the current org being used and pick one randomly to send the queries to.
        // Set<Peer> peerSet = sampleOrg.getPeers();
        // Peer queryPeer = peerSet.iterator().next();
        // out("Using peer %s for channel queries", queryPeer.getName());

        // 查询区块链信息
        BlockchainInfo channelInfo = fooChannel.queryBlockchainInfo();
        // 通道(账本)名称
        print("Channel info for : " + channelName);
        // 区块链高度
        print("Channel height: " + channelInfo.getHeight());
        // 账本当前区块Hash
        String chainCurrentHash = Hex.encodeHexString(channelInfo.getCurrentBlockHash());
        // 账本前一个块的Hash
        String chainPreviousHash = Hex.encodeHexString(channelInfo.getPreviousBlockHash());
        print("Chain current block hash: " + chainCurrentHash);
        print("Chain previous block hash: " + chainPreviousHash);

        // 通过区块编号查询
        // Query by block number. Should return latest block, i.e. block number 2
        BlockInfo returnedBlock = fooChannel.queryBlockByNumber(channelInfo.getHeight() - 1);
        String previousHash = Hex.encodeHexString(returnedBlock.getPreviousHash());
        print("queryBlockByNumber returned correct block with blockNumber " + returnedBlock.getBlockNumber()
                + " \n previous_hash " + previousHash);
        assertEquals(channelInfo.getHeight() - 1, returnedBlock.getBlockNumber());
        assertEquals(chainPreviousHash, previousHash);

        // Query by block hash. Using latest block's previous hash so should return block number 1
        // 通过区块Hash查询
        byte[] hashQuery = returnedBlock.getPreviousHash();
        returnedBlock = fooChannel.queryBlockByHash(hashQuery);
        print("queryBlockByHash returned block with blockNumber " + returnedBlock.getBlockNumber());
        assertEquals(channelInfo.getHeight() - 2, returnedBlock.getBlockNumber());

        // Query block by TxID. Since it's the last TxID, should be block 2
        // 通过交易Id查询区块
        returnedBlock = fooChannel.queryBlockByTransactionID(testTxID);
        print("queryBlockByTxID returned block with blockNumber " + returnedBlock.getBlockNumber());
        assertEquals(channelInfo.getHeight() - 1, returnedBlock.getBlockNumber());

        // query transaction by ID
        // 通过交易ID查询交易
        TransactionInfo txInfo = fooChannel.queryTransactionByID(testTxID);
        print("QueryTransactionByID returned TransactionInfo: txID " + txInfo.getTransactionID()
                + "\n validation code " + txInfo.getValidationCode().getNumber());

        if (chaincodeEventListenerHandler != null) {
            // 取消注册链码事件监听器
            fooChannel.unregisterChaincodeEventListener(chaincodeEventListenerHandler);
            // Should be two. One event in chaincode and two notification for each of the two event hubs
            final int numberEventsExpected = fooChannel.getEventHubs().size() + fooChannel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)).size();
            // just make sure we get the notifications.
            for (int i = 15; i > 0; --i) {
                if (chaincodeEventList.size() == numberEventsExpected) {
                    break;
                } else {
                    // wait for the events.
                    Thread.sleep(90);
                }
            }
            assertEquals(numberEventsExpected, chaincodeEventList.size());
            // 读取之前的链码事件
            for (ChaincodeEventCapture chaincodeEventCapture : chaincodeEventList) {
                assertEquals(chaincodeEventListenerHandler, chaincodeEventCapture.handle);
                assertEquals(testTxID, chaincodeEventCapture.chaincodeEvent.getTxId());
                assertEquals(EXPECTED_EVENT_NAME, chaincodeEventCapture.chaincodeEvent.getEventName());
                assertTrue(Arrays.equals(EXPECTED_EVENT_DATA, chaincodeEventCapture.chaincodeEvent.getPayload()));
                assertEquals(CHAIN_CODE_NAME, chaincodeEventCapture.chaincodeEvent.getChaincodeId());

                // 获取区块事件
                BlockEvent blockEvent = chaincodeEventCapture.blockEvent;
                assertEquals(channelName, blockEvent.getChannelId());
                // assertTrue(channel.getEventHubs().contains(blockEvent.getEventHub()));
            }
        } else {
            //assertTrue(chaincodeEventList.isEmpty());
        }

    }




    /**
     * 进行转账
     */
    public void transferMoney() throws Exception{
        // 清除响应结果列表
        successResponseList.clear();
        failedResponseList.clear();

        // 设置成普通的用户!!!
        fabricClient.setUserContext(peerOrganization1.getUser(normalUser1));
        // 构造交易提案请求
        TransactionProposalRequest transactionProposalRequest = fabricClient.newTransactionProposalRequest();
        // 设置需要执行的链码ID
        transactionProposalRequest.setChaincodeID(chaincodeId);
        // 链码语言
        transactionProposalRequest.setChaincodeLanguage(CHAIN_CODE_LANG);
        //transactionProposalRequest.setFcn("invoke");
        transactionProposalRequest.setFcn("move");
        transactionProposalRequest.setProposalWaitTime(testConfig.getProposalWaitTime());
        // 设置参数
        transactionProposalRequest.setArgs("a", "b", "100");
        // 母鸡在干啥
        Map<String, byte[]> tm2 = new HashMap<>();
        // Just some extra junk in transient map
        tm2.put("HyperLedgerFabric", "TransactionProposalRequest:JavaSDK".getBytes(UTF_8));
        // ditto
        tm2.put("method", "TransactionProposalRequest".getBytes(UTF_8));
        // This should be returned in the payload see chaincode why.
        tm2.put("result", ":)".getBytes(UTF_8));

        // 如果是GO语言且版本大于1.2
        if (Type.GO_LANG.equals(CHAIN_CODE_LANG) && testConfig.isFabricVersionAtOrAfter("1.2")) {
            // the chaincode will return this as status see chaincode why.
            expectedMoveRCMap.put(FOO_CHANNEL_NAME, random.nextInt(300) + 100L);
            // This should be returned see chaincode why.
            tm2.put("rc", (expectedMoveRCMap.get(FOO_CHANNEL_NAME) + "").getBytes(UTF_8));
            // 400 and above results in the peer not endorsing!
        } else {
            // not really supported for Java or Node.
            // 对Java或Go不太支持
            expectedMoveRCMap.put(FOO_CHANNEL_NAME, 200L);
        }
        // This should trigger an event see chaincode why.
        tm2.put(EXPECTED_EVENT_NAME, EXPECTED_EVENT_DATA);
        transactionProposalRequest.setTransientMap(tm2);

        logger.info("Sending transactionProposal to all peers with arguments: move(a,b,100)");

        // Collection<ProposalResponse> transactionPropResp = channel.sendTransactionProposalToEndorsers(transactionProposalRequest);
        // 往所有的Peer结点发送交易并得到响应
        Collection<ProposalResponse> transactionResponse = fooChannel.sendTransactionProposal(transactionProposalRequest, fooChannel.getPeers());
        // 康康结果是否OK
        for (ProposalResponse response : transactionResponse) {
            if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                print("Successful transaction proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                successResponseList.add(response);
            } else {
                failedResponseList.add(response);
            }
        }
        print("Received %d transaction proposal responses. Successful + verified: %d . Failed: %d",
                transactionResponse.size(), successResponseList.size(), failedResponseList.size());
        if (failedResponseList.size() > 0) {
            ProposalResponse firstTransactionProposalResponse = failedResponseList.iterator().next();
            fail("Not enough endorsers for invoke(move a,b,100):" + failedResponseList.size() + " endorser error: " +
                    firstTransactionProposalResponse.getMessage() + ". Was verified: " + firstTransactionProposalResponse.isVerified());
        }

        // 检查是否全部的提案都是一致的,这在发送给Orderer时是自动执行的.这里写出来只是说明应用程序可以自己选择使用
        // Check that all the proposals are consistent with each other. We should have only one set
        // where all the proposals above are consistent.
        // Note the when sending to Orderer this is done automatically.
        // Shown here as an example that applications can invoke and select.
        // See org.hyperledger.fabric.sdk.proposal.consistency_validation config property.
        // 获取响应集
        Collection<Set<ProposalResponse>> proposalConsistencySets = SDKUtils.getProposalConsistencySets(transactionResponse);
        if (proposalConsistencySets.size() != 1) {
            fail(format("Expected only one set of consistent proposal responses but got %d", proposalConsistencySets.size()));
        }
        // 到这里验证成功
        logger.info("Successfully received transaction proposal responses.");

        // 可以退出了,因为交易执行完毕
        //  System.exit(10);

        ///////////////////////////////////////////////////////////////////////////////////////////////////////
        /// 下面分析交易的返回结果
        ///////////////////////////////////////////////////////////////////////////////////////////////////////

        ProposalResponse successResponse = successResponseList.iterator().next();
        // This is the data returned by the chaincode.
        // 这里分析一下从链码返回的数据
        byte[] dataBytes = successResponse.getChaincodeActionResponsePayload();
        // 解析成字符串形式
        String resultAsString = null;
        if (dataBytes != null) {
            resultAsString = new String(dataBytes, UTF_8);
        }
        // 判断是否是下面的图像
        assertEquals(":)", resultAsString);
        // Chaincode's status.
        assertEquals(expectedMoveRCMap.get(FOO_CHANNEL_NAME).longValue(), successResponse.getChaincodeActionResponseStatus());

        // 获取读写集的信息
        TxReadWriteSetInfo readWriteSetInfo = successResponse.getChaincodeActionResponseReadWriteSetInfo();
        // See block walker below how to transverse this
        assertNotNull(readWriteSetInfo);
        assertTrue(readWriteSetInfo.getNsRwsetCount() > 0);
        // 获取响应的ChaincodeId
        ChaincodeID cid = successResponse.getChaincodeID();
        assertNotNull(cid);

        // 看看链码Id的路径是否是本地链码的路径
        final String path = cid.getPath();
        if (CHAIN_CODE_PATH == null) {
            assertTrue(path == null || "".equals(path));
        } else {
            assertEquals(CHAIN_CODE_PATH, path);
        }

        assertEquals(CHAIN_CODE_NAME, cid.getName());
        assertEquals(CHAIN_CODE_VERSION, cid.getVersion());

        ////////////////////////////////////////////////////////////////////////////////////////////////////////
        // 将成功的交易信息发送到Orderer结点
        ////////////////////////////////////////////////////////////////////////////////////////////////////////
        logger.info("Sending chaincode transaction(move a,b,100) to orderer.");

        // 将交易发送出去
        BlockEvent.TransactionEvent transactionEvent = fooChannel.sendTransaction(successResponseList).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);

        // 记录一下ID,方便后面的查询
        testTxID = transactionEvent.getTransactionID();
        logger.info("Finished transaction with transaction id " + transactionEvent.getTransactionID());
    }


    /**
     * 安装链码
     */
    private void installChaincode() throws Exception{
        // 判断当前链码是否已经被安装了
        for (String chainCodeName : fooChannel.getDiscoveredChaincodeNames()) {
            // 如果已经安装了链码
            if (CHAIN_CODE_NAME.equals(chainCodeName)) {
                logger.info("The chaincode " + CHAIN_CODE_NAME +" is already installed.");
                return;
            }
        }
        // 到这里说明需要安装链码,下面构造链码安装的提案请求
        // 设置当前客户端的操作人为Admin Peer结点
        fabricClient.setUserContext(peerOrganization1.getAdminPeer());

        logger.info("Creating install chaincode proposal.");

        // 构造链码安装请求
        InstallProposalRequest installProposalRequest = fabricClient.newInstallProposalRequest();
        // 传入上面生成的链码ID
        installProposalRequest.setChaincodeID(chaincodeId);
        // 默认从这里安装
        if (true) {
            // 如果是foo通道则从目录安装
            // For GO language and serving just a single user, chaincodeSource is mostly likely the users GOPATH
            // 对于Go语言的链码安装 TEST_FIXTURES_PATH即为文件固定目录
            installProposalRequest.setChaincodeSourceLocation(Paths.get(TEST_FIXTURES_PATH, CHAIN_CODE_FILEPATH).toFile());
            // 如果版本是后于1.1, 这里可以创建索引!!!!
            if (testConfig.isFabricVersionAtOrAfter("1.1")) {
                // 这将在链码中的字段"a"上设置索引,索引的配置参考meta-infs/end2endit/META-INF下面的IndexA.json文件
                // This sets an index on the variable a in the chaincode
                // see http://hyperledger-fabric.readthedocs.io/en/master/couchdb_as_state_database.html#using-couchdb-from-chaincode
                // The file IndexA.json as part of the META-INF will be packaged with the source to create the index.
                // 这里设置索引配置文件的路径
                installProposalRequest.setChaincodeMetaInfLocation(new File("src/test/fixture/meta-infs/end2endit"));
            }
        } else {
            // 如果是bar通道则从输入流安装
            // 对于inputStream，如果需要指示，应用程序需要确保流中提供了META-INF,SDK不会改变流中的任何东西
            // For inputStream if indicies are desired the application needs to make sure the META-INF is provided in the stream. The SDK does not change anything in the stream.
            // 如果是GO语言链码
            if (CHAIN_CODE_LANG.equals(Type.GO_LANG)) {
                // 设置链码的输入流
                installProposalRequest.setChaincodeInputStream(Util.generateTarGzInputStream(
                        (Paths.get(TEST_FIXTURES_PATH, CHAIN_CODE_FILEPATH, "src", CHAIN_CODE_PATH).toFile()),
                        Paths.get("src", CHAIN_CODE_PATH).toString()));
                // 其他语言链码
            } else {
                installProposalRequest.setChaincodeInputStream(Util.generateTarGzInputStream(
                        (Paths.get(TEST_FIXTURES_PATH, CHAIN_CODE_FILEPATH).toFile()), "src"));
            }
        }
        // 设置链码版本
        installProposalRequest.setChaincodeVersion(CHAIN_CODE_VERSION);
        // 设置链码语言
        installProposalRequest.setChaincodeLanguage(CHAIN_CODE_LANG);

        logger.info("Sending chaincode install proposal");

        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // 提交链码安装请求并分析结果
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // only a client from the same org as the peer can issue an install request
        int numInstallProposal = 0;
        // Set<String> orgs = orgPeers.keySet();
        // for (SampleOrg org : testSampleOrgs) {
        // 获取通道中的全部Peer结点
        Collection<Peer> peers = fooChannel.getPeers();
        // 需要安装链码的数量
        numInstallProposal = numInstallProposal + peers.size();
        // 发送链码安装请求并得到响应
        responseList = fabricClient.sendInstallProposal(installProposalRequest, peers);
        // 看看响应
        for (ProposalResponse response : responseList) {
            // 安装成功
            if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                print("Successful install proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                successResponseList.add(response);
            } else {
                failedResponseList.add(response);
            }
        }
        // }
        print("Received %d install proposal responses. 成功 + 验证个数: %d . 失败个数: %d", numInstallProposal, successResponseList.size(), failedResponseList.size());
        // 如果有失败的情况
        if (failedResponseList.size() > 0) {
            ProposalResponse first = failedResponseList.iterator().next();
            fail("Not enough endorsers for install :" + successResponseList.size() + ".  " + first.getMessage());
        }
        // 安装链码不需要发送交易到Orderer结点
        // Note: installing chaincode does not require transaction no need to send to Orderers
        // client.setUserContext(sampleOrg.getUser(TEST_ADMIN_NAME));
        // final ChaincodeID chaincodeID = firstInstallProposalResponse.getChaincodeID();
    }


    /**
     * 实例化链码
     */
    private void instantiateChaincode() throws Exception{
        // 构造实例化链码请求
        InstantiateProposalRequest instantiateProposalRequest = fabricClient.newInstantiationProposalRequest();
        // 设置链码实例化属性
        instantiateProposalRequest.setProposalWaitTime(DEPLOYWAITTIME);
        instantiateProposalRequest.setChaincodeID(chaincodeId);
        instantiateProposalRequest.setChaincodeLanguage(CHAIN_CODE_LANG);
        // 指定实例化的init方法
        instantiateProposalRequest.setFcn("init");
        // 设置实例化的参数(这里设置每个用户初始有多少钱)
        instantiateProposalRequest.setArgs("a", "500", "b", "" + (200 + delta));
        // 母鸡在干啥
        Map<String, byte[]> tm = new HashMap<>();
        tm.put("HyperLedgerFabric", "InstantiateProposalRequest:JavaSDK".getBytes(UTF_8));
        tm.put("method", "InstantiateProposalRequest".getBytes(UTF_8));
        instantiateProposalRequest.setTransientMap(tm);

        // 这里指定背书策略！！！！构造链码背书对象
        ChaincodeEndorsementPolicy endorsementPolicy = new ChaincodeEndorsementPolicy();
        // 从YAML文件读取背书策略
        endorsementPolicy.fromYamlFile(new File("src/test/fixture/sdkintegration/chaincodeendorsementpolicy.yaml"));
        instantiateProposalRequest.setChaincodeEndorsementPolicy(endorsementPolicy);

        print("Sending 链码实例化请求 to all peers with arguments: a and b set to 100 and %s respectively", "" + (200 + delta));
        // 清除响应结果记录
        successResponseList.clear();
        failedResponseList.clear();

        // 如果是Foo通道
        // Send responses both ways with specifying peers and by using those on the channel.
        if (true) {
            // 这里往所有的Peer结点发送实例化提案并得到响应
            responseList = fooChannel.sendInstantiationProposal(instantiateProposalRequest, fooChannel.getPeers());
        } else {
            responseList = fooChannel.sendInstantiationProposal(instantiateProposalRequest);
        }

        // 分析实例化提案的响应结果
        for (ProposalResponse response : responseList) {
            if (response.isVerified() && response.getStatus() == ProposalResponse.Status.SUCCESS) {
                successResponseList.add(response);
                print("成功实例化链码, response TxId: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
            } else {
                failedResponseList.add(response);
            }
        }
        print("Received %d instantiate proposal responses. Successful + verified: %d . Failed: %d", responseList.size(), successResponseList.size(), failedResponseList.size());
        // 实例化失败
        if (failedResponseList.size() > 0) {
            for (ProposalResponse fail : failedResponseList) {
                print("Not enough endorsers for instantiate :" + successResponseList.size() + "endorser failed with " + fail.getMessage() + ", on peer" + fail.getPeer());
            }
            ProposalResponse first = failedResponseList.iterator().next();
            // 这里抛出异常
            fail("Not enough endorsers for instantiate :" + successResponseList.size() + "endorser failed with " + first.getMessage() + ". Was verified:" + first.isVerified());
        }


        // 下面将实例化成功的交易发送给Orderer
        print("Sending 实例化交易 to orderer with a and b set to 100 and %s respectively", "" + (200 + delta));

        // Specify what events should complete the interest in this transaction. This is the default
        // for all to complete. It's possible to specify many different combinations like
        // any from a group, all from one group and just one from another or even None(NOfEvents.createNoEvents).
        // See. Channel.NOfEvents
        // 这里设置提交交易时感兴趣的事件
        Channel.NOfEvents nOfEvents = createNofEvents();
        if (!fooChannel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)).isEmpty()) {
            nOfEvents.addPeers(fooChannel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)));
        }
        if (!fooChannel.getEventHubs().isEmpty()) {
            nOfEvents.addEventHubs(fooChannel.getEventHubs());
        }

        CompletableFuture<BlockEvent.TransactionEvent> future = fooChannel.sendTransaction(
                // 包含上面的成功响应结果集
                successResponseList,
                // 交易配置
                createTransactionOptions()
                        // !!!!设置用户环境
                        .userContext(fabricClient.getUserContext())
                        // don't shuffle any orderers the default is true.
                        .shuffleOrders(false)
                        // specify the orderers we want to try this transaction. Fails once all Orderers are tried.
                        .orderers(fooChannel.getOrderers())
                        // The events to signal the completion of the interest in the transaction
                        // 设置感兴趣的事件
                        .nOfEvents(nOfEvents));

        // 从发送交易中获取交易事件
        BlockEvent.TransactionEvent transactionEvent = future.get();
        // 交易事件必须是合法的
        assertTrue(transactionEvent.isValid());
        // 交易事件必须有签名
        assertNotNull(transactionEvent.getSignature()); // Must have a signature.
        // 从交易事件获取区块事件
        BlockEvent blockEvent = transactionEvent.getBlockEvent(); // This is the block event that has this transaction.
        // 保证能够获取区块
        assertNotNull(blockEvent.getBlock()); // Make sure the RAW Fabric block is returned.
        // 到这里完成了链码实例化过程
        print("Finished instantiate transaction with transaction id %s", transactionEvent.getTransactionID());
    }


    /**
     * 查询方法
     */
    public void queryUser() throws Exception{
        //////////////////////////////////////////////////////////////////////////////////////////////
        // 发送查询提案给所有Peer结点
        //////////////////////////////////////////////////////////////////////////////////////////////
        String expect = "" + (300 + delta);
        logger.info("Now query chaincode for the value of b.");
        // 构造查询请求
        QueryByChaincodeRequest queryByChaincodeRequest = fabricClient.newQueryProposalRequest();
        // 设置参数
        queryByChaincodeRequest.setArgs("b");
        // 设置调用方法
        queryByChaincodeRequest.setFcn("query");
        // 设置链码Id
        queryByChaincodeRequest.setChaincodeID(chaincodeId);
        // 不知道在干啥
        Map<String, byte[]> tm2 = new HashMap<>();
        tm2.put("HyperLedgerFabric", "QueryByChaincodeRequest:JavaSDK".getBytes(UTF_8));
        tm2.put("method", "QueryByChaincodeRequest".getBytes(UTF_8));
        queryByChaincodeRequest.setTransientMap(tm2);

        // 发送查询请求并获取响应结果
        Collection<ProposalResponse> queryResponses = fooChannel.queryByChaincode(queryByChaincodeRequest, fooChannel.getPeers());
        // 分析响应结果
        for (ProposalResponse proposalResponse : queryResponses) {
            if (!proposalResponse.isVerified() || proposalResponse.getStatus() != ProposalResponse.Status.SUCCESS) {
                fail("Failed query proposal from peer " + proposalResponse.getPeer().getName() + " status: " + proposalResponse.getStatus() +
                        ". Messages: " + proposalResponse.getMessage() + ". Was verified : " + proposalResponse.isVerified());
            } else {
                // 查询成功,获取返回的数据
                String payload = proposalResponse.getProposalResponse().getResponse().getPayload().toStringUtf8();
                logger.info(proposalResponse.getTransactionID());
                logger.info(proposalResponse.getMessage());
                logger.info("Payload is :" + payload);
            }
        }
    }


    /**
     * 测试之前执行的默认配置
     */
    public void initConfig() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, MalformedURLException, org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException {
        // configHelper.clearConfig();
        // assertEquals(256, Config.getConfig().getSecurityLevel());
        resetConfig();
        configHelper.customizeConfig();

        // 获取组织的Set
        organizationSet = testConfig.getOrganizationSet();

        // 为每个组织设置HFCA
        for (Organization organization : organizationSet) {
            // Try one of each name and no name.
            // ca0 与 null
            String caName = organization.getCAName();
            if (caName != null && !caName.isEmpty()) {
                // 构造CA代理对象
                HFCAClient caClient = HFCAClient.createNewInstance(
                        // CA名称
                        caName,
                        // CA地址
                        organization.getCALocation(),
                        // CA属性
                        organization.getCAProperties());
                organization.setCAClient(caClient);
            } else {
                organization.setCAClient(HFCAClient.createNewInstance(organization.getCALocation(),
                        organization.getCAProperties()));
            }
        }
        // 将组织对象映射到本类中
        peerOrganization1 = testConfig.getOrganizationMap().get("peerOrg1");
        peerOrganization2 = testConfig.getOrganizationMap().get("peerOrg2");
        System.out.println(peerOrganization1.toString());
    }

    /**
     * 构造通道
     */
    private Channel buildChannel(String channelName) throws Exception {
        // 创建Foo通道(完成网络中通道的创建与结点的加入)(仅使用了组织1创建?)
        logger.info("Going to constructing channel foo");
        // 这里为false
        boolean doPeerEventing = !testConfig.isRunningAgainstFabric10() && BAR_CHANNEL_NAME.equals(channelName);

        // 只有PeerAdmin能创建通道
        MedicalUser peerAdmin = peerOrganization1.getAdminPeer();

        // 设置Fabric Client用户环境,也就是设置谁进行操作
        fabricClient.setUserContext(peerAdmin);

        // 排序结点
        Collection<Orderer> ordererCollection = new LinkedList<>();

        // 获取这个组织全部Orderer结点名称
        for (String orderName : peerOrganization1.getOrdererNames()) {
            // 获取Orderer的属性
            Properties ordererProperties = testConfig.getOrdererProperties(orderName);
            // example of setting keepAlive to avoid timeouts on inactive http2 connections.
            // Under 5 minutes would require changes to server side to accept faster ping rates.
            // 这里再加入一些属性
            ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[]{5L, TimeUnit.MINUTES});
            ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[]{8L, TimeUnit.SECONDS});
            // 没有调用也会KeepAlive
            ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveWithoutCalls", new Object[]{true});
            // 构造Orderer对象
            // orderName = "orderer.example.com"
            // Location = "grpc://172.20.29.67:7050"
            // Property: {clientCertFile=D:\code\12_Paper\fabric-sdk-java\src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\ordererOrganizations\example.com\\users\Admin@example.com\tls\client.crt, sslProvider=openSSL, negotiationType=TLS, hostnameOverride=orderer.example.com, grpc.NettyChannelBuilderOption.keepAliveTime=[Ljava.lang.Object;@60f00693, grpc.NettyChannelBuilderOption.keepAliveTimeout=[Ljava.lang.Object;@79207381, grpc.NettyChannelBuilderOption.keepAliveWithoutCalls=[Ljava.lang.Object;@491b9b8, pemFile=D:\code\12_Paper\fabric-sdk-java\src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\ordererOrganizations\example.com\orderers\orderer.example.com\tls\server.crt, clientKeyFile=D:\code\12_Paper\fabric-sdk-java\src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\ordererOrganizations\example.com\\users\Admin@example.com\tls\client.key}
            Orderer orderer = fabricClient.newOrderer(orderName, peerOrganization1.getOrdererLocation(orderName),
                    ordererProperties);
            // 将Orderer对象加入集合
            ordererCollection.add(orderer);
        }
        // 仅取集合中第一个Orderer创建通道
        Orderer anOrderer = ordererCollection.iterator().next();
        // 从集合中移除选中的这个Orderer
        ordererCollection.remove(anOrderer);
        // tx文件路径
        String path = "src/test/fixture/sdkintegration/e2e-2Orgs/v1.3/foo.tx";
        // 通过tx文件对Channel进行配置
        ChannelConfiguration channelConfiguration = new ChannelConfiguration(new File(path));

        // 使用peerAdmin进行签名
        byte[] signature = fabricClient.getChannelConfigurationSignature(channelConfiguration, peerAdmin);
        // Create channel that has only one signer that is this orgs peer admin. If channel creation policy needed more signature they would need to be added too.
        // 通过PeerAdmin创建channel
        Channel newChannel = fabricClient.newChannel(channelName, anOrderer, channelConfiguration, signature);
        logger.info("Created channel " + channelName);

        // test with both cases when doing peer eventing.
        boolean everyOther = true;

        // 这里决定哪些Peer加入通道?
        // 获取组织的全部Peer结点
        for (String peerName : peerOrganization1.getPeerNames()) {
            // 获取Peer的地址
            String peerLocation = peerOrganization1.getPeerLocation(peerName);

            // 获取Peer结点的配置属性
            Properties peerProperties = testConfig.getPeerProperties(peerName);
            if (peerProperties == null) {
                peerProperties = new Properties();
            }
            // 打印一下属性
            for (String property : peerProperties.stringPropertyNames()) {
                logger.info(property, peerProperties.getProperty(property));
            }

            // Example of setting specific options on grpc's NettyChannelBuilder
            // 添加额外的属性
            peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);

            // 逐一构造Peer结点对象
            Peer peer = fabricClient.newPeer(peerName, peerLocation, peerProperties);
            // 如果版本大于等于1.3
            if (testConfig.isFabricVersionAtOrAfter("1.3")) {
                // 将当前Peer结点加入Channel中
                newChannel.joinPeer(peer, createPeerOptions()
                        // 默认拥有全部角色(四种角色)
                        .setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY, PeerRole.EVENT_SOURCE)));
            } else {
                if (doPeerEventing && everyOther) {
                    newChannel.joinPeer(peer,
                            createPeerOptions().setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY, PeerRole.EVENT_SOURCE))); //Default is all roles.
                } else {
                    // Set peer to not be all roles but eventing.
                    newChannel.joinPeer(peer,
                            createPeerOptions().setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY)));
                }
            }
            logger.info("Peer " + peerName + " joined channel " + channelName);
            everyOther = !everyOther;
        }

        // add remaining orderers if any.
        // 将剩下的Order结点加入通道
        for (Orderer orderer : ordererCollection) {
            newChannel.addOrderer(orderer);
        }

        // 获取事件Hub的名称
        for (String eventHubName : peerOrganization1.getEventHubNames()) {
            // 获取Peer结点配置信息
            final Properties eventHubProperties = testConfig.getEventHubProperties(eventHubName);
            eventHubProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[]{5L, TimeUnit.MINUTES});
            eventHubProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[]{8L, TimeUnit.SECONDS});
            EventHub eventHub = fabricClient.newEventHub(eventHubName, peerOrganization1.getEventHubLocation(eventHubName),
                    eventHubProperties);
            // 将EventHub加入通道中
            newChannel.addEventHub(eventHub);
        }
        // 初始化通道
        newChannel.initialize();
        logger.info("Finished initialization channel " + channelName);
        return newChannel;
    }


    /**
     * 核心方法
     *
     * @param localStore 文件存储
     * @throws Exception exception
     */
    public void runFabricTest(final LocalStore localStore) throws Exception {

        // 构造并运行Channel
        // 获取组织peerOrg1
        Organization organization = testConfig.getIntegrationTestsSampleOrg("peerOrg1");

        // 运行Channel(设置事件监听器,安装链码,转账,查询等操作)
        runChannel(fabricClient, fooChannel, true, organization, 0);
        // assertFalse(fooChannel.isShutdown());
        // Force foo channel to shutdown clean up resources.
        // 强制关掉Foo通道并清理资源
        // fooChannel.shutdown(true);
        // assertTrue(fooChannel.isShutdown());
        // 现在已经查询不到Foo通道了
        // assertNull(fabricClient.getChannel(FOO_CHANNEL_NAME));
        // print("\n\n");

        // 获取组织peerOrg2的实体
        organization = testConfig.getIntegrationTestsSampleOrg("peerOrg2");
        // 通过组织2构建barChannel
        Channel barChannel = constructChannel(BAR_CHANNEL_NAME, fabricClient, organization);
        assertTrue(barChannel.isInitialized());
        // 持久化channel
        localStore.saveChannel(barChannel);
        assertFalse(barChannel.isShutdown());
        // 运行第二个Bar通道
        runChannel(fabricClient, barChannel, true, organization, 100);
        // let bar channel just shutdown so we have both scenarios.
        print("\nTraverse the blocks for chain %s ", barChannel.getName());
        blockWalker(fabricClient, barChannel);

        // assertFalse(barChannel.isShutdown());
        // assertTrue(barChannel.isInitialized());
        print("That's all folks!");
    }


    /**
     * 构造链码安装对象
     */
    private void initChainCodeId() {
        // 这里开始设置链码相关了!
        ChaincodeID.Builder chaincodeIDBuilder = ChaincodeID.newBuilder()
                // 链码名称: "example_cc_go"
                .setName(CHAIN_CODE_NAME)
                // 链码版本: 1
                .setVersion(CHAIN_CODE_VERSION);
        // 如果路径不为空则设置路径(GO意外的语言为空)
        if (CHAIN_CODE_PATH != null) {
            chaincodeIDBuilder.setPath(CHAIN_CODE_PATH);
        }
        // 使用生成器生成链码Id
        chaincodeId = chaincodeIDBuilder.build();
    }


    /**
     * 注册与登记用户并持久化
     *
     * @param localStore file
     * @throws Exception exception
     */
    public void enrollAndRegisterUsers(LocalStore localStore) throws Exception {
        logger.info("***** Enrolling Users *****");

        // 对每个组织进行操作
        for (Organization organization : organizationSet) {
            // 获取CA代理
            HFCAClient ca = organization.getCAClient();
            // 获取组织名称
            final String orgName = organization.getName();
            // 获取组织MSPID
            final String mspid = organization.getMSPID();
            // 设置加密套件
            ca.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
            // 判断是否开启了TLS
            if (testConfig.isRunningFabricTLS()) {
                print("Open with TLS.");
                // This shows how to get a client TLS certificate from Fabric CA
                // we will use one client TLS certificate for orderer peers etc.
                // 构造Enroll请求
                final EnrollmentRequest enrollmentRequestTLS = new EnrollmentRequest();
                // 添加Host
                enrollmentRequestTLS.addHost("localhost");
                enrollmentRequestTLS.setProfile("tls");
                // 通过CA获取Enrollment
                final Enrollment enroll = ca.enroll("admin", "adminpw", enrollmentRequestTLS);
                // 获取TLS证书的Pem
                final String tlsCertPEM = enroll.getCert();
                // 获取TLS秘钥的Pem
                final String tlsKeyPEM = getPEMStringFromPrivateKey(enroll.getKey());
                // TLS属性设置
                final Properties tlsProperties = new Properties();
                // 将TLS秘钥与证书放入到属性中
                tlsProperties.put("clientKeyBytes", tlsKeyPEM.getBytes(UTF_8));
                tlsProperties.put("clientCertBytes", tlsCertPEM.getBytes(UTF_8));
                clientTLSProperties.put(organization.getName(), tlsProperties);
                // Save in sampleStore for follow on tests.
                // 将秘钥存入组织键值对中
                localStore.storeClientPemTlsCertificate(organization, tlsCertPEM);
                localStore.storeClientPemTlsKey(organization, tlsKeyPEM);
            }
            // 获取CA信息来判断是否连接成功
            HFCAInfo info = ca.info();
            // 获取Admin用户
            MedicalUser admin = localStore.getUser(TEST_ADMIN_NAME, orgName);
            // Preregistered admin only needs to be enrolled with Fabric caClient.
            // 如果Admin没有登记就进行登记
            if (!admin.isEnrolled()) {
                // Admin登记(使用CA启动时的用户名与密码)
                Enrollment enrollment = ca.enroll("admin", "adminpw");
                admin.setEnrollment(enrollment);
                // 设置MSPID
                // Org1MSP Org2MSP
                admin.setMspId(mspid);
            }
            // 创建一个新的普通用户
            MedicalUser user = localStore.getUser(normalUser1, organization.getName());
            // 对普通User用户进行登记与注册
            if (!user.isRegistered()) {
                // 设置用户的名称及其所属组织
                RegistrationRequest registerRequest = new RegistrationRequest(user.getName(), "org1.department1");
                // 利用Admin进行注册并获取登记密码
                String secret = ca.register(registerRequest, admin);
                user.setEnrollmentSecret(secret);
            }
            // 用户登记
            if (!user.isEnrolled()) {
                Enrollment enrollment = ca.enroll(user.getName(), user.getEnrollmentSecret());
                user.setEnrollment(enrollment);
                // Org1MSP Org2MSP
                user.setMspId(mspid);
            }
            // 获取组织名称 peerOrg1 peerOrg2
            final String organizationName = organization.getName();
            // 组织域名 org1.example.com org2.example.com
            final String organizationDomainName = organization.getDomainName();

            // 获取组织的Admin结点
            MedicalUser peerOrgAdmin = localStore.getUser(organizationName + "Admin", organizationName, organization.getMSPID(),
                    // src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\peerOrganizations\org1.example.com\\users\Admin@org1.example.com\msp\keystore\581fa072e48dc2a516f664df94ea687447c071f89fc0b783b147956a08929dcc_sk
                    Util.findFileSk(Paths.get(testConfig.getTestChannelPath(), "crypto-config/peerOrganizations/",
                            organizationDomainName, format("/users/Admin@%s/msp/keystore", organizationDomainName)).toFile()),
                    // src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\peerOrganizations\org1.example.com\\users\Admin@org1.example.com\msp\signcerts\Admin@org1.example.com-cert.pem
                    Paths.get(testConfig.getTestChannelPath(), "crypto-config/peerOrganizations/", organizationDomainName,
                            format("/users/Admin@%s/msp/signcerts/Admin@%s-cert.pem", organizationDomainName, organizationDomainName)).toFile());
            // A special user that can create channels, join peers and install chaincode
            // 创建当前组织的Admin结点
            organization.setAdminPeer(peerOrgAdmin);
            // 将普通用户加入当前组织
            organization.addUser(user);
            // 将Admin用户加入当前组织
            organization.setAdminUser(admin);
        }
    }


    /**
     * 组织1的注册与登记
     *
     * @param localStore 持久化文件
     */
    private void registerAndEnrollForOrg(LocalStore localStore, Organization organization) {
        try {
            // 获取CA代理
            HFCAClient caClient = organization.getCAClient();
            // 获取组织名称
            final String orgName = organization.getName();
            // 获取组织MSPID
            final String mspid = organization.getMSPID();
            // 设置加密套件
            caClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
            // 判断是否开启了TLS(默认为false)
            if (testConfig.isRunningFabricTLS()) {
                logger.info("Open with TLS.");
                // 这里演示了如何通过FabricCA获取一个客户端的TLS证书
                // This shows how to get a client TLS certificate from Fabric CA
                // we will use one client TLS certificate for orderer peers etc.
                // 构造Enroll请求
                final EnrollmentRequest enrollmentRequestTls = new EnrollmentRequest();
                // 添加Host
                enrollmentRequestTls.addHost("localhost");
                enrollmentRequestTls.setProfile("tls");
                // 通过CA获取Enrollment(使用Admin的账号和密码)
                final Enrollment enroll = caClient.enroll("admin", "adminpw", enrollmentRequestTls);
                // 获取TLS证书的Pem
                final String tlsCertPem = enroll.getCert();
                // 获取TLS秘钥的Pem
                final String tlsKeyPem = getPEMStringFromPrivateKey(enroll.getKey());
                // TLS属性设置
                final Properties tlsProperties = new Properties();
                // 将TLS秘钥与证书放入到属性中
                tlsProperties.put("clientKeyBytes", tlsKeyPem.getBytes(UTF_8));
                tlsProperties.put("clientCertBytes", tlsCertPem.getBytes(UTF_8));
                // TLS信息存入对应的组织名称下面
                clientTLSProperties.put(organization.getName(), tlsProperties);
                // Save in sampleStore for follow on tests.
                // 将秘钥存入组织键值对中(存入的是客户端的TLS证书)
                localStore.storeClientPemTlsCertificate(organization, tlsCertPem);
                localStore.storeClientPemTlsKey(organization, tlsKeyPem);
            }
            // 获取CA信息来判断是否连接成功
            HFCAInfo info = caClient.info();
            // 获取这个组织的Admin用户
            MedicalUser admin = localStore.getUser("admin", orgName);
            // Preregistered admin only needs to be enrolled with Fabric caClient.
            // 如果Admin没有登记就进行登记
            if (!admin.isEnrolled()) {
                // Admin登记(使用CA启动时的用户名与密码)
                Enrollment enrollment = caClient.enroll("admin", "adminpw");
                admin.setEnrollment(enrollment);
                // 设置MSPID
                // Org1MSP Org2MSP
                admin.setMspId(mspid);
            }
            // 创建一个新的普通用户
            MedicalUser user = localStore.getUser(normalUser1, organization.getName());

            // 对普通User用户进行登记与注册
            if (!user.isRegistered()) {
                // 设置用户的名称及其所属组织属性
                RegistrationRequest registerRequest = new RegistrationRequest(user.getName(), "org1.department1");
                // 利用组织的Admin用户进行注册并获取登记密码
                String secret = caClient.register(registerRequest, admin);
                user.setEnrollmentSecret(secret);
            }
            // 用户登记
            if (!user.isEnrolled()) {
                Enrollment enrollment = caClient.enroll(user.getName(), user.getEnrollmentSecret());
                user.setEnrollment(enrollment);
                // Org1MSP Org2MSP
                user.setMspId(mspid);
            }
            // 获取组织名称 peerOrg1 peerOrg2
            final String organizationName = organization.getName();
            // 组织域名 org1.example.com org2.example.com
            final String organizationDomainName = organization.getDomainName();

            // 获取组织的Admin结点(传入用户名,组织名,MSPID,私钥文件路径,证书文件路径)
            MedicalUser peerOrgAdmin = localStore.getUser(organizationName + "Admin", organizationName, organization.getMSPID(),
                    // 这里是私钥文件路径
                    // src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\peerOrganizations\
                    // org1.example.com\\users\Admin@org1.example.com\msp\keystore\581fa072e48dc2a516f664df94ea687447c071f89fc0b783b147956a08929dcc_sk
                    Util.findFileSk(Paths.get(testConfig.getTestChannelPath(), "crypto-config/peerOrganizations/",
                            organizationDomainName, format("/users/Admin@%s/msp/keystore", organizationDomainName)).toFile()),
                    // 这里是证书文件路径
                    // src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\peerOrganizations\
                    // org1.example.com\\users\Admin@org1.example.com\msp\signcerts\Admin@org1.example.com-cert.pem
                    Paths.get(testConfig.getTestChannelPath(), "crypto-config/peerOrganizations/", organizationDomainName,
                            format("/users/Admin@%s/msp/signcerts/Admin@%s-cert.pem", organizationDomainName, organizationDomainName)).toFile());
            // A special user that can create channels, join peers and install chaincode

            // 将前面的几个用户加入到组织中
            // 创建当前组织的AdminPeer结点
            organization.setAdminPeer(peerOrgAdmin);
            // 将普通用户加入当前组织
            organization.addUser(user);
            // 将AdminUser用户加入当前组织
            organization.setAdminUser(admin);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    static String getPEMStringFromPrivateKey(PrivateKey privateKey) throws IOException {
        StringWriter pemStrWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(pemStrWriter);
        pemWriter.writeObject(privateKey);
        pemWriter.close();
        return pemStrWriter.toString();
    }

    /**
     * map from channel name to move chaincode's return code.
     */
    Map<String, Long> expectedMoveRCMap = new HashMap<>();


    /**
     * 运行Channel
     *
     * @param fabricClient     代理对象
     * @param channel          通道
     * @param installChaincode 是否安装链码
     * @param organization     组织
     * @param delta            初始化数据
     */
    void runChannel(HFClient fabricClient, Channel channel, boolean installChaincode, Organization organization, int delta) {

        // 链码事件列表
        // Test list to capture chaincode events.
        List<ChaincodeEventCapture> chaincodeEventList = new LinkedList<>();

        try {
            // 获取通道名称
            final String channelName = channel.getName();
            // 是否是foo这个通道
            boolean isFooChain = FOO_CHANNEL_NAME.equals(channelName);
            print("Running channel is %s", channelName);
            // 获取通道中的全部Order结点
            Collection<Orderer> orderers = channel.getOrderers();
            // 初始化chaincodeID

            // 初始化提案的响应集合
            Collection<ProposalResponse> responseList;
            Collection<ProposalResponse> successResponseList = new LinkedList<>();
            Collection<ProposalResponse> failedResponseList = new LinkedList<>();

            // Register a chaincode event listener that will trigger for any chaincode id and only for EXPECTED_EVENT_NAME event.
            // 注册一个链码事件监听器
            chaincodeEventListenerHandler = channel.registerChaincodeEventListener(
                    Pattern.compile(".*"),
                    // 期待的事件: EXPECTED_EVENT_NAME = "event"
                    Pattern.compile(Pattern.quote(EXPECTED_EVENT_NAME)),
                    (handler, blockEvent, chaincodeEvent) -> {
                        // 将事件加入列表
                        chaincodeEventList.add(new ChaincodeEventCapture(handler, blockEvent, chaincodeEvent));

                        String es = blockEvent.getPeer() != null ? blockEvent.getPeer().getName() : blockEvent.getEventHub().getName();
                        print("RECEIVED Chaincode event with handle: %s, chaincode Id: %s, chaincode event name: %s, "
                                        + "transaction id: %s, event payload: \"%s\", from eventhub: %s",
                                handler, chaincodeEvent.getChaincodeId(),
                                chaincodeEvent.getEventName(),
                                chaincodeEvent.getTxId(),
                                new String(chaincodeEvent.getPayload()), es);
                    });

            // For non foo channel unregister event listener to test events are not called.
            // 如果不是foo通道就不注册事件监听器
            if (!isFooChain) {
                channel.unregisterChaincodeEventListener(chaincodeEventListenerHandler);
                chaincodeEventListenerHandler = null;
            }

            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 构造链码安装对象
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 这里开始设置链码相关了!
            ChaincodeID.Builder chaincodeIDBuilder = ChaincodeID.newBuilder()
                    // 链码名称: "example_cc_go"
                    .setName(CHAIN_CODE_NAME)
                    // 链码版本: 1
                    .setVersion(CHAIN_CODE_VERSION);

            // 如果路径不为空则设置路径(GO意外的语言为空)
            if (CHAIN_CODE_PATH != null) {
                chaincodeIDBuilder.setPath(CHAIN_CODE_PATH);
            }

            // 使用生成器生成链码Id
            chaincodeId = chaincodeIDBuilder.build();

            // 如果需要安装链码
            if (installChaincode) {
                // 下面构造链码安装的提案请求
                // 设置当前客户端的操作人为Admin Peer结点
                fabricClient.setUserContext(organization.getAdminPeer());
                print("Creating install chaincode proposal.");
                // 构造链码安装请求
                InstallProposalRequest installProposalRequest = fabricClient.newInstallProposalRequest();
                // 传入上面生成的链码ID
                installProposalRequest.setChaincodeID(chaincodeId);
                // 如果是Foo通道
                if (isFooChain) {
                    // 如果是foo通道则从目录安装
                    // on foo chain install from directory.
                    // For GO language and serving just a single user, chaincodeSource is mostly likely the users GOPATH
                    // 对于Go语言的链码安装 TEST_FIXTURES_PATH即为文件固定目录
                    installProposalRequest.setChaincodeSourceLocation(Paths.get(TEST_FIXTURES_PATH, CHAIN_CODE_FILEPATH).toFile());
                    // 如果版本是后于1.1
                    // 这里可以创建索引!!!!
                    if (testConfig.isFabricVersionAtOrAfter("1.1")) {
                        // 这将在链码中的字段"a"上设置索引,索引的配置参考meta-infs/end2endit/META-INF下面的IndexA.json文件
                        // This sets an index on the variable a in the chaincode
                        // see http://hyperledger-fabric.readthedocs.io/en/master/couchdb_as_state_database.html#using-couchdb-from-chaincode
                        // The file IndexA.json as part of the META-INF will be packaged with the source to create the index.
                        // 这里设置索引配置文件的路径
                        installProposalRequest.setChaincodeMetaInfLocation(new File("src/test/fixture/meta-infs/end2endit"));
                    }
                } else {
                    // 如果是bar通道则从输入流安装
                    // On bar chain install from an input stream.
                    // 对于inputStream，如果需要指示，应用程序需要确保流中提供了META-INF,SDK不会改变流中的任何东西
                    // For inputStream if indicies are desired the application needs to make sure the META-INF is provided in the stream. The SDK does not change anything in the stream.
                    // 如果是GO语言链码
                    if (CHAIN_CODE_LANG.equals(Type.GO_LANG)) {
                        // 设置链码的输入流
                        installProposalRequest.setChaincodeInputStream(Util.generateTarGzInputStream(
                                (Paths.get(TEST_FIXTURES_PATH, CHAIN_CODE_FILEPATH, "src", CHAIN_CODE_PATH).toFile()),
                                Paths.get("src", CHAIN_CODE_PATH).toString()));
                        // 其他语言链码
                    } else {
                        installProposalRequest.setChaincodeInputStream(Util.generateTarGzInputStream(
                                (Paths.get(TEST_FIXTURES_PATH, CHAIN_CODE_FILEPATH).toFile()), "src"));
                    }
                }
                // 设置链码版本
                installProposalRequest.setChaincodeVersion(CHAIN_CODE_VERSION);
                // 设置链码语言
                installProposalRequest.setChaincodeLanguage(CHAIN_CODE_LANG);

                print("Sending chaincode install proposal");

                ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                // 提交链码安装请求并分析结果
                ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
                // only a client from the same org as the peer can issue an install request
                int numInstallProposal = 0;
                // Set<String> orgs = orgPeers.keySet();
                // for (SampleOrg org : testSampleOrgs) {
                // 获取通道中的全部Peer结点
                Collection<Peer> peers = channel.getPeers();
                // 需要安装链码的数量
                numInstallProposal = numInstallProposal + peers.size();
                // 发送链码安装请求并得到响应
                responseList = fabricClient.sendInstallProposal(installProposalRequest, peers);
                // 看看响应
                for (ProposalResponse response : responseList) {
                    // 安装成功
                    if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                        print("Successful install proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                        successResponseList.add(response);
                    } else {
                        failedResponseList.add(response);
                    }
                }
                // }
                print("Received %d install proposal responses. 成功 + 验证个数: %d . 失败个数: %d", numInstallProposal, successResponseList.size(), failedResponseList.size());
                // 如果有失败的情况
                if (failedResponseList.size() > 0) {
                    ProposalResponse first = failedResponseList.iterator().next();
                    fail("Not enough endorsers for install :" + successResponseList.size() + ".  " + first.getMessage());
                }
            }

            // client.setUserContext(sampleOrg.getUser(TEST_ADMIN_NAME));
            // final ChaincodeID chaincodeID = firstInstallProposalResponse.getChaincodeID();

            // 安装链码不需要发送交易到Orderer结点
            // Note: installing chaincode does not require transaction no need to send to Orderers

            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 实例化链码
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 构造实例化链码请求
            InstantiateProposalRequest instantiateProposalRequest = fabricClient.newInstantiationProposalRequest();
            // 设置链码实例化属性
            instantiateProposalRequest.setProposalWaitTime(DEPLOYWAITTIME);
            instantiateProposalRequest.setChaincodeID(chaincodeId);
            instantiateProposalRequest.setChaincodeLanguage(CHAIN_CODE_LANG);
            // 指定实例化的init方法
            instantiateProposalRequest.setFcn("init");
            // 设置实例化的参数(这里设置每个用户初始有多少钱)
            instantiateProposalRequest.setArgs("a", "500", "b", "" + (200 + delta));
            // 母鸡在干啥
            Map<String, byte[]> tm = new HashMap<>();
            tm.put("HyperLedgerFabric", "InstantiateProposalRequest:JavaSDK".getBytes(UTF_8));
            tm.put("method", "InstantiateProposalRequest".getBytes(UTF_8));
            instantiateProposalRequest.setTransientMap(tm);

            // 指定背书策略！！！！
            /*
              policy OR(Org1MSP.member, Org2MSP.member) meaning 1 signature from someone in either Org1 or Org2
              See README.md Chaincode endorsement policies section for more details.
            */
            // 构造链码背书对象
            ChaincodeEndorsementPolicy endorsementPolicy = new ChaincodeEndorsementPolicy();
            // 从YAML文件读取背书策略
            endorsementPolicy.fromYamlFile(new File(TEST_FIXTURES_PATH + "/sdkintegration/chaincodeendorsementpolicy.yaml"));
            instantiateProposalRequest.setChaincodeEndorsementPolicy(endorsementPolicy);

            print("Sending 链码实例化请求 to all peers with arguments: a and b set to 100 and %s respectively", "" + (200 + delta));
            // 清除响应结果记录
            successResponseList.clear();
            failedResponseList.clear();

            // 如果是Foo通道
            // Send responses both ways with specifying peers and by using those on the channel.
            if (isFooChain) {
                // 这里往所有的Peer结点发送实例化提案并得到响应
                responseList = channel.sendInstantiationProposal(instantiateProposalRequest, channel.getPeers());
            } else {
                responseList = channel.sendInstantiationProposal(instantiateProposalRequest);
            }

            // 分析实例化提案的响应结果
            for (ProposalResponse response : responseList) {
                if (response.isVerified() && response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    successResponseList.add(response);
                    print("Succesful instantiate proposal response TxId: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                } else {
                    failedResponseList.add(response);
                }
            }
            print("Received %d instantiate proposal responses. Successful + verified: %d . Failed: %d", responseList.size(), successResponseList.size(), failedResponseList.size());
            // 实例化失败
            if (failedResponseList.size() > 0) {
                for (ProposalResponse fail : failedResponseList) {
                    print("Not enough endorsers for instantiate :" + successResponseList.size() + "endorser failed with " + fail.getMessage() + ", on peer" + fail.getPeer());
                }
                ProposalResponse first = failedResponseList.iterator().next();
                // 这里抛出异常
                fail("Not enough endorsers for instantiate :" + successResponseList.size() + "endorser failed with " + first.getMessage() + ". Was verified:" + first.isVerified());
            }

            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 发送实例化交易到Orderer
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // Send instantiate transaction to orderer

            print("Sending 实例化交易 to orderer with a and b set to 100 and %s respectively", "" + (200 + delta));

            // Specify what events should complete the interest in this transaction. This is the default
            // for all to complete. It's possible to specify many different combinations like
            // any from a group, all from one group and just one from another or even None(NOfEvents.createNoEvents).
            // See. Channel.NOfEvents
            // 这里设置提交交易时感兴趣的事件
            Channel.NOfEvents nOfEvents = createNofEvents();
            if (!channel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)).isEmpty()) {
                nOfEvents.addPeers(channel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)));
            }
            if (!channel.getEventHubs().isEmpty()) {
                nOfEvents.addEventHubs(channel.getEventHubs());
            }
            // 将实例化的交易发送到Order结点
            channel.sendTransaction(
                    // 包含上面的成功响应结果集
                    successResponseList,
                    // 交易配置
                    createTransactionOptions()
                            // !!!!设置用户环境
                            .userContext(fabricClient.getUserContext())
                            // don't shuffle any orderers the default is true.
                            .shuffleOrders(false)
                            // specify the orderers we want to try this transaction. Fails once all Orderers are tried.
                            .orderers(channel.getOrderers())
                            // The events to signal the completion of the interest in the transaction
                            // 设置感兴趣的事件
                            .nOfEvents(nOfEvents)

                    // 指定之后执行的内容(对交易的事件进行处理)
            ).thenApply(transactionEvent -> {
                // 没用
                waitOnFabric(0);
                // 交易事件必须是合法的
                assertTrue(transactionEvent.isValid());
                // 交易事件必须有签名
                assertNotNull(transactionEvent.getSignature()); // Must have a signature.
                // 从交易事件获取区块事件
                BlockEvent blockEvent = transactionEvent.getBlockEvent(); // This is the block event that has this transaction.
                // 保证能够获取区块
                assertNotNull(blockEvent.getBlock()); // Make sure the RAW Fabric block is returned.
                // 到这里完成了链码实例化过程
                print("Finished instantiate transaction with transaction id %s", transactionEvent.getTransactionID());

                ///////////////////////////////////////////////////////////////////////////////////////////////////////
                /// 发送交易提案到所有的Peer结点(这里执行转账操作了)
                ///////////////////////////////////////////////////////////////////////////////////////////////////////
                try {
                    assertEquals(blockEvent.getChannelId(), channel.getName());
                    // 清除响应结果列表
                    successResponseList.clear();
                    failedResponseList.clear();

                    // 设置成普通的用户!!!
                    fabricClient.setUserContext(organization.getUser(normalUser1));
                    // 构造交易提案请求
                    TransactionProposalRequest transactionProposalRequest = fabricClient.newTransactionProposalRequest();
                    // 设置需要执行的链码ID
                    transactionProposalRequest.setChaincodeID(chaincodeId);
                    // 链码语言
                    transactionProposalRequest.setChaincodeLanguage(CHAIN_CODE_LANG);
                    //transactionProposalRequest.setFcn("invoke");
                    transactionProposalRequest.setFcn("move");
                    transactionProposalRequest.setProposalWaitTime(testConfig.getProposalWaitTime());
                    // 设置参数
                    transactionProposalRequest.setArgs("a", "b", "100");
                    // 母鸡在干啥
                    Map<String, byte[]> tm2 = new HashMap<>();
                    // Just some extra junk in transient map
                    tm2.put("HyperLedgerFabric", "TransactionProposalRequest:JavaSDK".getBytes(UTF_8));
                    // ditto
                    tm2.put("method", "TransactionProposalRequest".getBytes(UTF_8));
                    // This should be returned in the payload see chaincode why.
                    tm2.put("result", ":)".getBytes(UTF_8));

                    // 如果是GO语言且版本大于1.2
                    if (Type.GO_LANG.equals(CHAIN_CODE_LANG) && testConfig.isFabricVersionAtOrAfter("1.2")) {
                        // the chaincode will return this as status see chaincode why.
                        expectedMoveRCMap.put(channelName, random.nextInt(300) + 100L);
                        // This should be returned see chaincode why.
                        tm2.put("rc", (expectedMoveRCMap.get(channelName) + "").getBytes(UTF_8));
                        // 400 and above results in the peer not endorsing!
                    } else {
                        // not really supported for Java or Node.
                        // 对Java或Go不太支持
                        expectedMoveRCMap.put(channelName, 200L);
                    }
                    // This should trigger an event see chaincode why.
                    tm2.put(EXPECTED_EVENT_NAME, EXPECTED_EVENT_DATA);
                    transactionProposalRequest.setTransientMap(tm2);

                    print("Sending transactionProposal to all peers with arguments: move(a,b,100)");

                    // Collection<ProposalResponse> transactionPropResp = channel.sendTransactionProposalToEndorsers(transactionProposalRequest);
                    // 往所有的Peer结点发送交易并得到响应
                    Collection<ProposalResponse> transactionResponse = channel.sendTransactionProposal(transactionProposalRequest, channel.getPeers());
                    // 康康结果是否OK
                    for (ProposalResponse response : transactionResponse) {
                        if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                            print("Successful transaction proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                            successResponseList.add(response);
                        } else {
                            failedResponseList.add(response);
                        }
                    }
                    print("Received %d transaction proposal responses. Successful + verified: %d . Failed: %d",
                            transactionResponse.size(), successResponseList.size(), failedResponseList.size());
                    if (failedResponseList.size() > 0) {
                        ProposalResponse firstTransactionProposalResponse = failedResponseList.iterator().next();
                        fail("Not enough endorsers for invoke(move a,b,100):" + failedResponseList.size() + " endorser error: " +
                                firstTransactionProposalResponse.getMessage() + ". Was verified: " + firstTransactionProposalResponse.isVerified());
                    }

                    // 检查是否全部的提案都是一致的,这在发送给Orderer时是自动执行的.这里写出来只是说明应用程序可以自己选择使用
                    // Check that all the proposals are consistent with each other. We should have only one set
                    // where all the proposals above are consistent.
                    // Note the when sending to Orderer this is done automatically.
                    // Shown here as an example that applications can invoke and select.
                    // See org.hyperledger.fabric.sdk.proposal.consistency_validation config property.
                    // 获取响应集
                    Collection<Set<ProposalResponse>> proposalConsistencySets = SDKUtils.getProposalConsistencySets(transactionResponse);
                    if (proposalConsistencySets.size() != 1) {
                        fail(format("Expected only one set of consistent proposal responses but got %d", proposalConsistencySets.size()));
                    }
                    // 到这里验证成功
                    print("Successfully received transaction proposal responses.");

                    // 可以退出了,因为交易执行完毕
                    //  System.exit(10);

                    ///////////////////////////////////////////////////////////////////////////////////////////////////////
                    /// 下面分析交易的返回结果
                    ///////////////////////////////////////////////////////////////////////////////////////////////////////

                    ProposalResponse successResponse = successResponseList.iterator().next();
                    // This is the data returned by the chaincode.
                    // 这里分析一下从链码返回的数据
                    byte[] dataBytes = successResponse.getChaincodeActionResponsePayload();
                    // 解析成字符串形式
                    String resultAsString = null;
                    if (dataBytes != null) {
                        resultAsString = new String(dataBytes, UTF_8);
                    }
                    // 判断是否是下面的图像
                    assertEquals(":)", resultAsString);
                    // Chaincode's status.
                    assertEquals(expectedMoveRCMap.get(channelName).longValue(), successResponse.getChaincodeActionResponseStatus());

                    // 获取读写集的信息
                    TxReadWriteSetInfo readWriteSetInfo = successResponse.getChaincodeActionResponseReadWriteSetInfo();
                    // See block walker below how to transverse this
                    assertNotNull(readWriteSetInfo);
                    assertTrue(readWriteSetInfo.getNsRwsetCount() > 0);
                    // 获取响应的ChaincodeId
                    ChaincodeID cid = successResponse.getChaincodeID();
                    assertNotNull(cid);

                    // 看看链码Id的路径是否是本地链码的路径
                    final String path = cid.getPath();
                    if (CHAIN_CODE_PATH == null) {
                        assertTrue(path == null || "".equals(path));
                    } else {
                        assertEquals(CHAIN_CODE_PATH, path);
                    }

                    assertEquals(CHAIN_CODE_NAME, cid.getName());
                    assertEquals(CHAIN_CODE_VERSION, cid.getVersion());

                    ////////////////////////////////////////////////////////////////////////////////////////////////////////
                    // 将成功的交易信息发送到Orderer结点
                    ////////////////////////////////////////////////////////////////////////////////////////////////////////
                    print("Sending chaincode transaction(move a,b,100) to orderer.");
                    return channel.sendTransaction(successResponseList).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);
                } catch (Exception e) {
                    print("Caught an exception while invoking chaincode");
                    e.printStackTrace();
                    fail("Failed invoking chaincode with error : " + e.getMessage());
                }
                return null;

                // 之后执行
            }).thenApply(transactionEvent -> {
                try {
                    // 交易事件必须合法
                    assertTrue(transactionEvent.isValid());
                    print("Finished transaction with transaction id %s", transactionEvent.getTransactionID());
                    // used in the channel queries later
                    // 用于后面的交易查询
                    testTxID = transactionEvent.getTransactionID();

                    //////////////////////////////////////////////////////////////////////////////////////////////
                    // 发送查询提案给所有Peer结点
                    //////////////////////////////////////////////////////////////////////////////////////////////
                    String expect = "" + (300 + delta);
                    print("Now query chaincode for the value of b.");
                    // 构造查询请求
                    QueryByChaincodeRequest queryByChaincodeRequest = fabricClient.newQueryProposalRequest();
                    // 设置参数
                    queryByChaincodeRequest.setArgs("b");
                    // 设置调用方法
                    queryByChaincodeRequest.setFcn("query");
                    // 设置链码Id
                    queryByChaincodeRequest.setChaincodeID(chaincodeId);
                    // 不知道在干啥
                    Map<String, byte[]> tm2 = new HashMap<>();
                    tm2.put("HyperLedgerFabric", "QueryByChaincodeRequest:JavaSDK".getBytes(UTF_8));
                    tm2.put("method", "QueryByChaincodeRequest".getBytes(UTF_8));
                    queryByChaincodeRequest.setTransientMap(tm2);

                    // 发送查询请求并获取响应结果
                    Collection<ProposalResponse> queryResponses = channel.queryByChaincode(queryByChaincodeRequest, channel.getPeers());
                    // 分析响应结果
                    for (ProposalResponse proposalResponse : queryResponses) {
                        if (!proposalResponse.isVerified() || proposalResponse.getStatus() != ProposalResponse.Status.SUCCESS) {
                            fail("Failed query proposal from peer " + proposalResponse.getPeer().getName() + " status: " + proposalResponse.getStatus() +
                                    ". Messages: " + proposalResponse.getMessage() + ". Was verified : " + proposalResponse.isVerified());
                        } else {
                            // 查询成功,获取返回的数据
                            String payload = proposalResponse.getProposalResponse().getResponse().getPayload().toStringUtf8();
                            print("Query payload of b from peer %s returned %s", proposalResponse.getPeer().getName(), payload);
                            assertEquals(payload, expect);
                        }
                    }
                    return null;

                } catch (Exception e) {
                    print("Caught exception while running query");
                    e.printStackTrace();
                    fail("Failed during chaincode query with error : " + e.getMessage());
                }
                return null;

                // 发生异常
            }).exceptionally(e -> {
                if (e instanceof TransactionEventException) {
                    BlockEvent.TransactionEvent te = ((TransactionEventException) e).getTransactionEvent();
                    if (te != null) {
                        throw new AssertionError(format("Transaction with TxId %s failed. %s", te.getTransactionID(), e.getMessage()), e);
                    }
                }
                throw new AssertionError(format("Test failed with %s exception %s", e.getClass().getName(), e.getMessage()), e);
            }).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);


            //////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 通道信息查询
            //////////////////////////////////////////////////////////////////////////////////////////////////////////

            // We can only send channel queries to peers that are in the same org as the SDK user context
            // Get the peers from the current org being used and pick one randomly to send the queries to.
            // Set<Peer> peerSet = sampleOrg.getPeers();
            // Peer queryPeer = peerSet.iterator().next();
            // out("Using peer %s for channel queries", queryPeer.getName());

            // 查询区块链信息
            BlockchainInfo channelInfo = channel.queryBlockchainInfo();
            // 通道(账本)名称
            print("Channel info for : " + channelName);
            // 区块链高度
            print("Channel height: " + channelInfo.getHeight());
            // 账本当前区块Hash
            String chainCurrentHash = Hex.encodeHexString(channelInfo.getCurrentBlockHash());
            // 账本前一个块的Hash
            String chainPreviousHash = Hex.encodeHexString(channelInfo.getPreviousBlockHash());
            print("Chain current block hash: " + chainCurrentHash);
            print("Chain previous block hash: " + chainPreviousHash);

            // 通过区块编号查询
            // Query by block number. Should return latest block, i.e. block number 2
            BlockInfo returnedBlock = channel.queryBlockByNumber(channelInfo.getHeight() - 1);
            String previousHash = Hex.encodeHexString(returnedBlock.getPreviousHash());
            print("queryBlockByNumber returned correct block with blockNumber " + returnedBlock.getBlockNumber()
                    + " \n previous_hash " + previousHash);
            assertEquals(channelInfo.getHeight() - 1, returnedBlock.getBlockNumber());
            assertEquals(chainPreviousHash, previousHash);

            // Query by block hash. Using latest block's previous hash so should return block number 1
            // 通过区块Hash查询
            byte[] hashQuery = returnedBlock.getPreviousHash();
            returnedBlock = channel.queryBlockByHash(hashQuery);
            print("queryBlockByHash returned block with blockNumber " + returnedBlock.getBlockNumber());
            assertEquals(channelInfo.getHeight() - 2, returnedBlock.getBlockNumber());

            // Query block by TxID. Since it's the last TxID, should be block 2
            // 通过交易Id查询区块
            returnedBlock = channel.queryBlockByTransactionID(testTxID);
            print("queryBlockByTxID returned block with blockNumber " + returnedBlock.getBlockNumber());
            assertEquals(channelInfo.getHeight() - 1, returnedBlock.getBlockNumber());

            // query transaction by ID
            // 通过交易ID查询交易
            TransactionInfo txInfo = channel.queryTransactionByID(testTxID);
            print("QueryTransactionByID returned TransactionInfo: txID " + txInfo.getTransactionID()
                    + "\n     validation code " + txInfo.getValidationCode().getNumber());


            if (chaincodeEventListenerHandler != null) {
                // 取消注册链码事件监听器
                channel.unregisterChaincodeEventListener(chaincodeEventListenerHandler);
                // Should be two. One event in chaincode and two notification for each of the two event hubs
                final int numberEventsExpected = channel.getEventHubs().size() + channel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)).size();
                // just make sure we get the notifications.
                for (int i = 15; i > 0; --i) {
                    if (chaincodeEventList.size() == numberEventsExpected) {
                        break;
                    } else {
                        Thread.sleep(90); // wait for the events.
                    }
                }
                assertEquals(numberEventsExpected, chaincodeEventList.size());
                // 读取之前的链码事件
                for (ChaincodeEventCapture chaincodeEventCapture : chaincodeEventList) {
                    assertEquals(chaincodeEventListenerHandler, chaincodeEventCapture.handle);
                    assertEquals(testTxID, chaincodeEventCapture.chaincodeEvent.getTxId());
                    assertEquals(EXPECTED_EVENT_NAME, chaincodeEventCapture.chaincodeEvent.getEventName());
                    assertTrue(Arrays.equals(EXPECTED_EVENT_DATA, chaincodeEventCapture.chaincodeEvent.getPayload()));
                    assertEquals(CHAIN_CODE_NAME, chaincodeEventCapture.chaincodeEvent.getChaincodeId());

                    // 获取区块事件
                    BlockEvent blockEvent = chaincodeEventCapture.blockEvent;
                    assertEquals(channelName, blockEvent.getChannelId());
                    // assertTrue(channel.getEventHubs().contains(blockEvent.getEventHub()));
                }
            } else {
                assertTrue(chaincodeEventList.isEmpty());
            }
            print("Running for Channel %s done", channelName);
        } catch (Exception e) {
            print("Caught an exception running channel %s", channel.getName());
            e.printStackTrace();
            fail("Test failed with error : " + e.getMessage());
        }
    }

    /**
     * 构造通道对象
     *
     * @param channelName  通道名称
     * @param fabricClient Fabric客户端
     * @param organization 组织
     */
    Channel constructChannel(String channelName, HFClient fabricClient, Organization organization) throws Exception {
        print("Going to constructing channel %s", channelName);
        // boolean doPeerEventing = false;
        // 这里为false
        boolean doPeerEventing = !testConfig.isRunningAgainstFabric10() && BAR_CHANNEL_NAME.equals(channelName);
        // boolean doPeerEventing = !testConfig.isRunningAgainstFabric10() && FOO_CHANNEL_NAME.equals(name);

        // 只有PeerAdmin能创建通道
        MedicalUser peerAdmin = organization.getAdminPeer();
        // 设置Fabric Client用户环境,也就是设置谁进行操作
        fabricClient.setUserContext(peerAdmin);
        // 排序结点
        Collection<Orderer> ordererCollection = new LinkedList<>();

        for (String orderName : organization.getOrdererNames()) {
            // 获取Orderer的属性
            Properties ordererProperties = testConfig.getOrdererProperties(orderName);
            // example of setting keepAlive to avoid timeouts on inactive http2 connections.
            // Under 5 minutes would require changes to server side to accept faster ping rates.
            // 这里再加入一些属性
            ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[]{5L, TimeUnit.MINUTES});
            ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[]{8L, TimeUnit.SECONDS});
            ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveWithoutCalls", new Object[]{true});
            // 构造Orderer对象
            // orderName = "orderer.example.com"
            // Location = "grpc://172.20.29.67:7050"
            // Property: {clientCertFile=D:\code\12_Paper\fabric-sdk-java\src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\ordererOrganizations\example.com\\users\Admin@example.com\tls\client.crt, sslProvider=openSSL, negotiationType=TLS, hostnameOverride=orderer.example.com, grpc.NettyChannelBuilderOption.keepAliveTime=[Ljava.lang.Object;@60f00693, grpc.NettyChannelBuilderOption.keepAliveTimeout=[Ljava.lang.Object;@79207381, grpc.NettyChannelBuilderOption.keepAliveWithoutCalls=[Ljava.lang.Object;@491b9b8, pemFile=D:\code\12_Paper\fabric-sdk-java\src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\ordererOrganizations\example.com\orderers\orderer.example.com\tls\server.crt, clientKeyFile=D:\code\12_Paper\fabric-sdk-java\src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\ordererOrganizations\example.com\\users\Admin@example.com\tls\client.key}
            Orderer orderer = fabricClient.newOrderer(orderName, organization.getOrdererLocation(orderName),
                    ordererProperties);
            // 将Orderer对象加入集合
            ordererCollection.add(orderer);
        }
        // 仅取集合中第一个Orderer创建通道
        Orderer anOrderer = ordererCollection.iterator().next();
        // 从集合中移除该Orderer
        ordererCollection.remove(anOrderer);
        // tx文件路径: src/test/fixture/sdkintegration/e2e-2Orgs/v1.3/foo.tx
        String path = TEST_FIXTURES_PATH + "/sdkintegration/e2e-2Orgs/" + testConfig.getFabricConfigGenVers() + "/" + channelName + ".tx";
        // 通过tx文件对Channel进行配置
        ChannelConfiguration channelConfiguration = new ChannelConfiguration(new File(path));

        // 使用peerAdmin进行签名
        byte[] signature = fabricClient.getChannelConfigurationSignature(channelConfiguration, peerAdmin);
        // print(new String(signature));
        // Create channel that has only one signer that is this orgs peer admin. If channel creation policy needed more signature they would need to be added too.
        // 通过Peer Admin创建channel
        Channel newChannel = fabricClient.newChannel(channelName, anOrderer, channelConfiguration, signature);

        print("Created channel %s", channelName);

        boolean everyOther = true; // test with both cases when doing peer eventing.

        // 获取组织的全部Peer结点
        for (String peerName : organization.getPeerNames()) {
            // 获取Peer的地址
            String peerLocation = organization.getPeerLocation(peerName);
            print("PeerLocation", peerLocation);
            print("PeerName", peerName);

            // 获取Peer结点的配置属性
            Properties peerProperties = testConfig.getPeerProperties(peerName);
            if (peerProperties == null) {
                peerProperties = new Properties();
            }
            // 打印一下属性
            for (String property : peerProperties.stringPropertyNames()) {
                print(property, peerProperties.getProperty(property));
            }

            // Example of setting specific options on grpc's NettyChannelBuilder
            // 添加额外的属性
            peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);

            // 构造Peer结点对象
            Peer peer = fabricClient.newPeer(peerName, peerLocation, peerProperties);
            // 如果版本大于等于1.3
            if (testConfig.isFabricVersionAtOrAfter("1.3")) {
                // 将当前Peer结点加入Channel中
                newChannel.joinPeer(peer, createPeerOptions()
                        // 默认拥有全部角色
                        .setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY, PeerRole.EVENT_SOURCE)));

            } else {
                if (doPeerEventing && everyOther) {
                    newChannel.joinPeer(peer, createPeerOptions().setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY, PeerRole.EVENT_SOURCE))); //Default is all roles.
                } else {
                    // Set peer to not be all roles but eventing.
                    newChannel.joinPeer(peer, createPeerOptions().setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY)));
                }
            }
            print("Peer %s joined channel %s", peerName, channelName);
            everyOther = !everyOther;
        }

        // 仅仅是测试
        if (doPeerEventing || testConfig.isFabricVersionAtOrAfter("1.3")) {
            // Make sure there is one of each type peer at the very least.
            assertFalse(newChannel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)).isEmpty());
            assertFalse(newChannel.getPeers(PeerRole.NO_EVENT_SOURCE).isEmpty());
        }

        // add remaining orderers if any.
        // 将剩下的Order结点加入通道
        for (Orderer orderer : ordererCollection) {
            newChannel.addOrderer(orderer);
            print("其他Order结点名称", orderer.getName());
        }
        // 获取事件Hub的名称
        for (String eventHubName : organization.getEventHubNames()) {
            // 获取Peer结点配置信息
            final Properties eventHubProperties = testConfig.getEventHubProperties(eventHubName);

            eventHubProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[]{5L, TimeUnit.MINUTES});
            eventHubProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[]{8L, TimeUnit.SECONDS});

            EventHub eventHub = fabricClient.newEventHub(eventHubName, organization.getEventHubLocation(eventHubName),
                    eventHubProperties);
            // 将EventHub加入通道中
            newChannel.addEventHub(eventHub);
        }
        // 初始化通道
        newChannel.initialize();
        print("Finished initialization channel %s", channelName);

        // 看看是否能够序列化与反序列化通道
        // Just checks if channel can be serialized and deserialized .. otherwise this is just a waste :)
        byte[] serializedChannelBytes = newChannel.serializeChannel();
        newChannel.shutdown(true);
        // 这里其实可以直接返回Channel
        return fabricClient.deSerializeChannel(serializedChannelBytes).initialize();
    }

    private void waitOnFabric(int additional) {
        // Do Nothing.
    }

    /**
     * 区块的查看方法
     *
     * @param fabricClient Client
     * @param channel      channel
     */
    void blockWalker(HFClient fabricClient, Channel channel) throws InvalidArgumentException, ProposalException, IOException {
        try {
            // 获取区块链信息
            BlockchainInfo channelInfo = channel.queryBlockchainInfo();
            // 迭代获取每个区块的信息
            for (long current = channelInfo.getHeight() - 1; current > -1; current--) {
                // 区块信息
                BlockInfo returnedBlock = channel.queryBlockByNumber(current);
                final long blockNumber = returnedBlock.getBlockNumber();

                print("current block number %d has data hash: %s", blockNumber, Hex.encodeHexString(returnedBlock.getDataHash()));
                print("current block number %d has previous hash id: %s", blockNumber, Hex.encodeHexString(returnedBlock.getPreviousHash()));
                print("current block number %d has calculated block hash is %s", blockNumber, Hex.encodeHexString(SDKUtils.calculateBlockHash(fabricClient,
                        blockNumber, returnedBlock.getPreviousHash(), returnedBlock.getDataHash())));
                // 获取Envelope的数量
                final int envelopeCount = returnedBlock.getEnvelopeCount();
                assertEquals(1, envelopeCount);
                print("current block number %d has %d envelope count:", blockNumber, returnedBlock.getEnvelopeCount());
                int i = 0;
                int transactionCount = 0;
                for (BlockInfo.EnvelopeInfo envelopeInfo : returnedBlock.getEnvelopeInfos()) {
                    i++;
                    print("  Transaction number %d has transaction id: %s", i, envelopeInfo.getTransactionID());
                    final String channelId = envelopeInfo.getChannelId();
                    assertTrue("foo".equals(channelId) || "bar".equals(channelId));

                    print("  Transaction number %d has channel id: %s", i, channelId);
                    print("  Transaction number %d has epoch: %d", i, envelopeInfo.getEpoch());
                    print("  Transaction number %d has transaction timestamp: %tB %<te,  %<tY  %<tT %<Tp", i, envelopeInfo.getTimestamp());
                    print("  Transaction number %d has type id: %s", i, "" + envelopeInfo.getType());
                    print("  Transaction number %d has nonce : %s", i, "" + Hex.encodeHexString(envelopeInfo.getNonce()));
                    print("  Transaction number %d has submitter mspid: %s,  certificate: %s", i, envelopeInfo.getCreator().getMspid(), envelopeInfo.getCreator().getId());

                    if (envelopeInfo.getType() == TRANSACTION_ENVELOPE) {
                        ++transactionCount;
                        BlockInfo.TransactionEnvelopeInfo transactionEnvelopeInfo = (BlockInfo.TransactionEnvelopeInfo) envelopeInfo;

                        print("  Transaction number %d has %d actions", i, transactionEnvelopeInfo.getTransactionActionInfoCount());
                        assertEquals(1, transactionEnvelopeInfo.getTransactionActionInfoCount()); // for now there is only 1 action per transaction.
                        print("  Transaction number %d isValid %b", i, transactionEnvelopeInfo.isValid());
                        assertEquals(transactionEnvelopeInfo.isValid(), true);
                        print("  Transaction number %d validation code %d", i, transactionEnvelopeInfo.getValidationCode());
                        assertEquals(0, transactionEnvelopeInfo.getValidationCode());
                        int j = 0;
                        for (BlockInfo.TransactionEnvelopeInfo.TransactionActionInfo transactionActionInfo : transactionEnvelopeInfo.getTransactionActionInfos()) {
                            ++j;
                            print("   Transaction action %d has response status %d", j, transactionActionInfo.getResponseStatus());

                            long excpectedStatus = current == 2 && i == 1 && j == 1 ? expectedMoveRCMap.get(channel.getName()) : 200; // only transaction we changed the status code.
                            assertEquals(format("channel %s current: %d, i: %d.  transaction action j=%d", channel.getName(), current, i, j), excpectedStatus, transactionActionInfo.getResponseStatus());
                            print("   Transaction action %d has response message bytes as string: %s", j,
                                    printableString(new String(transactionActionInfo.getResponseMessageBytes(), UTF_8)));
                            print("   Transaction action %d has %d endorsements", j, transactionActionInfo.getEndorsementsCount());
                            assertEquals(2, transactionActionInfo.getEndorsementsCount());

                            for (int n = 0; n < transactionActionInfo.getEndorsementsCount(); ++n) {
                                BlockInfo.EndorserInfo endorserInfo = transactionActionInfo.getEndorsementInfo(n);
                                print("Endorser %d signature: %s", n, Hex.encodeHexString(endorserInfo.getSignature()));
                                print("Endorser %d endorser: mspid %s \n certificate %s", n, endorserInfo.getMspid(), endorserInfo.getId());
                            }
                            print("   Transaction action %d has %d chaincode input arguments", j, transactionActionInfo.getChaincodeInputArgsCount());
                            for (int z = 0; z < transactionActionInfo.getChaincodeInputArgsCount(); ++z) {
                                print("     Transaction action %d has chaincode input argument %d is: %s", j, z,
                                        printableString(new String(transactionActionInfo.getChaincodeInputArgs(z), UTF_8)));
                            }
                            print("   Transaction action %d proposal response status: %d", j,
                                    transactionActionInfo.getProposalResponseStatus());
                            print("   Transaction action %d proposal response payload: %s", j,
                                    printableString(new String(transactionActionInfo.getProposalResponsePayload())));

                            String chaincodeIDName = transactionActionInfo.getChaincodeIDName();
                            String chaincodeIDVersion = transactionActionInfo.getChaincodeIDVersion();
                            String chaincodeIDPath = transactionActionInfo.getChaincodeIDPath();
                            print("   Transaction action %d proposal chaincodeIDName: %s, chaincodeIDVersion: %s,  chaincodeIDPath: %s ", j,
                                    chaincodeIDName, chaincodeIDVersion, chaincodeIDPath);

                            // Check to see if we have our expected event.
                            if (blockNumber == 2) {
                                ChaincodeEvent chaincodeEvent = transactionActionInfo.getEvent();
                                assertNotNull(chaincodeEvent);

                                assertTrue(Arrays.equals(EXPECTED_EVENT_DATA, chaincodeEvent.getPayload()));
                                assertEquals(testTxID, chaincodeEvent.getTxId());
                                assertEquals(CHAIN_CODE_NAME, chaincodeEvent.getChaincodeId());
                                assertEquals(EXPECTED_EVENT_NAME, chaincodeEvent.getEventName());
                                assertEquals(CHAIN_CODE_NAME, chaincodeIDName);
                                assertEquals("github.com/example_cc", chaincodeIDPath);
                                assertEquals("1", chaincodeIDVersion);
                            }

                            TxReadWriteSetInfo rwsetInfo = transactionActionInfo.getTxReadWriteSet();
                            if (null != rwsetInfo) {
                                print("   Transaction action %d has %d name space read write sets", j, rwsetInfo.getNsRwsetCount());

                                for (TxReadWriteSetInfo.NsRwsetInfo nsRwsetInfo : rwsetInfo.getNsRwsetInfos()) {
                                    final String namespace = nsRwsetInfo.getNamespace();
                                    KvRwset.KVRWSet rws = nsRwsetInfo.getRwset();

                                    int rs = -1;
                                    for (KvRwset.KVRead readList : rws.getReadsList()) {
                                        rs++;

                                        print("     Namespace %s read set %d key %s  version [%d:%d]", namespace, rs, readList.getKey(),
                                                readList.getVersion().getBlockNum(), readList.getVersion().getTxNum());

                                        if ("bar".equals(channelId) && blockNumber == 2) {
                                            if ("example_cc_go".equals(namespace)) {
                                                if (rs == 0) {
                                                    assertEquals("a", readList.getKey());
                                                    assertEquals(1, readList.getVersion().getBlockNum());
                                                    assertEquals(0, readList.getVersion().getTxNum());
                                                } else if (rs == 1) {
                                                    assertEquals("b", readList.getKey());
                                                    assertEquals(1, readList.getVersion().getBlockNum());
                                                    assertEquals(0, readList.getVersion().getTxNum());
                                                } else {
                                                    fail(format("unexpected readset %d", rs));
                                                }

                                                TX_EXPECTED.remove("readset1");
                                            }
                                        }
                                    }

                                    rs = -1;
                                    for (KvRwset.KVWrite writeList : rws.getWritesList()) {
                                        rs++;
                                        String valAsString = printableString(new String(writeList.getValue().toByteArray(), UTF_8));

                                        print("     Namespace %s write set %d key %s has value '%s' ", namespace, rs,
                                                writeList.getKey(),
                                                valAsString);

                                        if ("bar".equals(channelId) && blockNumber == 2) {
                                            if (rs == 0) {
                                                assertEquals("a", writeList.getKey());
                                                assertEquals("400", valAsString);
                                            } else if (rs == 1) {
                                                assertEquals("b", writeList.getKey());
                                                assertEquals("400", valAsString);
                                            } else {
                                                fail(format("unexpected writeset %d", rs));
                                            }

                                            TX_EXPECTED.remove("writeset1");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    assertEquals(transactionCount, returnedBlock.getTransactionCount());
                }
            }
            if (!TX_EXPECTED.isEmpty()) {
                fail(TX_EXPECTED.get(0));
            }
        } catch (InvalidProtocolBufferRuntimeException e) {
            throw e.getCause();
        }
    }

    /**
     * 输出
     */
    static void print(String note, String format, Object... args) {
        System.err.flush();
        System.out.flush();
        System.out.println("***" + note + "***: " + format(format, args));
        System.err.flush();
        System.out.flush();
    }

    /**
     * 输出
     */
    static void print(String format, Object... args) {
        System.err.flush();
        System.out.flush();
        System.out.println("***Logger***: " + format(format, args));
        System.err.flush();
        System.out.flush();
    }


    static String printableString(final String string) {
        int maxLogStringLength = 64;
        if (string == null || string.length() == 0) {
            return string;
        }
        String res = string.replaceAll("[^\\p{Print}]", "?");
        res = res.substring(0, Math.min(res.length(), maxLogStringLength)) + (res.length() > maxLogStringLength ? "..." : "");
        return res;
    }

    // A test class to capture chaincode events 用于捕获链码事件的测试类
    class ChaincodeEventCapture {
        // 处理
        final String handle;
        // 区块事件
        final BlockEvent blockEvent;
        // 链码事件
        final ChaincodeEvent chaincodeEvent;

        // 构造器
        ChaincodeEventCapture(String handle, BlockEvent blockEvent, ChaincodeEvent chaincodeEvent) {
            this.handle = handle;
            this.blockEvent = blockEvent;
            this.chaincodeEvent = chaincodeEvent;
        }

    }

    public static void main(String[] args) {
        new FabricCoreTestJavaChainCode().init();
    }


}
