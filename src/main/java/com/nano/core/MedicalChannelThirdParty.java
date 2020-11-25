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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
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
import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.fabric.sdk.BlockInfo.EnvelopeType.TRANSACTION_ENVELOPE;
import static org.hyperledger.fabric.sdk.Channel.NOfEvents.createNofEvents;
import static org.hyperledger.fabric.sdk.Channel.PeerOptions.createPeerOptions;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * The full process of the procedure.
 *
 * @author nano
 */
@Component
public class MedicalChannelThirdParty {

    private static final Logger logger = LoggerFactory.getLogger("ChannelThirdParty");

    /**
     * 测试配置
     */
    private final MedicalConfig medicalConfig = MedicalConfig.getConfig();

    /**
     * 随机数生成器
     */
    private static final Random random = new Random();


    private static final byte[] EXPECTED_EVENT_DATA = "!".getBytes(UTF_8);
    private static final String EXPECTED_EVENT_NAME = "event";
    private static final Map<String, String> TX_EXPECTED;

    /**
     * 链码相关配置
     */
//    private static final String CHAIN_CODE_FILEPATH = "sdkintegration/gocc/sample1";
//    private static final String CHAIN_CODE_NAME = "example_cc_go";
//    private static final String CHAIN_CODE_PATH = "github.com/example_cc";
//    private static final String CHAIN_CODE_VERSION = "1";
//    private static final Type CHAIN_CODE_LANG = Type.GO_LANG;


    /**
     * 链码相关配置
     */
    private static final String CHAIN_CODE_FILEPATH = "sdkintegration/gocc/thirdparty";
    private static final String CHAIN_CODE_NAME = "datause_cc_go";
    private static final String CHAIN_CODE_PATH = "github.com/example_cc";
    private static final String CHAIN_CODE_VERSION = "1";
    private static final Type CHAIN_CODE_LANG = Type.GO_LANG;


    // 静态初始化
    static {
        TX_EXPECTED = new HashMap<>();
        TX_EXPECTED.put("readset1", "Missing readset for channel bar block 1");
        TX_EXPECTED.put("writeset1", "Missing writeset for channel bar block 1");
    }

    /***
     * 配置帮助器
     */
    private final MedicalConfigHelper configHelper = new MedicalConfigHelper();

    /**
     * 测试的TransactionId
     */
    private String testTxId = null;

    /**
     * 文件本地键值对存储
     */
    private LocalStore localStore = null;

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
    public HFClient fabricClientThirdParty;

    /**
     * Foo通道对象
     */
    public Channel channelThirdParty;

    /**
     * 链码ID对象
     */
    public ChaincodeID chaincodeId;


    /**
     * 链码ID对象(DataUse链码)
     */
    public ChaincodeID chaincodeIdDataUse;


    /**
     * 客户端TLS属性
     */
    Map<String, Properties> clientTLSProperties = new HashMap<>();


    /**
     * 两个组织
     */
    private Organization organizationPatient;
    private Organization organizationThirdParty;


    // 链码事件列表
    // Test list to capture chaincode events.
    List<ChaincodeEventCapture> chaincodeEventList = new LinkedList<>();

    /**
     * 链码事件监听器处理器
     */
    String chaincodeEventListenerHandler;

    /**
     * 是否已经初始化
     */
    private boolean isInit = false;


    public static void main(String[] args) {
        new MedicalChannelThirdParty().init();
    }

    /**
     * 初始化方法
     */
    public void init() {
        try {
            logger.info("开始初始化配置.");
            // 初始化配置
            initConfig();
            logger.info("完成初始化配置.");
            // 持久化不是SDK的一部分,生产环境别用SampleFile这个类,需要自己做实现!!!!!!
            // 每次都删除掉之前的存储文件
            File localStoreFilePath = new File(MedicalConfig.FIXTURES_PATH + "/HFCSampletest.properties");
            if (localStoreFilePath.exists()) {
                localStoreFilePath.delete();
            }
            localStore = new LocalStore(localStoreFilePath);
            // This enrolls users with fabric ca and setups sample store to get users later.
            // enrollAndRegisterUsers(sampleStore);
            // 分别为两个组织注册用户信息(AdminUser, NormalUser, AdminPeer)
            registerAndEnrollForOrg(localStore, organizationPatient);
            registerAndEnrollForOrg(localStore, organizationThirdParty);

            // 创建Fabric客户端,设置加密套件
            fabricClientThirdParty = HFClient.createNewInstance();
            fabricClientThirdParty.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

            // 构造FooChannel
            channelThirdParty = buildPatientChannel();

            // 将创建好的通道对象存入本地
            localStore.saveChannel(channelThirdParty);

            // 注册一个链码事件监听器
            String chaincodeEventListenerHandler = channelThirdParty.registerChaincodeEventListener(
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
            initChainCodeIdTest();


            // 安装链码
            installChaincodePatient();

            Thread.sleep(2000);

            // 实例化链码
            instantiateChaincode();

            Thread.sleep(2000);

            // 转账操作
            transferMoney();

            // 进行查询
            queryLedger();

            // 查询账本信息
            queryLedgerInfo();
            logger.info("Finished all the steps.");
        } catch (Exception e) {
            print("Caught an exception running channel %s", channelThirdParty.getName());
            e.printStackTrace();
            fail("Test failed with error : " + e.getMessage());
        }
    }


    /**
     * 查询区块信息
     */
    private void queryLedgerInfo() throws Exception {
        // 获取通道名称
        final String channelName = channelThirdParty.getName();
        // 查询区块链信息
        BlockchainInfo channelInfo = channelThirdParty.queryBlockchainInfo();
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
        BlockInfo returnedBlock = channelThirdParty.queryBlockByNumber(channelInfo.getHeight() - 1);
        String previousHash = Hex.encodeHexString(returnedBlock.getPreviousHash());
        print("queryBlockByNumber returned correct block with blockNumber " + returnedBlock.getBlockNumber()
                + " \n previous_hash " + previousHash);
        assertEquals(channelInfo.getHeight() - 1, returnedBlock.getBlockNumber());
        assertEquals(chainPreviousHash, previousHash);

        // Query by block hash. Using latest block's previous hash so should return block number 1
        // 通过区块Hash查询
        byte[] hashQuery = returnedBlock.getPreviousHash();
        returnedBlock = channelThirdParty.queryBlockByHash(hashQuery);
        print("queryBlockByHash returned block with blockNumber " + returnedBlock.getBlockNumber());
        assertEquals(channelInfo.getHeight() - 2, returnedBlock.getBlockNumber());

        // Query block by TxID. Since it's the last TxID, should be block 2
        // 通过交易Id查询区块
        returnedBlock = channelThirdParty.queryBlockByTransactionID(testTxId);
        print("queryBlockByTxID returned block with blockNumber " + returnedBlock.getBlockNumber());
        assertEquals(channelInfo.getHeight() - 1, returnedBlock.getBlockNumber());

        // query transaction by ID
        // 通过交易ID查询交易
        TransactionInfo txInfo = channelThirdParty.queryTransactionByID(testTxId);
        print("QueryTransactionByID returned TransactionInfo: txID " + txInfo.getTransactionID()
                + "\n validation code " + txInfo.getValidationCode().getNumber());

        if (chaincodeEventListenerHandler != null) {
            // 取消注册链码事件监听器
            channelThirdParty.unregisterChaincodeEventListener(chaincodeEventListenerHandler);
            // Should be two. One event in chaincode and two notification for each of the two event hubs
            final int numberEventsExpected = channelThirdParty.getEventHubs().size() + channelThirdParty.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)).size();
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
                assertEquals(testTxId, chaincodeEventCapture.chaincodeEvent.getTxId());
                assertEquals(EXPECTED_EVENT_NAME, chaincodeEventCapture.chaincodeEvent.getEventName());
                assertTrue(Arrays.equals(EXPECTED_EVENT_DATA, chaincodeEventCapture.chaincodeEvent.getPayload()));
                assertEquals(CHAIN_CODE_NAME, chaincodeEventCapture.chaincodeEvent.getChaincodeId());

                // 获取区块事件
                BlockEvent blockEvent = chaincodeEventCapture.blockEvent;
                assertEquals(channelName, blockEvent.getChannelId());
            }
        }

    }


    /**
     * 进行转账
     */
    public void transferMoney() throws Exception {
        // 设置成普通的用户!!!
        fabricClientThirdParty.setUserContext(organizationPatient.getUser(normalUser1));
        // 构造交易提案请求
        TransactionProposalRequest transactionProposalRequest = fabricClientThirdParty.newTransactionProposalRequest();
        // 设置需要执行的链码ID
        transactionProposalRequest.setChaincodeID(chaincodeId);
        // 链码语言
        transactionProposalRequest.setChaincodeLanguage(CHAIN_CODE_LANG);
        //transactionProposalRequest.setFcn("invoke");
        transactionProposalRequest.setFcn("move");
        transactionProposalRequest.setProposalWaitTime(medicalConfig.getProposalWaitTime());
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
        if (Type.GO_LANG.equals(CHAIN_CODE_LANG) && medicalConfig.isFabricVersionAtOrAfter("1.2")) {
            // the chaincode will return this as status see chaincode why.
            expectedMoveRCMap.put(MedicalConfig.CHANNEL_NAME_THIRD_PARTY, random.nextInt(300) + 100L);
            // This should be returned see chaincode why.
            tm2.put("rc", (expectedMoveRCMap.get(MedicalConfig.CHANNEL_NAME_THIRD_PARTY) + "").getBytes(UTF_8));
            // 400 and above results in the peer not endorsing!
        } else {
            // not really supported for Java or Node.
            // 对Java或Go不太支持
            expectedMoveRCMap.put(MedicalConfig.CHANNEL_NAME_THIRD_PARTY, 200L);
        }
        // This should trigger an event see chaincode why.
        tm2.put(EXPECTED_EVENT_NAME, EXPECTED_EVENT_DATA);
        transactionProposalRequest.setTransientMap(tm2);

        logger.info("Sending transactionProposal to all peers with arguments: move(a,b,100)");


        // Collection<ProposalResponse> transactionPropResp = channel.sendTransactionProposalToEndorsers(transactionProposalRequest);
        // 往所有的Peer结点发送交易并得到响应
        Collection<ProposalResponse> transactionResponse = channelThirdParty.sendTransactionProposal(transactionProposalRequest, channelThirdParty.getPeers());
        Collection<ProposalResponse> successResponseList = new HashSet<>();
        Collection<ProposalResponse> failedResponseList = new HashSet<>();
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
        assertEquals(expectedMoveRCMap.get(MedicalConfig.CHANNEL_NAME_THIRD_PARTY).longValue(), successResponse.getChaincodeActionResponseStatus());

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
        BlockEvent.TransactionEvent transactionEvent = channelThirdParty.sendTransaction(successResponseList).get(32000, TimeUnit.SECONDS);

        // 记录一下ID,方便后面的查询
        testTxId = transactionEvent.getTransactionID();
        logger.info("Finished transaction with transaction id " + transactionEvent.getTransactionID());
    }


    /**
     * 安装链码
     */
    private void installChaincodePatient() {
        logger.info("开始安装链码.");
        try {
            // 判断当前链码是否已经被安装了
            for (String chainCodeName : channelThirdParty.getDiscoveredChaincodeNames()) {
                // 如果已经安装了链码
                if (CHAIN_CODE_NAME.equals(chainCodeName)) {
                    logger.info("The chaincode " + CHAIN_CODE_NAME + " is already installed.");
                    return;
                }
            }
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 下面由PatientPeerAdmin进行链码安装操作
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 设置当前客户端的操作人为Admin Peer结点
            fabricClientThirdParty.setUserContext(organizationPatient.getAdminPeer());
            // 构造链码安装请求
            InstallProposalRequest installProposalRequestPatient = fabricClientThirdParty.newInstallProposalRequest();
            // 传入上面生成的链码ID
            installProposalRequestPatient.setChaincodeID(chaincodeId);
            installProposalRequestPatient.setChaincodeSourceLocation(Paths.get(MedicalConfig.FIXTURES_PATH, CHAIN_CODE_FILEPATH).toFile());
            // 这里设置索引配置文件的路径
            installProposalRequestPatient.setChaincodeMetaInfLocation(new File("src/test/fixture/meta-infs/end2endit"));
            // 设置链码版本与语言
            installProposalRequestPatient.setChaincodeVersion(CHAIN_CODE_VERSION);
            installProposalRequestPatient.setChaincodeLanguage(CHAIN_CODE_LANG);

            // 获取通道中的全部Peer结点
            Collection<Peer> peersAll = channelThirdParty.getPeers();
            Collection<Peer> orgPatientPeers = new HashSet<>();
            Collection<Peer> orgThirdPartyPeers = new HashSet<>();
            for (Peer peer : peersAll) {
                logger.info("当前通道的Peer:" + peer.getName());
                // 将Peer归类
                if (peer.getName().contains("orgthirdparty")) {
                    orgThirdPartyPeers.add(peer);
                } else {
                    orgPatientPeers.add(peer);
                }
            }
            logger.info("PatientOrg发送链码安装Proposal.");
            // 发送链码安装请求并得到响应(先发送Patient组织的)
            Collection<ProposalResponse> patientResponse = fabricClientThirdParty.sendInstallProposal(installProposalRequestPatient, orgPatientPeers);
            int failResponseCounter = 0;
            for (ProposalResponse response : patientResponse) {
                // 安装成功
                if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    logger.info("成功收到链码安装提案: " + response.getTransactionID() + " " + response.getPeer().getName());
                } else {
                    logger.info("失败收到链码安装提案: " + response.getTransactionID() + " " + response.getPeer().getName());
                    failResponseCounter++;
                }
            }

            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 下面由ThirdPartyPeerAdmin进行链码安装操作
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 切换为组织ThirdParty的AdminPeer
            logger.info("当前操作的用户:" + organizationThirdParty.getAdminPeer().toString());
            fabricClientThirdParty.setUserContext(organizationThirdParty.getAdminPeer());

            // 构造链码安装请求
            InstallProposalRequest installProposalRequestThirdParty = fabricClientThirdParty.newInstallProposalRequest();
            // 传入上面生成的链码ID
            installProposalRequestThirdParty.setChaincodeID(chaincodeId);
            installProposalRequestThirdParty.setChaincodeSourceLocation(Paths.get(MedicalConfig.FIXTURES_PATH, CHAIN_CODE_FILEPATH).toFile());
            // 这里设置索引配置文件的路径
            installProposalRequestThirdParty.setChaincodeMetaInfLocation(new File("src/test/fixture/meta-infs/end2endit"));
            // 设置链码版本设置链码语言
            installProposalRequestThirdParty.setChaincodeVersion(CHAIN_CODE_VERSION);
            installProposalRequestThirdParty.setChaincodeLanguage(CHAIN_CODE_LANG);

            logger.info("ThirdParty发送链码安装Proposal.");
            Collection<ProposalResponse> thirdPartyResponse = fabricClientThirdParty.sendInstallProposal(installProposalRequestThirdParty, orgThirdPartyPeers);
            for (ProposalResponse response : thirdPartyResponse) {
                // 安装成功
                if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    logger.info("成功收到链码安装提案: " + response.getTransactionID() + " " + response.getPeer().getName());
                } else {
                    logger.info("失败成功收到链码安装提案: " + response.getTransactionID() + " " + response.getPeer().getName());
                    failResponseCounter++;
                }
            }
            // 如果有失败的情况
            if (failResponseCounter > 0) {
                throw new RuntimeException("链码安装失败");
            }
            // 安装链码不需要发送交易到Orderer结点
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * 安装链码(PatientData)
     */
    private void installChaincodePatientData() {
        logger.info("开始安装Patient链码.");
        try {
            // 判断当前链码是否已经被安装了
            for (String chainCodeName : channelThirdParty.getDiscoveredChaincodeNames()) {
                // 如果已经安装了链码
                if (CHAIN_CODE_NAME.equals(chainCodeName)) {
                    logger.info("The chaincode " + CHAIN_CODE_NAME + " is already installed.");
                    return;
                }
            }
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 下面由PatientPeerAdmin进行链码安装操作
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 设置当前客户端的操作人为Admin Peer结点
            fabricClientThirdParty.setUserContext(organizationPatient.getAdminPeer());
            // 构造链码安装请求
            InstallProposalRequest installProposalRequestPatient = fabricClientThirdParty.newInstallProposalRequest();
            // 传入上面生成的链码ID
            installProposalRequestPatient.setChaincodeID(chaincodeId);
            installProposalRequestPatient.setChaincodeSourceLocation(Paths.get(MedicalConfig.FIXTURES_PATH, CHAIN_CODE_FILEPATH).toFile());
            // 这里设置索引配置文件的路径
            installProposalRequestPatient.setChaincodeMetaInfLocation(new File("src/test/fixture/meta-infs/end2endit"));
            // 设置链码版本与语言
            installProposalRequestPatient.setChaincodeVersion(CHAIN_CODE_VERSION);
            installProposalRequestPatient.setChaincodeLanguage(CHAIN_CODE_LANG);

            // 获取通道中的全部Peer结点
            Collection<Peer> peersAll = channelThirdParty.getPeers();
            Collection<Peer> orgPatientPeers = new HashSet<>();
            Collection<Peer> orgThirdPartyPeers = new HashSet<>();
            for (Peer peer : peersAll) {
                logger.info("当前通道的Peer:" + peer.getName());
                // 将Peer归类
                if (peer.getName().contains("orgthirdparty")) {
                    orgThirdPartyPeers.add(peer);
                } else {
                    orgPatientPeers.add(peer);
                }
            }
            logger.info("PatientOrg发送链码安装Proposal.");
            // 发送链码安装请求并得到响应(先发送Patient组织的)
            Collection<ProposalResponse> patientResponse = fabricClientThirdParty.sendInstallProposal(installProposalRequestPatient, orgPatientPeers);
            int failResponseCounter = 0;
            for (ProposalResponse response : patientResponse) {
                // 安装成功
                if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    logger.info("成功收到链码安装提案: " + response.getTransactionID() + " " + response.getPeer().getName());
                } else {
                    logger.info("失败收到链码安装提案: " + response.getTransactionID() + " " + response.getPeer().getName());
                    failResponseCounter++;
                }
            }

            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 下面由ThirdPartyPeerAdmin进行链码安装操作
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 切换为组织ThirdParty的AdminPeer
            logger.info("当前操作的用户:" + organizationThirdParty.getAdminPeer().toString());
            fabricClientThirdParty.setUserContext(organizationThirdParty.getAdminPeer());

            // 构造链码安装请求
            InstallProposalRequest installProposalRequestThirdParty = fabricClientThirdParty.newInstallProposalRequest();
            // 传入上面生成的链码ID
            installProposalRequestThirdParty.setChaincodeID(chaincodeId);
            installProposalRequestThirdParty.setChaincodeSourceLocation(Paths.get(MedicalConfig.FIXTURES_PATH, CHAIN_CODE_FILEPATH).toFile());
            // 这里设置索引配置文件的路径
            installProposalRequestThirdParty.setChaincodeMetaInfLocation(new File("src/test/fixture/meta-infs/end2endit"));
            // 设置链码版本设置链码语言
            installProposalRequestThirdParty.setChaincodeVersion(CHAIN_CODE_VERSION);
            installProposalRequestThirdParty.setChaincodeLanguage(CHAIN_CODE_LANG);

            logger.info("ThirdParty发送链码安装Proposal.");
            Collection<ProposalResponse> thirdPartyResponse = fabricClientThirdParty.sendInstallProposal(installProposalRequestThirdParty, orgThirdPartyPeers);
            for (ProposalResponse response : thirdPartyResponse) {
                // 安装成功
                if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    logger.info("成功收到链码安装提案: " + response.getTransactionID() + " " + response.getPeer().getName());
                } else {
                    logger.info("失败成功收到链码安装提案: " + response.getTransactionID() + " " + response.getPeer().getName());
                    failResponseCounter++;
                }
            }
            // 如果有失败的情况
            if (failResponseCounter > 0) {
                throw new RuntimeException("链码安装失败");
            }
            // 安装链码不需要发送交易到Orderer结点
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 实例化链码
     */
    private void instantiateChaincode() throws Exception {
        logger.info("**************************************************************************");
        logger.info("准备实例化链码...");
        Collection<Peer> peersAll = channelThirdParty.getPeers();
        Collection<Peer> patientPeers = new HashSet<>();
        Collection<Peer> thirdPartyPeers = new HashSet<>();
        for (Peer peer : peersAll) {
            if (peer.getName().contains("orgthirdparty")) {
                thirdPartyPeers.add(peer);
            } else {
                patientPeers.add(peer);
            }
        }

        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // 下面由PatientPeerAdmin进行链码安装操作
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        logger.info("使用发送实例化请求: " + organizationPatient.getAdminPeer().getName());
        fabricClientThirdParty.setUserContext(organizationPatient.getAdminPeer());
        // 构造实例化链码请求
        InstantiateProposalRequest instantiateProposalRequestPatient = fabricClientThirdParty.newInstantiationProposalRequest();
        // 设置链码实例化属性
        instantiateProposalRequestPatient.setProposalWaitTime(medicalConfig.getDeployWaitTime());
        instantiateProposalRequestPatient.setChaincodeID(chaincodeId);
        instantiateProposalRequestPatient.setChaincodeLanguage(CHAIN_CODE_LANG);
        // 指定实例化的init方法
        instantiateProposalRequestPatient.setFcn("init");
        // 设置实例化的参数(这里设置每个用户初始有多少钱)
        instantiateProposalRequestPatient.setArgs("a", "500", "b", "200");
        // 母鸡在干啥
        Map<String, byte[]> tm = new HashMap<>();
        tm.put("HyperLedgerFabric", "InstantiateProposalRequest:JavaSDK".getBytes(UTF_8));
        tm.put("method", "InstantiateProposalRequest".getBytes(UTF_8));
        instantiateProposalRequestPatient.setTransientMap(tm);
        // 这里指定背书策略！！！！构造链码背书对象
        ChaincodeEndorsementPolicy endorsementPolicy = new ChaincodeEndorsementPolicy();
        // 从YAML文件读取背书策略(!!!!!!!!!!!!)
        endorsementPolicy.fromYamlFile(new File("src/test/fixture/sdkintegration/chaincodeendorsementpolicy-medical.yaml"));
        instantiateProposalRequestPatient.setChaincodeEndorsementPolicy(endorsementPolicy);

        logger.info("使用Patient发送实例化请求.");
        Collection<ProposalResponse> patientResponse = channelThirdParty.sendInstantiationProposal(instantiateProposalRequestPatient, patientPeers);

        int failResponseCounter = 0;

        // 分析实例化提案的响应结果
        for (ProposalResponse response : patientResponse) {
            if (response.isVerified() && response.getStatus() == ProposalResponse.Status.SUCCESS) {
                logger.info("成功实例化链码, response TxId: %s from peer %s" + response.getTransactionID() + "  " + response.getPeer().getName());
            } else {
                logger.info("失败实例化链码, response TxId: %s from peer %s" + response.getTransactionID() + "  " + response.getPeer().getName());
                failResponseCounter++;
            }
        }

        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // 下面由ThirdPartyPeerAdmin进行链码安装操作
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        logger.info("使用ThirdParty发送实例化请求: " + organizationThirdParty.getAdminPeer().getName());
        fabricClientThirdParty.setUserContext(organizationThirdParty.getAdminPeer());
        // 构造实例化链码请求
        InstantiateProposalRequest instantiateProposalRequestThirdParty = fabricClientThirdParty.newInstantiationProposalRequest();
        // 设置链码实例化属性
        instantiateProposalRequestThirdParty.setProposalWaitTime(medicalConfig.getDeployWaitTime());
        instantiateProposalRequestThirdParty.setChaincodeID(chaincodeId);
        instantiateProposalRequestThirdParty.setChaincodeLanguage(CHAIN_CODE_LANG);
        // 指定实例化的init方法
        instantiateProposalRequestThirdParty.setFcn("init");
        instantiateProposalRequestThirdParty.setArgs("a", "500", "b", "200");
        // 母鸡在干啥
        Map<String, byte[]> tm2 = new HashMap<>();
        tm2.put("HyperLedgerFabric", "InstantiateProposalRequest:JavaSDK".getBytes(UTF_8));
        tm2.put("method", "InstantiateProposalRequest".getBytes(UTF_8));
        instantiateProposalRequestThirdParty.setTransientMap(tm2);

        // 这里指定背书策略！！！！构造链码背书对象
        ChaincodeEndorsementPolicy endorsementPolicyThirdParty = new ChaincodeEndorsementPolicy();
        // 从YAML文件读取背书策略(!!!!!!!!!!!!)
        endorsementPolicyThirdParty.fromYamlFile(new File("src/test/fixture/sdkintegration/chaincodeendorsementpolicy-medical.yaml"));
        instantiateProposalRequestThirdParty.setChaincodeEndorsementPolicy(endorsementPolicyThirdParty);

        Collection<ProposalResponse> thirdPartyResponse = channelThirdParty.sendInstantiationProposal(instantiateProposalRequestThirdParty, thirdPartyPeers);

        // 分析实例化提案的响应结果
        for (ProposalResponse response : thirdPartyResponse) {
            if (response.isVerified() && response.getStatus() == ProposalResponse.Status.SUCCESS) {
                logger.info("成功实例化链码, response TxId: %s from peer %s" + response.getTransactionID() + "  " + response.getPeer().getName());
                //print("成功实例化链码, response TxId: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
            } else {
                logger.info("失败实例化链码, response TxId: %s from peer %s" + response.getTransactionID() + "  " + response.getPeer().getName());
                failResponseCounter++;
            }
        }

        // 实例化失败
        if (failResponseCounter > 0) {
            throw new RuntimeException("链码实例化失败.");
        }

        // 下面将实例化成功的交易发送给Orderer
        logger.info("Sending 实例化交易 to orderer with a and b set to 100 and 200 respectively.");

        // 这里设置提交交易时感兴趣的事件
        Channel.NOfEvents nOfEvents = createNofEvents();
        if (!channelThirdParty.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)).isEmpty()) {
            nOfEvents.addPeers(channelThirdParty.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)));
        }
        if (!channelThirdParty.getEventHubs().isEmpty()) {
            nOfEvents.addEventHubs(channelThirdParty.getEventHubs());
        }
        logger.info("准备发送实例化成功的交易提案.");
        CompletableFuture<BlockEvent.TransactionEvent> futurePatient = channelThirdParty.sendTransaction(
                // 包含上面的成功响应结果集
                patientResponse, channelThirdParty.getOrderers());
        // 从发送交易中获取交易事件
        BlockEvent.TransactionEvent transactionEventPatient = futurePatient.get();
        // 交易事件必须是合法的
        assertTrue(transactionEventPatient.isValid());
        // 交易事件必须有签名
        assertNotNull(transactionEventPatient.getSignature());
        // 从交易事件获取区块事件
        BlockEvent blockEventPatient = transactionEventPatient.getBlockEvent();
        // 保证能够获取区块
        assertNotNull(blockEventPatient.getBlock());
    }


    /**
     * 查询方法
     */
    public void queryLedger() {
        try {
            logger.info("查询账户B的余额...");
            // 构造查询请求
            QueryByChaincodeRequest queryRequest = fabricClientThirdParty.newQueryProposalRequest();
            // 设置参数
            queryRequest.setArgs("b");
            // 设置调用方法
            queryRequest.setFcn("query");
            // 设置链码Id
            queryRequest.setChaincodeID(chaincodeId);
            // 不知道在干啥
            Map<String, byte[]> tm2 = new HashMap<>();
            tm2.put("HyperLedgerFabric", "QueryByChaincodeRequest:JavaSDK".getBytes(UTF_8));
            tm2.put("method", "QueryByChaincodeRequest".getBytes(UTF_8));
            queryRequest.setTransientMap(tm2);

            // 发送查询请求并获取响应结果
            Collection<ProposalResponse> queryResponses = channelThirdParty.queryByChaincode(queryRequest, channelThirdParty.getPeers());
            // 分析响应结果
            for (ProposalResponse proposalResponse : queryResponses) {
                // 查询不成功
                if (!proposalResponse.isVerified() || proposalResponse.getStatus() != ProposalResponse.Status.SUCCESS) {
                    fail("Failed query proposal from peer " + proposalResponse.getPeer().getName() + " status: " + proposalResponse.getStatus() +
                            ". Messages: " + proposalResponse.getMessage() + ". Was verified : " + proposalResponse.isVerified());
                    throw new RuntimeException("查询操作失败...");
                } else {
                    // 查询成功,获取返回的数据
                    String payload = proposalResponse.getProposalResponse().getResponse().getPayload().toStringUtf8();
                    logger.info(proposalResponse.getTransactionID());
                    logger.info(proposalResponse.getMessage());
                    logger.info("余额为: " + payload);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * 测试之前执行的默认配置
     */
    public void initConfig() {
        try {
            resetConfig();
            configHelper.customizeConfig();
            // 获取组织的Set
            organizationSet = medicalConfig.getOrganizationSet();
            logger.info("当前组织数: " + organizationSet.size());
            // 将组织对象映射到本类中
            organizationPatient = medicalConfig.getOrganizationMap().get("peerOrgPatient");
            organizationThirdParty = medicalConfig.getOrganizationMap().get("peerOrgThirdParty");
            String caNamePatient = organizationPatient.getCAName();
            logger.info("组织PatientCA名称: " + caNamePatient);
            // 构造组织1的CA代理对象
            HFCAClient caClientPatient = HFCAClient.createNewInstance(
                    // CA名称
                    caNamePatient,
                    // CA地址
                    organizationPatient.getCALocation(),
                    // CA属性
                    organizationPatient.getCAProperties());
            caClientPatient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
            organizationPatient.setCAClient(caClientPatient);

            // 构造组织ThirdParty的CA代理对象
            String caNameThirdParty = organizationThirdParty.getCAName();
            HFCAClient caClientThirdParty = HFCAClient.createNewInstance(
                    // CA名称
                    caNameThirdParty,
                    // CA地址
                    organizationThirdParty.getCALocation(),
                    // CA属性
                    organizationThirdParty.getCAProperties());
            caClientThirdParty.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
            organizationThirdParty.setCAClient(caClientThirdParty);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 构造通道
     */
    private Channel buildPatientChannel() {
        final String channelName = MedicalConfig.CHANNEL_NAME_THIRD_PARTY;
        try {
            // 创建Foo通道(完成网络中通道的创建与结点的加入)(仅使用了组织1创建?)
            logger.info("准备创建MyChannel");
            // 只有PeerAdmin能创建通道
            MedicalUser peerAdmin = organizationPatient.getAdminPeer();
            MedicalUser peerAdminThird = organizationThirdParty.getAdminPeer();
            logger.info("PeerAdmin用户信息:" + peerAdmin.toString());
            // 设置Fabric Client用户环境,也就是设置谁进行操作
            fabricClientThirdParty.setUserContext(peerAdmin);

            // Orderer结点
            Collection<Orderer> ordererCollection = new LinkedList<>();

            // 获取这个组织全部Orderer结点名称
            for (String orderName : organizationPatient.getOrdererNames()) {
                // 获取Orderer的属性
                Properties ordererProperties = medicalConfig.getOrdererProperties(orderName);
                for (String pro : ordererProperties.stringPropertyNames()) {
                    logger.info(orderName + "属性: " + pro + ": " + ordererProperties.getProperty(pro));
                }
                ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[]{5L, TimeUnit.MINUTES});
                ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[]{8L, TimeUnit.SECONDS});
                // 没有调用也会KeepAlive
                ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveWithoutCalls", new Object[]{true});

                // 构造Orderer对象
                // orderName = "orderer.example.com"
                // Location = "grpc://172.20.29.67:7050"
                // Property: {clientCertFile=D:\code\12_Paper\fabric-sdk-java\src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\ordererOrganizations\example.com\\users\Admin@example.com\tls\client.crt, sslProvider=openSSL, negotiationType=TLS, hostnameOverride=orderer.example.com, grpc.NettyChannelBuilderOption.keepAliveTime=[Ljava.lang.Object;@60f00693, grpc.NettyChannelBuilderOption.keepAliveTimeout=[Ljava.lang.Object;@79207381, grpc.NettyChannelBuilderOption.keepAliveWithoutCalls=[Ljava.lang.Object;@491b9b8, pemFile=D:\code\12_Paper\fabric-sdk-java\src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\ordererOrganizations\example.com\orderers\orderer.example.com\tls\server.crt, clientKeyFile=D:\code\12_Paper\fabric-sdk-java\src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\ordererOrganizations\example.com\\users\Admin@example.com\tls\client.key}
                logger.info("创建Orderer结点对象: " + orderName);
                Orderer orderer = fabricClientThirdParty.newOrderer(orderName, organizationPatient.getOrdererLocation(orderName), ordererProperties);
                logger.info("创建Orderer结点对象完成: " + orderName);
                // 将Orderer对象加入集合
                ordererCollection.add(orderer);
            }


            // 仅取集合中第一个Orderer创建通道
            Orderer anOrderer = ordererCollection.iterator().next();
            // 从集合中移除选中的这个Orderer
            ordererCollection.remove(anOrderer);
            // tx文件路径
            String path = "src/test/fixture/sdkintegration/e2e-2Orgs/v1.333/channelthirdparty.tx";
            // 通过tx文件对Channel进行配置
            ChannelConfiguration channelConfiguration = new ChannelConfiguration(new File(path));

            // 使用peerAdmin进行签名
            logger.info("使用peerAdmin进行签名");
            byte[] signature = fabricClientThirdParty.getChannelConfigurationSignature(channelConfiguration, peerAdmin);
            // Create channel that has only one signer that is this orgs peer admin. If channel creation policy needed more signature they would need to be added too.
            // 通过PeerAdmin创建channel
            logger.info("开始创建Channel: " + channelName);
            Channel newChannel = fabricClientThirdParty.newChannel(channelName, anOrderer, channelConfiguration, signature);
            logger.info("完成创建Channel: " + channelName);


            // 这里决定哪些Peer加入通道?
            // 获取组织的全部Peer结点
            logger.info("组织1加入Channel");
            for (String peerName : organizationPatient.getPeerNames()) {
                // 获取Peer的地址
                String peerLocation = organizationPatient.getPeerLocation(peerName);
                // 获取Peer结点的配置属性
                Properties peerProperties = medicalConfig.getPeerProperties(peerName);
                if (peerProperties == null) {
                    peerProperties = new Properties();
                }
                // 打印一下属性
                for (String property : peerProperties.stringPropertyNames()) {
                    logger.info(peerName + "属性: " + property, peerProperties.getProperty(property));
                }

                // Example of setting specific options on grpc's NettyChannelBuilder
                // 添加额外的属性
                peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);

                logger.info("构造Peer对象:" + peerName);
                // 逐一构造Peer结点对象
                Peer peer = fabricClientThirdParty.newPeer(peerName, peerLocation, peerProperties);
                logger.info("完成构造Peer对象:" + peerName);
                // 如果版本大于等于1.3
                if (medicalConfig.isFabricVersionAtOrAfter("1.3")) {
                    logger.info("当前Peer加入Channel:" + peerName);
                    // 将当前Peer结点加入Channel中
                    newChannel.joinPeer(peer, createPeerOptions()
                            // 默认拥有全部角色(四种角色)
                            .setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY, PeerRole.EVENT_SOURCE)));
                } else {
                }
                logger.info("Peer " + peerName + " joined channel " + channelName);
            }

            logger.info("组织2加入Channel");
            fabricClientThirdParty.setUserContext(peerAdminThird);
            for (String peerName : organizationThirdParty.getPeerNames()) {
                // 获取Peer的地址
                String peerLocation = organizationThirdParty.getPeerLocation(peerName);
                // 获取Peer结点的配置属性
                Properties peerProperties = medicalConfig.getPeerProperties(peerName);
                if (peerProperties == null) {
                    peerProperties = new Properties();
                }
                // 打印一下属性
                for (String property : peerProperties.stringPropertyNames()) {
                    logger.info(peerName + "属性: " + property, peerProperties.getProperty(property));
                }

                // Example of setting specific options on grpc's NettyChannelBuilder
                // 添加额外的属性
                peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);

                logger.info("构造Peer对象:" + peerName);
                // 逐一构造Peer结点对象
                Peer peer = fabricClientThirdParty.newPeer(peerName, peerLocation, peerProperties);
                logger.info("完成构造Peer对象:" + peerName);
                // 如果版本大于等于1.3
                if (medicalConfig.isFabricVersionAtOrAfter("1.3")) {
                    logger.info("当前Peer加入Channel:" + peerName);
                    // 将当前Peer结点加入Channel中
                    newChannel.joinPeer(peer, createPeerOptions()
                            // 默认拥有全部角色(四种角色)
                            .setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY, PeerRole.EVENT_SOURCE)));
                } else {

                }
                logger.info("Peer " + peerName + " joined channel " + channelName);
            }

            // 这里尝试加入Org2的结果失败了

            logger.info("全部Peer结点加入通道.");

            // add remaining orderers if any.
            // 将剩下的Order结点加入通道
            for (Orderer orderer : ordererCollection) {
                newChannel.addOrderer(orderer);
            }

            // 获取事件Hub的名称
            for (String eventHubName : organizationPatient.getEventHubNames()) {
                // 获取Peer结点配置信息
                final Properties eventHubProperties = medicalConfig.getEventHubProperties(eventHubName);
                eventHubProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[]{5L, TimeUnit.MINUTES});
                eventHubProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[]{8L, TimeUnit.SECONDS});
                EventHub eventHub = fabricClientThirdParty.newEventHub(eventHubName, organizationPatient.getEventHubLocation(eventHubName),
                        eventHubProperties);
                // 将EventHub加入通道中
                newChannel.addEventHub(eventHub);
            }
            logger.info("初始化通道." + channelName);
            // 初始化通道
            newChannel.initialize();
            logger.info("完成通道初始化." + channelName);
            return newChannel;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 为Fabric网络中节点配置TLS根证书
     *
     * @param certPath 根证书路径
     * @param hostName 节点域名
     */
    private static void loadTLSFile(String certPath, String hostName, Properties properties) throws IOException {
        // 其实只需要一个TLS根证书就可以了，比如TLS相关的秘钥等都是可选的
        properties.put("pemBytes", Files.readAllBytes(Paths.get(certPath)));
        properties.setProperty("sslProvider", "openSSL");
        properties.setProperty("negotiationType", "TLS");
        properties.setProperty("trustServerCertificate", "true");
        properties.setProperty("hostnameOverride", hostName);
    }


    /**
     * 构造链码安装对象
     */
    private void initChainCodeIdTest() {
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
     * 组织1的注册与登记
     *
     * @param localStore 持久化文件
     */
    private void registerAndEnrollForOrg(LocalStore localStore, Organization organization) {
        logger.info("开始为组织" + organization.name + "注册登记用户.");
        try {
            // 获取CA代理
            HFCAClient caClient = organization.getCAClient();
            // 获取组织名称
            final String orgName = organization.getName();
            // 获取组织MSPID
            final String mspId = organization.getMSPID();

            // "ca0.example.com"
            logger.info("CA代理的名称:" + caClient.info().getCAName());

            // 设置加密套件
            caClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
            // 判断是否开启了TLS(默认为false)
            if (true) {
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
            logger.info("Admin用户信息: " + admin.toString());
            // Preregistered admin only needs to be enrolled with Fabric caClient.
            // 如果Admin没有登记就进行登记
            if (!admin.isEnrolled()) {
                logger.info("登记AdminUser");
                // Admin登记(使用CA启动时的用户名与密码)
                Enrollment enrollment = caClient.enroll("admin", "adminpw");
                logger.info("AdminUser的私钥:" + enrollment.getKey().toString());
                admin.setEnrollment(enrollment);
                // 设置MSPID
                // Org1MSP Org2MSP
                admin.setMspId(mspId);
            }

            // 创建一个新的普通用户
            MedicalUser user = localStore.getUser(normalUser1, organization.getName());
            logger.info("普通用户信息: " + user.toString());
            // 对普通User用户进行登记与注册
            if (!user.isRegistered()) {
                logger.info("注册普通User");
                // 设置用户的名称及其所属组织属性
                RegistrationRequest registerRequest = new RegistrationRequest(user.getName());
                // 利用组织的Admin用户进行注册并获取登记密码
                String secret = caClient.register(registerRequest, admin);
                user.setEnrollmentSecret(secret);
            }
            // 用户登记
            if (!user.isEnrolled()) {
                logger.info("登记普通User");
                Enrollment enrollment = caClient.enroll(user.getName(), user.getEnrollmentSecret());
                user.setEnrollment(enrollment);
                // Org1MSP Org2MSP
                user.setMspId(mspId);
            }
            // 获取组织名称 peerOrg1 peerOrg2
            final String organizationName = organization.getName();
            // 组织域名 org1.example.com org2.example.com
            final String organizationDomainName = organization.getDomainName();
            logger.info("开始构造组织的PeerAdmin用户");

            // 获取组织的Admin结点(传入用户名,组织名,MSPID,私钥文件路径,证书文件路径)
            MedicalUser peerOrgAdmin = localStore.getUser(organizationName + "Admin", organizationName, organization.getMSPID(),
                    // 这里是私钥文件路径
                    // src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\peerOrganizations\
                    // org1.example.com\\users\Admin@org1.example.com\msp\keystore\581fa072e48dc2a516f664df94ea687447c071f89fc0b783b147956a08929dcc_sk
                    Util.findFileSk(Paths.get("src/test/fixture/sdkintegration/e2e-2Orgs/v1.333", "crypto-config/peerOrganizations/", organizationDomainName, format("/users/Admin@%s/msp/keystore", organizationDomainName)).toFile()),

                    // 这里是证书文件路径
                    // src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\peerOrganizations\
                    // org1.example.com\\users\Admin@org1.example.com\msp\signcerts\Admin@org1.example.com-cert.pem
                    Paths.get("src/test/fixture/sdkintegration/e2e-2Orgs/v1.333", "crypto-config/peerOrganizations/", organizationDomainName,
                            format("/users/Admin@%s/msp/signcerts/Admin@%s-cert.pem", organizationDomainName, organizationDomainName)).toFile());
            // A special user that can create channels, join peers and install chaincode

            // 将前面的几个用户加入到组织中
            // 创建当前组织的AdminPeer结点
            organization.setAdminPeer(peerOrgAdmin);
            // 将普通用户加入当前组织
            organization.addUser(user);
            // 将AdminUser用户加入当前组织
            organization.setAdminUser(admin);
            logger.info("完成组织用户加载.");
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
                    //assertTrue("foo".equals(channelId) || "bar".equals(channelId));

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
                                assertEquals(testTxId, chaincodeEvent.getTxId());
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
                // fail(TX_EXPECTED.get(0));
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
        System.out.println("Logger: " + format(format, args));
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


}

