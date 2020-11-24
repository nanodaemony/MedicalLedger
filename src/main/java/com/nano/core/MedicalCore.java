package com.nano.core;

import com.nano.chaincode.ChaincodeEntity;
import com.nano.chaincode.ChaincodeManager;

import org.hyperledger.fabric.sdk.BlockEvent;
import org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy;
import org.hyperledger.fabric.sdk.ChaincodeEvent;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.ChannelConfiguration;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.EventHub;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.InstallProposalRequest;
import org.hyperledger.fabric.sdk.InstantiateProposalRequest;
import org.hyperledger.fabric.sdk.Orderer;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.ProposalResponse;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.file.Paths;
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
import static org.hyperledger.fabric.sdk.Channel.NOfEvents.createNofEvents;
import static org.hyperledger.fabric.sdk.Channel.PeerOptions.createPeerOptions;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Description: Core class of the network.
 *
 * @version: 1.0
 * @author: nano
 * @date: 2020/11/24 15:57
 */
@Component
public class MedicalCore {

    private static Logger logger = LoggerFactory.getLogger("Medical Core");

    /**
     * 配置类
     */
    private static final MedicalConfig medicalConfig = MedicalConfig.getConfig();


    /**
     * 随机数生成器
     */
    private static final Random random = new Random();


    private static final byte[] EXPECTED_EVENT_DATA = "!".getBytes(UTF_8);
    private static final String EXPECTED_EVENT_NAME = "event";
    private static final Map<String, String> TX_EXPECTED;

    // 静态初始化
    static {
        TX_EXPECTED = new HashMap<>();
        TX_EXPECTED.put("readset1", "Missing readset for channel bar block 1");
        TX_EXPECTED.put("writeset1", "Missing writeset for channel bar block 1");
    }

    /**
     * 测试的TransactionId
     * save the CC invoke TxID and use in queries
     */
    private String testTxId = null;

    /**
     * 文件本地键值对存储
     */
    private LocalStore localStore = null;
    private File localStoreFilePath = new File("G:\\HFCSampletest.properties");

    /**
     * 组织集合
     */
    private Set<Organization> organizationSet;

    /**
     * 普通用户
     */
    static String normalUser = "user" + System.currentTimeMillis();


    /**
     * Foo通道对象
     */
    public Channel thirdPartyChannel;

    /**
     * Foo通道对象
     */
    public Channel patientChannel;

    /**
     * 客户端TLS属性
     */
    Map<String, Properties> clientTLSProperties = new HashMap<>();


    /**
     * 两个组织
     */
    private Organization organizationPatient;
    private Organization organizationThirdParty;


    /**
     * 链码事件列表
     */
    List<ChaincodeEventCapture> chaincodeEventList = new LinkedList<>();

    /**
     * 提交提案的响应集合
     */
    Collection<ProposalResponse> responseList = new LinkedList<>();
    Collection<ProposalResponse> successResponseList = new LinkedList<>();
    Collection<ProposalResponse> failedResponseList = new LinkedList<>();

    /**
     * 链码事件监听器处理器
     */
    String chaincodeEventListenerHandler;

    /**
     * 系统是否已经初始化
     */
    private static boolean isSystemInit = false;


    /**
     * 系统初始化
     */
    public void systemInit() {
        try {
            // 初始化配置
            initConfig();
            // 为组织注册并生成用户
            registerAndEnrollForOrganization(localStore, organizationPatient);
            registerAndEnrollForOrganization(localStore, organizationThirdParty);
            // 构造病人通道
            patientChannel = buildPatientChannel();
            // 构造第三方通道
            thirdPartyChannel = buildThirdPartyChannel();

            // 注册一个链码事件监听器
            String chaincodeEventListenerHandler = patientChannel.registerChaincodeEventListener(
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

            logger.info("系统初始化完成.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public void initChainCodeForPatient() {
        installChainCodeForPatient();
        instantiateChaincodeForPatient();
    }

    public void initChainCodeForThirdParty() {
        installChainCodeForThirdParty();
        instantiateChaincodeForThirdParty();
    }




    public HFClient getFabricClient() {
        try {
            logger.info("创建Fabric代理对象");
            HFClient fabricClient = HFClient.createNewInstance();
            fabricClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
            logger.info("创建Fabric代理对象完成");
            return fabricClient;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    public HFClient getFabricClient(MedicalUser user) {
        try {
            logger.info("创建Fabric代理对象");
            HFClient fabricClient = HFClient.createNewInstance();
            fabricClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
            fabricClient.setUserContext(user);
            logger.info("创建Fabric代理对象完成");
            return fabricClient;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 实例化链码(Patient)
     */
    private void instantiateChaincodeForPatient(){
        try {
            logger.info("\n\n\n");
            logger.info("准备实例化链码: Patient");

            ChaincodeEntity chaincodePatient = ChaincodeManager.chaincodeEntityPatient;

            // 将通道的eer结点分类
            Collection<Peer> patientPeers = new HashSet<>();
            Collection<Peer> thirdPartyPeers = new HashSet<>();
            for (Peer peer : patientChannel.getPeers()) {
                if (peer.getName().contains("orgthirdparty")) {
                    thirdPartyPeers.add(peer);
                } else {
                    patientPeers.add(peer);
                }
            }

            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 使用PatientAdminPeer操作
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            logger.info("使用发送实例化请求: " + organizationPatient.getAdminPeer().getName());
            HFClient fabricClient = getFabricClient(organizationPatient.getAdminPeer());
            // 构造实例化链码请求
            InstantiateProposalRequest instantiateProposalRequestPatient = fabricClient.newInstantiationProposalRequest();
            // 设置链码实例化属性
            instantiateProposalRequestPatient.setProposalWaitTime(medicalConfig.getDeployWaitTime());
            instantiateProposalRequestPatient.setChaincodeID(chaincodePatient.getChaincodeId());
            instantiateProposalRequestPatient.setChaincodeLanguage(chaincodePatient.getLanguage());
            // 指定实例化的init方法
            instantiateProposalRequestPatient.setFcn("init");
            // 设置实例化的参数(这里设置每个用户初始有多少钱)
            instantiateProposalRequestPatient.setArgs("a", "500", "b", "300");
            // 母鸡在干啥
            Map<String, byte[]> tm = new HashMap<>();
            tm.put("HyperLedgerFabric", "InstantiateProposalRequest:JavaSDK".getBytes(UTF_8));
            tm.put("method", "InstantiateProposalRequest".getBytes(UTF_8));
            instantiateProposalRequestPatient.setTransientMap(tm);
            // 这里指定背书策略！！！！构造链码背书对象
            ChaincodeEndorsementPolicy endorsementPolicy = new ChaincodeEndorsementPolicy();
            // 从YAML文件读取背书策略(!!!!!!!!!!!!)
            endorsementPolicy.fromYamlFile(new File(MedicalConfig.ENDORSEMENT_POLICY_PATH_PATIENT));
            instantiateProposalRequestPatient.setChaincodeEndorsementPolicy(endorsementPolicy);

            logger.info("使用PatientPeer发送实例化请求.");
            Collection<ProposalResponse> patientResponse = patientChannel.sendInstantiationProposal(instantiateProposalRequestPatient, patientPeers);
            int failedResponseCounter = 0;
            // 分析实例化提案的响应结果
            for (ProposalResponse response : patientResponse) {
                if (response.isVerified() && response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    logger.info("成功实例化链码, response TxId: %s from peer %s" + response.getTransactionID() + "  " + response.getPeer().getName());
                } else {
                    logger.info("失败实例化链码, response TxId: %s from peer %s" + response.getTransactionID() + "  " + response.getPeer().getName());
                    failedResponseCounter++;
                }
            }


            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 使用ThirdPartyAdminPeer操作
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            logger.info("使用ThirdParty发送实例化请求: " + organizationThirdParty.getAdminPeer().getName());
            fabricClient = getFabricClient(organizationThirdParty.getAdminPeer());
            // 构造实例化链码请求
            InstantiateProposalRequest instantiateProposalRequestThirdParty = fabricClient.newInstantiationProposalRequest();
            // 设置链码实例化属性
            instantiateProposalRequestThirdParty.setProposalWaitTime(medicalConfig.getDeployWaitTime());
            instantiateProposalRequestThirdParty.setChaincodeID(chaincodePatient.getChaincodeId());
            instantiateProposalRequestThirdParty.setChaincodeLanguage(chaincodePatient.getLanguage());
            // 指定实例化的init方法
            instantiateProposalRequestThirdParty.setFcn("init");
            // 设置实例化的参数(这里设置每个用户初始有多少钱)
            instantiateProposalRequestThirdParty.setArgs("a", "500", "b", "300");
            // 母鸡在干啥
            Map<String, byte[]> tm2 = new HashMap<>();
            tm2.put("HyperLedgerFabric", "InstantiateProposalRequest:JavaSDK".getBytes(UTF_8));
            tm2.put("method", "InstantiateProposalRequest".getBytes(UTF_8));
            instantiateProposalRequestThirdParty.setTransientMap(tm2);

            // 这里指定背书策略！！！！构造链码背书对象
            ChaincodeEndorsementPolicy endorsementPolicyThirdParty = new ChaincodeEndorsementPolicy();
            // 从YAML文件读取背书策略(!!!!!!!!!!!!)
            endorsementPolicyThirdParty.fromYamlFile(new File(MedicalConfig.ENDORSEMENT_POLICY_PATH_PATIENT));
            instantiateProposalRequestThirdParty.setChaincodeEndorsementPolicy(endorsementPolicyThirdParty);
            Collection<ProposalResponse> thirdPartyResponse = patientChannel.sendInstantiationProposal(instantiateProposalRequestThirdParty, thirdPartyPeers);

            // 分析实例化提案的响应结果
            for (ProposalResponse response : thirdPartyResponse) {
                if (response.isVerified() && response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    logger.info("成功实例化链码, response TxId: %s from peer %s" + response.getTransactionID() + "  " + response.getPeer().getName());
                    //print("成功实例化链码, response TxId: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                } else {
                    logger.info("失败实例化链码, response TxId: %s from peer %s" + response.getTransactionID() + "  " + response.getPeer().getName());
                    failedResponseCounter++;
                }
            }
            // 实例化失败
            if (failedResponseCounter > 0) {
                throw new RuntimeException("链码实例化失败.");
            }

            // 下面将实例化成功的交易发送给Orderer
            logger.info("发送实例化交易至Orderer");

            // 这里设置提交交易时感兴趣的事件
            Channel.NOfEvents nOfEvents = createNofEvents();
            if (!patientChannel.getPeers(EnumSet.of(Peer.PeerRole.EVENT_SOURCE)).isEmpty()) {
                nOfEvents.addPeers(patientChannel.getPeers(EnumSet.of(Peer.PeerRole.EVENT_SOURCE)));
            }
            if (!patientChannel.getEventHubs().isEmpty()) {
                nOfEvents.addEventHubs(patientChannel.getEventHubs());
            }

            logger.info("准备发送实例化成功的交易提案.");
            CompletableFuture<BlockEvent.TransactionEvent> future = patientChannel.sendTransaction(
                    // 包含上面的成功响应结果集
                    patientResponse, patientChannel.getOrderers());
            // 从发送交易中获取交易事件
            BlockEvent.TransactionEvent transactionEventPatient = future.get();
            // 交易事件必须是合法的
            assertTrue(transactionEventPatient.isValid());
            // 交易事件必须有签名
            assertNotNull(transactionEventPatient.getSignature());
            // 从交易事件获取区块事件
            BlockEvent blockEventPatient = transactionEventPatient.getBlockEvent();
            // 保证能够获取区块
            assertNotNull(blockEventPatient.getBlock());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * 实例化链码(Patient)
     */
    private void instantiateChaincodeForThirdParty() {
        try {
            logger.info("\n\n\n");
            logger.info("准备实例化链码: ThirdParty");

            ChaincodeEntity chaincode = ChaincodeManager.chaincodeEntityThirdParty;

            // 将通道的eer结点分类
            Collection<Peer> patientPeers = new HashSet<>();
            Collection<Peer> thirdPartyPeers = new HashSet<>();
            for (Peer peer : thirdPartyChannel.getPeers()) {
                if (peer.getName().contains("orgthirdparty")) {
                    thirdPartyPeers.add(peer);
                } else {
                    patientPeers.add(peer);
                }
            }

            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 使用PatientAdminPeer操作
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            logger.info("使用发送实例化请求: " + organizationPatient.getAdminPeer().getName());
            HFClient fabricClient = getFabricClient(organizationPatient.getAdminPeer());
            // 构造实例化链码请求
            InstantiateProposalRequest instantiateProposalRequestPatient = fabricClient.newInstantiationProposalRequest();
            // 设置链码实例化属性
            instantiateProposalRequestPatient.setProposalWaitTime(medicalConfig.getDeployWaitTime());
            instantiateProposalRequestPatient.setChaincodeID(chaincode.getChaincodeId());
            instantiateProposalRequestPatient.setChaincodeLanguage(chaincode.getLanguage());
            // 指定实例化的init方法
            instantiateProposalRequestPatient.setFcn("init");
            // 设置实例化的参数(这里设置每个用户初始有多少钱)
            instantiateProposalRequestPatient.setArgs("a", "500", "b", "300");
            // 母鸡在干啥
            Map<String, byte[]> tm = new HashMap<>();
            tm.put("HyperLedgerFabric", "InstantiateProposalRequest:JavaSDK".getBytes(UTF_8));
            tm.put("method", "InstantiateProposalRequest".getBytes(UTF_8));
            instantiateProposalRequestPatient.setTransientMap(tm);
            // 这里指定背书策略！！！！构造链码背书对象
            ChaincodeEndorsementPolicy endorsementPolicy = new ChaincodeEndorsementPolicy();
            // 从YAML文件读取背书策略(!!!!!!!!!!!!)
            endorsementPolicy.fromYamlFile(new File(MedicalConfig.ENDORSEMENT_POLICY_PATH_PATIENT));
            instantiateProposalRequestPatient.setChaincodeEndorsementPolicy(endorsementPolicy);

            logger.info("使用PatientPeer发送实例化请求.");
            Collection<ProposalResponse> patientResponse = thirdPartyChannel.sendInstantiationProposal(instantiateProposalRequestPatient, patientPeers);
            int failedResponseCounter = 0;
            // 分析实例化提案的响应结果
            for (ProposalResponse response : patientResponse) {
                if (response.isVerified() && response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    logger.info("成功实例化链码, response TxId: %s from peer %s" + response.getTransactionID() + "  " + response.getPeer().getName());
                } else {
                    logger.info("失败实例化链码, response TxId: %s from peer %s" + response.getTransactionID() + "  " + response.getPeer().getName());
                    failedResponseCounter++;
                }
            }

            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 使用ThirdPartyAdminPeer操作
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            logger.info("使用ThirdParty发送实例化请求: " + organizationThirdParty.getAdminPeer().getName());
            fabricClient = getFabricClient(organizationThirdParty.getAdminPeer());
            // 构造实例化链码请求
            InstantiateProposalRequest instantiateProposalRequestThirdParty = fabricClient.newInstantiationProposalRequest();
            // 设置链码实例化属性
            instantiateProposalRequestThirdParty.setProposalWaitTime(medicalConfig.getDeployWaitTime());
            instantiateProposalRequestThirdParty.setChaincodeID(chaincode.getChaincodeId());
            instantiateProposalRequestThirdParty.setChaincodeLanguage(chaincode.getLanguage());
            // 指定实例化的init方法
            instantiateProposalRequestThirdParty.setFcn("init");
            // 设置实例化的参数(这里设置每个用户初始有多少钱)
            instantiateProposalRequestThirdParty.setArgs("a", "500", "b", "300");
            // 母鸡在干啥
            Map<String, byte[]> tm2 = new HashMap<>();
            tm2.put("HyperLedgerFabric", "InstantiateProposalRequest:JavaSDK".getBytes(UTF_8));
            tm2.put("method", "InstantiateProposalRequest".getBytes(UTF_8));
            instantiateProposalRequestThirdParty.setTransientMap(tm2);

            // 这里指定背书策略！！！！构造链码背书对象
            ChaincodeEndorsementPolicy endorsementPolicyThirdParty = new ChaincodeEndorsementPolicy();
            // 从YAML文件读取背书策略(!!!!!!!!!!!!)
            endorsementPolicyThirdParty.fromYamlFile(new File(MedicalConfig.ENDORSEMENT_POLICY_PATH_PATIENT));
            instantiateProposalRequestThirdParty.setChaincodeEndorsementPolicy(endorsementPolicyThirdParty);
            Collection<ProposalResponse> thirdPartyResponse = thirdPartyChannel.sendInstantiationProposal(instantiateProposalRequestThirdParty, thirdPartyPeers);

            // 分析实例化提案的响应结果
            for (ProposalResponse response : thirdPartyResponse) {
                if (response.isVerified() && response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    logger.info("成功实例化链码, response TxId: %s from peer %s" + response.getTransactionID() + "  " + response.getPeer().getName());
                    //print("成功实例化链码, response TxId: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                } else {
                    logger.info("失败实例化链码, response TxId: %s from peer %s" + response.getTransactionID() + "  " + response.getPeer().getName());
                    failedResponseCounter++;
                }
            }
            // 实例化失败
            if (failedResponseCounter > 0) {
                throw new RuntimeException("链码实例化失败.");
            }

            // 下面将实例化成功的交易发送给Orderer
            logger.info("发送实例化交易至Orderer");

            // 这里设置提交交易时感兴趣的事件
            Channel.NOfEvents nOfEvents = createNofEvents();
            if (!thirdPartyChannel.getPeers(EnumSet.of(Peer.PeerRole.EVENT_SOURCE)).isEmpty()) {
                nOfEvents.addPeers(thirdPartyChannel.getPeers(EnumSet.of(Peer.PeerRole.EVENT_SOURCE)));
            }
            if (!thirdPartyChannel.getEventHubs().isEmpty()) {
                nOfEvents.addEventHubs(thirdPartyChannel.getEventHubs());
            }

            logger.info("准备发送实例化成功的交易提案.");
            CompletableFuture<BlockEvent.TransactionEvent> future = thirdPartyChannel.sendTransaction(
                    // 包含上面的成功响应结果集
                    patientResponse, thirdPartyChannel.getOrderers());
            // 从发送交易中获取交易事件
            BlockEvent.TransactionEvent transactionEventPatient = future.get();
            // 交易事件必须是合法的
            assertTrue(transactionEventPatient.isValid());
            // 交易事件必须有签名
            assertNotNull(transactionEventPatient.getSignature());
            // 从交易事件获取区块事件
            BlockEvent blockEventPatient = transactionEventPatient.getBlockEvent();
            // 保证能够获取区块
            assertNotNull(blockEventPatient.getBlock());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * 为病人组织安装链码
     * 安装链码不需要发送交易到Orderer结点
     */
    public void installChainCodeForPatient() {
        // 获取客户端
        HFClient fabricClient = getFabricClient(organizationPatient.getAdminPeer());
        // 获取链码对象
        ChaincodeEntity chainCodePatient = ChaincodeManager.chaincodeEntityPatient;
        logger.info("开始安装链码: " + chainCodePatient.getCodeName());
        try {
            // 判断当前链码是否已经被安装了
            for (String chainCodeName : patientChannel.getDiscoveredChaincodeNames()) {
                // 如果已经安装了链码
                if (chainCodePatient.getCodeName().equals(chainCodeName)) {
                    logger.info("The chaincode " + chainCodePatient.getCodeName() + " is already installed.");
                    return;
                }
            }
            // 到这里说明需要安装链码,下面构造链码安装的提案请求
            // 设置当前客户端的操作人为Admin Peer结点
            logger.info("当前操作的用户:" + organizationPatient.getAdminPeer().toString());
            fabricClient.setUserContext(organizationPatient.getAdminPeer());
            // 构造链码安装请求
            InstallProposalRequest installProposalRequestPatient = fabricClient.newInstallProposalRequest();
            // 传入上面生成的链码ID
            installProposalRequestPatient.setChaincodeID(chainCodePatient.getChaincodeId());
            installProposalRequestPatient.setChaincodeSourceLocation(Paths.get(MedicalConfig.FIXTURES_PATH, chainCodePatient.getFilePath()).toFile());
            // 这里设置索引配置文件的路径
            String indexFilePath = MedicalConfig.INDEX_FILE_PATH_PATIENT;
            installProposalRequestPatient.setChaincodeMetaInfLocation(new File(indexFilePath));
            // 设置链码版本与语言
            installProposalRequestPatient.setChaincodeVersion(chainCodePatient.getVersion());
            installProposalRequestPatient.setChaincodeLanguage(chainCodePatient.getLanguage());

            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 提交链码安装请求并分析结果
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 获取通道中的全部Peer结点
            Collection<Peer> peers = patientChannel.getPeers();
            Collection<Peer> orgPatientPeers = new HashSet<>();
            Collection<Peer> orgThirdPartyPeers = new HashSet<>();
            // 将Peer结点分类
            for (Peer peer : peers) {
                logger.info(patientChannel.getName() + " 通道的Peer:" + peer.getName());
                // 将Peer归类
                if (peer.getName().contains("orgthirdparty")) {
                    orgThirdPartyPeers.add(peer);
                } else {
                    orgPatientPeers.add(peer);
                }
            }
            logger.info("Patient发送链码安装Proposal.");
            // 发送链码安装请求并得到响应(先发送Patient组织的)
            Collection<ProposalResponse> patientResponse = fabricClient.sendInstallProposal(installProposalRequestPatient, orgPatientPeers);
            for (ProposalResponse response : patientResponse) {
                // 安装成功
                if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    logger.info("成功收到链码安装提案: " + response.getTransactionID() + " " + response.getPeer().getName());
                } else {
                    logger.info("失败收到链码安装提案: " + response.getTransactionID() + " " + response.getPeer().getName());
                    throw new RuntimeException("链码安装失败");
                }
            }
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

            // 切换为组织2的Admin
            logger.info("当前操作的用户:" + organizationThirdParty.getAdminPeer().toString());
            // 切换用户
            fabricClient = getFabricClient(organizationThirdParty.getAdminPeer());

            // 构造链码安装请求
            InstallProposalRequest installProposalRequestThirdParty = fabricClient.newInstallProposalRequest();
            // 传入上面生成的链码ID
            installProposalRequestThirdParty.setChaincodeID(chainCodePatient.getChaincodeId());
            // For GO language and serving just a single user, chaincodeSource is mostly likely the users GOPATH
            installProposalRequestThirdParty.setChaincodeSourceLocation(Paths.get(MedicalConfig.FIXTURES_PATH, chainCodePatient.getFilePath()).toFile());
            // 这里设置索引配置文件的路径
            installProposalRequestThirdParty.setChaincodeMetaInfLocation(new File("src/test/fixture/meta-infs/end2endit"));
            // 设置链码版本与语言
            installProposalRequestThirdParty.setChaincodeVersion(chainCodePatient.getVersion());
            installProposalRequestThirdParty.setChaincodeLanguage(chainCodePatient.getLanguage());

            logger.info("ThirdParty发送链码安装Proposal.");
            Collection<ProposalResponse> thirdPartyResponse = fabricClient.sendInstallProposal(installProposalRequestThirdParty, orgThirdPartyPeers);

            for (ProposalResponse response : thirdPartyResponse) {
                // 安装成功
                if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    logger.info("成功收到链码安装提案: " + response.getTransactionID() + " " + response.getPeer().getName());
                } else {
                    logger.info("失败收到链码安装提案: " + response.getTransactionID() + " " + response.getPeer().getName());
                    throw new RuntimeException("链码安装失败.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * 为第三方组织安装链码
     * 安装链码不需要发送交易到Orderer结点
     */
    public void installChainCodeForThirdParty() {

        // 获取链码对象
        ChaincodeEntity chainCodeThirdParty = ChaincodeManager.chaincodeEntityThirdParty;
        logger.info("开始安装链码: " + chainCodeThirdParty.getCodeName());
        try {
            // 判断当前链码是否已经被安装了
            for (String chainCodeName : thirdPartyChannel.getDiscoveredChaincodeNames()) {
                // 如果已经安装了链码
                if (chainCodeThirdParty.getCodeName().equals(chainCodeName)) {
                    logger.info("The chaincode " + chainCodeThirdParty.getCodeName() + " is already installed.");
                    return;
                }
            }
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 先操作OrgPatient
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 获取客户端
            HFClient fabricClient = getFabricClient(organizationPatient.getAdminPeer());
            // 设置当前客户端的操作人为Admin Peer结点
            logger.info("当前操作的用户:" + organizationPatient.getAdminPeer().toString());
            // 构造链码安装请求
            InstallProposalRequest installProposalRequestPatient = fabricClient.newInstallProposalRequest();
            // 传入上面生成的链码ID
            installProposalRequestPatient.setChaincodeID(chainCodeThirdParty.getChaincodeId());
            installProposalRequestPatient.setChaincodeSourceLocation(Paths.get(MedicalConfig.FIXTURES_PATH, chainCodeThirdParty.getFilePath()).toFile());
            // 这里设置索引配置文件的路径
            String indexFilePath = MedicalConfig.INDEX_FILE_PATH_PATIENT;
            installProposalRequestPatient.setChaincodeMetaInfLocation(new File(indexFilePath));
            // 设置链码版本与语言
            installProposalRequestPatient.setChaincodeVersion(chainCodeThirdParty.getVersion());
            installProposalRequestPatient.setChaincodeLanguage(chainCodeThirdParty.getLanguage());

            // 获取通道中的全部Peer结点
            Collection<Peer> peers = thirdPartyChannel.getPeers();
            Collection<Peer> orgPatientPeers = new HashSet<>();
            Collection<Peer> orgThirdPartyPeers = new HashSet<>();
            // 将Peer结点分类
            for (Peer peer : peers) {
                logger.info(thirdPartyChannel.getName() + " 通道的Peer:" + peer.getName());
                // 将Peer归类
                if (peer.getName().contains("orgthirdparty")) {
                    orgThirdPartyPeers.add(peer);
                } else {
                    orgPatientPeers.add(peer);
                }
            }
            logger.info("Patient发送链码安装Proposal.");
            // 发送链码安装请求并得到响应(先发送Patient组织的)
            Collection<ProposalResponse> patientResponse = fabricClient.sendInstallProposal(installProposalRequestPatient, orgPatientPeers);
            for (ProposalResponse response : patientResponse) {
                // 安装成功
                if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    logger.info("成功收到链码安装提案: " + response.getTransactionID() + " " + response.getPeer().getName());
                } else {
                    logger.info("失败收到链码安装提案: " + response.getTransactionID() + " " + response.getPeer().getName());
                    throw new RuntimeException("链码安装失败");
                }
            }

            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 再操作OrgThirdParty
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 切换为组织2的Admin
            logger.info("当前操作的用户:" + organizationThirdParty.getAdminPeer().toString());
            fabricClient = getFabricClient(organizationThirdParty.getAdminPeer());

            // 构造链码安装请求
            InstallProposalRequest installProposalRequestThirdParty = fabricClient.newInstallProposalRequest();
            // 传入上面生成的链码ID
            installProposalRequestThirdParty.setChaincodeID(chainCodeThirdParty.getChaincodeId());
            // For GO language and serving just a single user, chaincodeSource is mostly likely the users GOPATH
            installProposalRequestThirdParty.setChaincodeSourceLocation(Paths.get(MedicalConfig.FIXTURES_PATH, chainCodeThirdParty.getFilePath()).toFile());
            // 这里设置索引配置文件的路径
            installProposalRequestThirdParty.setChaincodeMetaInfLocation(new File(MedicalConfig.INDEX_FILE_PATH_THIRD_PARTY));
            // 设置链码版本与语言
            installProposalRequestThirdParty.setChaincodeVersion(chainCodeThirdParty.getVersion());
            installProposalRequestThirdParty.setChaincodeLanguage(chainCodeThirdParty.getLanguage());

            logger.info("ThirdParty发送链码安装Proposal.");
            Collection<ProposalResponse> thirdPartyResponse = fabricClient.sendInstallProposal(installProposalRequestThirdParty, orgThirdPartyPeers);

            for (ProposalResponse response : thirdPartyResponse) {
                // 安装成功
                if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    logger.info("成功收到链码安装提案: " + response.getTransactionID() + " " + response.getPeer().getName());
                } else {
                    logger.info("失败收到链码安装提案: " + response.getTransactionID() + " " + response.getPeer().getName());
                    throw new RuntimeException("链码安装失败.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 构造通道
     */
    private Channel buildThirdPartyChannel() {
        final String channelName = MedicalConfig.THIRD_PARTY_CHANNEL_NAME;
        try {

            logger.info("创建Fabric代理对象");
            HFClient fabricClient = HFClient.createNewInstance();
            fabricClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
            logger.info("创建Fabric代理对象完成");

            // 创建Foo通道(完成网络中通道的创建与结点的加入)(仅使用了组织1创建?)
            logger.info("准备创建MyChannel:" + channelName);
            // 只有PeerAdmin能创建通道
            MedicalUser peerAdminPatient = organizationPatient.getAdminPeer();
            MedicalUser peerAdminThirdParty = organizationThirdParty.getAdminPeer();
            // 设置Fabric Client用户环境,也就是设置谁进行操作
            fabricClient.setUserContext(peerAdminPatient);

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
                Orderer orderer = fabricClient.newOrderer(orderName, organizationPatient.getOrdererLocation(orderName), ordererProperties);
                // 将Orderer对象加入集合
                ordererCollection.add(orderer);
            }
            // 仅取集合中第一个Orderer创建通道
            Orderer anOrderer = ordererCollection.iterator().next();
            // 从集合中移除选中的这个Orderer
            ordererCollection.remove(anOrderer);
            // tx文件路径
            String txFilePath = MedicalConfig.THIRD_PARTY_CHANNEL_TX_FILE_PATH;
            // 通过tx文件对Channel进行配置
            ChannelConfiguration channelConfiguration = new ChannelConfiguration(new File(txFilePath));

            // 使用peerAdmin进行签名
            logger.info("使用peerAdmin进行签名");
            byte[] signature = fabricClient.getChannelConfigurationSignature(channelConfiguration, peerAdminPatient);
            // 通过PeerAdmin创建channel
            logger.info("开始创建Channel: " + channelName);
            Channel newChannel = fabricClient.newChannel(channelName, anOrderer, channelConfiguration, signature);
            logger.info("完成创建Channel: " + channelName);

            // 这里决定哪些Peer加入通道?
            // 获取组织的全部Peer结点
            logger.info("组织Patient加入Channel:" + channelName);
            for (String peerName : organizationPatient.getPeerNames()) {
                // 获取Peer的地址
                String peerLocation = organizationPatient.getPeerLocation(peerName);
                // 获取Peer结点的配置属性
                Properties peerProperties = medicalConfig.getPeerProperties(peerName);
                if (peerProperties == null) {
                    peerProperties = new Properties();
                }
                // 打印一下属性
                //for (String property : peerProperties.stringPropertyNames()) {
                //    logger.info(peerName + "属性: " + property, peerProperties.getProperty(property));
                //}

                // Example of setting specific options on grpc's NettyChannelBuilder
                // 添加额外的属性
                peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);

                // 逐一构造Peer结点对象
                Peer peer = fabricClient.newPeer(peerName, peerLocation, peerProperties);
                logger.info("当前Peer加入Channel:" + peerName);
                // 将当前Peer结点加入Channel中
                newChannel.joinPeer(peer, createPeerOptions()
                        // 默认拥有全部角色(四种角色)
                        .setPeerRoles(EnumSet.of(Peer.PeerRole.ENDORSING_PEER, Peer.PeerRole.LEDGER_QUERY, Peer.PeerRole.CHAINCODE_QUERY, Peer.PeerRole.EVENT_SOURCE)));
                logger.info("Peer结点: " + peerName + " 成功加入通道: " + channelName);
            }

            logger.info("组织ThirdParty加入Channel:" + channelName);
            fabricClient.setUserContext(peerAdminThirdParty);
            for (String peerName : organizationThirdParty.getPeerNames()) {
                // 获取Peer的地址
                String peerLocation = organizationThirdParty.getPeerLocation(peerName);
                // 获取Peer结点的配置属性
                Properties peerProperties = medicalConfig.getPeerProperties(peerName);
                if (peerProperties == null) {
                    peerProperties = new Properties();
                }
                // 打印一下属性
                //for (String property : peerProperties.stringPropertyNames()) {
                //    logger.info(peerName + "属性: " + property, peerProperties.getProperty(property));
                //}
                // Example of setting specific options on grpc's NettyChannelBuilder
                // 添加额外的属性
                peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);
                // 逐一构造Peer结点对象
                Peer peer = fabricClient.newPeer(peerName, peerLocation, peerProperties);
                logger.info("当前Peer加入Channel:" + peerName);
                // 将当前Peer结点加入Channel中
                newChannel.joinPeer(peer, createPeerOptions()
                        // 默认拥有全部角色(四种角色)
                        .setPeerRoles(EnumSet.of(Peer.PeerRole.ENDORSING_PEER, Peer.PeerRole.LEDGER_QUERY, Peer.PeerRole.CHAINCODE_QUERY, Peer.PeerRole.EVENT_SOURCE)));
                logger.info("Peer结点: " + peerName + " 成功加入通道: " + channelName);
            }
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
                EventHub eventHub = fabricClient.newEventHub(eventHubName, organizationPatient.getEventHubLocation(eventHubName),
                        eventHubProperties);
                // 将EventHub加入通道中
                newChannel.addEventHub(eventHub);
            }
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
     * 构造通道
     */
    private Channel buildPatientChannel() {
        // 通道名称
        final String channelName = MedicalConfig.PATIENT_CHANNEL_NAME;
        try {
            logger.info("创建Fabric代理对象");
            HFClient fabricClient = HFClient.createNewInstance();
            fabricClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
            logger.info("创建Fabric代理对象完成");

            logger.info("准备创建Channel:" + channelName);
            // 只有PeerAdmin能创建通道
            MedicalUser peerAdminPatient = organizationPatient.getAdminPeer();
            MedicalUser peerAdminThirdParty = organizationThirdParty.getAdminPeer();
            logger.info("PeerAdmin用户信息:" + peerAdminPatient.toString());
            // 设置Fabric Client用户环境,也就是设置谁进行操作
            fabricClient.setUserContext(peerAdminPatient);

            // Orderer结点
            Collection<Orderer> ordererCollection = new LinkedList<>();

            // 获取全部Orderer结点名称
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
                Orderer orderer = fabricClient.newOrderer(orderName, organizationPatient.getOrdererLocation(orderName), ordererProperties);
                logger.info("创建Orderer结点对象完成: " + orderName);
                // 将Orderer对象加入集合
                ordererCollection.add(orderer);
            }

            // 仅取集合中第一个Orderer创建通道
            Orderer anOrderer = ordererCollection.iterator().next();
            // 从集合中移除选中的这个Orderer
            ordererCollection.remove(anOrderer);
            // tx文件路径
            String txFilePath = MedicalConfig.PATIENT_CHANNEL_TX_FILE_PATH;
            // 通过tx文件对Channel进行配置
            ChannelConfiguration channelConfiguration = new ChannelConfiguration(new File(txFilePath));
            // 使用peerAdmin进行签名
            logger.info("使用peerAdmin进行签名");
            byte[] signature = fabricClient.getChannelConfigurationSignature(channelConfiguration, peerAdminPatient);
            // Create channel that has only one signer that is this orgs peer admin. If channel creation policy needed more signature they would need to be added too.
            // 通过PeerAdmin创建channel
            logger.info("开始创建Channel: " + channelName);
            Channel newChannel = fabricClient.newChannel(channelName, anOrderer, channelConfiguration, signature);
            logger.info("完成创建Channel: " + channelName);

            // 这里决定哪些Peer加入通道?
            // 获取组织的全部Peer结点
            logger.info("组织Patient加入Channel:" + channelName);
            for (String peerName : organizationPatient.getPeerNames()) {
                // 获取Peer的地址
                String peerLocation = organizationPatient.getPeerLocation(peerName);
                // 获取Peer结点的配置属性
                Properties peerProperties = medicalConfig.getPeerProperties(peerName);
                if (peerProperties == null) {
                    peerProperties = new Properties();
                }
                // 打印一下属性
                // for (String property : peerProperties.stringPropertyNames()) {
                //     logger.info(peerName + "属性: " + property, peerProperties.getProperty(property));
                // }

                // Example of setting specific options on grpc's NettyChannelBuilder
                // 添加额外的属性
                peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);

                // 逐一构造Peer结点对象
                Peer peer = fabricClient.newPeer(peerName, peerLocation, peerProperties);
                // 将当前Peer结点加入Channel中
                newChannel.joinPeer(peer, createPeerOptions()
                        // 默认拥有全部角色(四种角色)
                        .setPeerRoles(EnumSet.of(Peer.PeerRole.ENDORSING_PEER, Peer.PeerRole.LEDGER_QUERY, Peer.PeerRole.CHAINCODE_QUERY, Peer.PeerRole.EVENT_SOURCE)));
                logger.info("Peer结点: " + peerName + " 成功加入通道: " + channelName);
            }

            logger.info("组织ThirdParty加入Channel:" + channelName);
            fabricClient.setUserContext(peerAdminThirdParty);
            for (String peerName : organizationThirdParty.getPeerNames()) {
                // 这里仅将Government加入PatientChannel
                if (peerName.contains("government")) {
                    // 获取Peer的地址
                    String peerLocation = organizationThirdParty.getPeerLocation(peerName);
                    // 获取Peer结点的配置属性
                    Properties peerProperties = medicalConfig.getPeerProperties(peerName);
                    if (peerProperties == null) {
                        peerProperties = new Properties();
                    }
                    // 打印一下属性
                    // for (String property : peerProperties.stringPropertyNames()) {
                    //     logger.info(peerName + "属性: " + property, peerProperties.getProperty(property));
                    // }
                    // 添加额外的属性
                    peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);
                    // 逐一构造Peer结点对象
                    Peer peer = fabricClient.newPeer(peerName, peerLocation, peerProperties);
                    // 如果版本大于等于1.3
                    // 将当前Peer结点加入Channel中
                    newChannel.joinPeer(peer, createPeerOptions()
                            // 默认拥有全部角色(四种角色)
                            .setPeerRoles(EnumSet.of(Peer.PeerRole.ENDORSING_PEER, Peer.PeerRole.LEDGER_QUERY, Peer.PeerRole.CHAINCODE_QUERY, Peer.PeerRole.EVENT_SOURCE)));
                    logger.info("Peer结点: " + peerName + " 成功加入通道: " + channelName);
                }
            }
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
                EventHub eventHub = fabricClient.newEventHub(eventHubName, organizationPatient.getEventHubLocation(eventHubName),
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
     * 为组织注册与登记用户
     *
     * @param localStore 持久化文件
     */
    private void registerAndEnrollForOrganization(LocalStore localStore, Organization organization) {
        logger.info("开始为组织: " + organization.name + " 注册登记用户.");
        try {
            // 获取CA代理
            HFCAClient caClient = organization.getCAClient();
            // 获取组织名称
            final String orgName = organization.getName();
            // 获取组织MSPID
            final String mspid = organization.getMSPID();
            // "ca0.example.com"
            logger.info("当前组织CA代理的名称:" + caClient.info().getCAName());
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
                final String tlsKeyPem = MedicalUtil.getPEMStringFromPrivateKey(enroll.getKey());
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
                admin.setMspId(mspid);
            }

            // 创建一个新的普通用户
            MedicalUser user = localStore.getUser(normalUser, organization.getName());
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
                user.setMspId(mspid);
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


    /**
     * 初始化配置(仅需执行一次,后续直接使用即可)
     */
    public void initConfig() {
        if (isSystemInit) {
            return;
        }
        logger.info("开始系统初始化配置.");
        try {
            // 重置配置
            resetConfig();
            // 获取组织的Set
            organizationSet = medicalConfig.getOrganizationSet();
            logger.info("系统组织数: " + organizationSet.size());
            // 将组织对象映射到本类中
            organizationPatient = medicalConfig.getOrganizationMap().get("peerOrgPatient");
            organizationThirdParty = medicalConfig.getOrganizationMap().get("peerOrgThirdParty");
            
            // 初始化CA0
            String caPatientName = organizationPatient.getCAName();
            logger.info("组织1CA名称: " + caPatientName);
            logger.info("构造组织1的CA代理对象.");
            // 构造组织1的CA代理对象
            HFCAClient caClientPatient = HFCAClient.createNewInstance(
                    // CA名称
                    caPatientName,
                    // CA地址
                    organizationPatient.getCALocation(),
                    // CA属性
                    organizationPatient.getCAProperties());
            logger.info("构造组织Patient的CA代理对象完成.");
            // 这里设置加密套件
            caClientPatient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
            organizationPatient.setCAClient(caClientPatient);

            // 构造组织1的CA代理对象
            String caThirdPartyName = organizationThirdParty.getCAName();
            HFCAClient caClientThirdParty = HFCAClient.createNewInstance(
                    // CA名称
                    caThirdPartyName,
                    // CA地址
                    organizationThirdParty.getCALocation(),
                    // CA属性
                    organizationThirdParty.getCAProperties());
            logger.info("构造组织ThirdParty的CA代理对象完成.");
            caClientThirdParty.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
            organizationThirdParty.setCAClient(caClientThirdParty);

            // 重新构造存储文件
            if (localStoreFilePath.exists()) {
                localStoreFilePath.delete();
            }
            // 重新创建文件
            localStore = new LocalStore(localStoreFilePath);
        } catch (Exception e) {
            e.printStackTrace();
        }
        isSystemInit = true;
        logger.info("完成系统初始化配置.");
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
}
