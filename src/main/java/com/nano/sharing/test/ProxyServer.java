package com.nano.sharing.test;

import com.nano.core.MedicalChannelThirdParty;
import com.nano.medical.DataUsageEntity;
import com.nano.sharing.MessageEntity;
import com.nano.sharing.ProxyReEncryptionServer;

import org.springframework.beans.factory.annotation.Autowired;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Description: Proxy server for data sharing.
 *
 * @version: 1.0
 * @author: nano
 * @date: 2020/12/6 14:58
 */
public class ProxyServer {


    @Autowired
    private MedicalChannelThirdParty thirdParty;

    private ProxyReEncryptionServer server = new ProxyReEncryptionServer();

    /**
     * 接收方的公钥Map
     * key: PID
     * value: RSA公钥
     */
    private Map<String, BigInteger> receiverPublicKeyMap = new HashMap<>();

    /**
     * 重加密的中间信息Map
     */
    private Map<String, MessageEntity> middleMessageMap = new HashMap<>();


    /**
     * 进行用户注册
     */
    public void doUserRegister(String receiverPid, BigInteger publicKey) {
        receiverPublicKeyMap.put(receiverPid, publicKey);
    }


    /**
     * 进行代理重加密
     */
    public void doProxyReEncryption(MessageEntity senderMessage) {
        // 产生中间密文
        MessageEntity middleMessage = server.reEncrypt(senderMessage);

    }


    /**
     * 获取分享的数据
     */
    public void getSharedMessage(String receiverPid) {

        if (!receiverPublicKeyMap.containsKey(receiverPid)) {
            throw new RuntimeException("接受者未注册.");
        }

        if(!middleMessageMap.containsKey(receiverPid)) {
            throw new RuntimeException("没有重加密的消息.");
        }

        MessageEntity entity = middleMessageMap.get(receiverPid);

        DataUsageEntity dataUsageEntity = new DataUsageEntity();
        dataUsageEntity.setSenderPseudonymId(entity.getSenderPid());
        dataUsageEntity.setReceiverPseudonymId(entity.getReceiverPid());
        dataUsageEntity.setTreatmentId(entity.getTreatmentId());
        dataUsageEntity.setTimestamp(System.currentTimeMillis());

        // Save data usage info to Fabric.
        try {
            // 存入区块链成功
            boolean success = thirdParty.saveDataUsageInfo(dataUsageEntity);
            if(!success) {
                throw new RuntimeException("失败");
            }



        } catch (Exception e) {
            e.printStackTrace();
        }



    }


}
