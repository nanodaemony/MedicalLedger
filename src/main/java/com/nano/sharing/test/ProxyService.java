package com.nano.sharing.test;

import com.nano.core.MedicalChannelThirdParty;
import com.nano.medical.DataUsageEntity;
import com.nano.sharing.Encryption;
import com.nano.sharing.MessageEntity;
import com.nano.sharing.ProxyReEncryptionServer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.math.BigInteger;

/**
 * Description:
 *
 * @version: 1.0
 * @author: nano
 * @date: 2020/12/6 17:13
 */
@Component
public class ProxyService {

    @Autowired
    private MedicalChannelThirdParty channelThirdParty;


    public static void main(String[] args) {
        new ProxyService().doTest();
    }



    private static final String SHARED_DATA = "{\"admissionId\":\"577311724\",\"beforeOperationDiagnosis\":\"普通感冒\",\"choosedOperationName\":\"\",\"hospitalArea\":\"重庆\",\"hospitalCode\":\"50\",\"hospitalLevel\":\"三甲\",\"hospitalOperationNumber\":\"1607254982954\",\"operationASALevel\":3,\"operationAnesthesiaMode\":\"局麻\",\"operationHeartFunctionLevel\":\"II级\",\"operationIsUrgent\":false,\"operationKidneyFunctionLevel\":\"4\",\"operationLiverFunctionLevel\":\"B级\",\"operationLungFunctionLevel\":\"3级\",\"operationName\":\"XXXXXX术\",\"pastMedicalHistory\":\"无\",\"patientAge\":\"90\",\"patientHeight\":\"190\",\"patientId\":\"160725498295428008251\",\"patientSex\":\"1\",\"patientWeight\":\"70\",\"specialDiseaseCase\":\"高血压\"}\n";

    /**
     * Do test.
     */
    public void doTest() {

        Encryption sender = new Encryption();
        ProxyReEncryptionServer server = new ProxyReEncryptionServer();
        Encryption receiver = new Encryption();
        try {
            // 发送者用AES加密消息明文
            MessageEntity senderMessage = sender.encryptMessageByAes(SHARED_DATA);
            // 加密消息内的AES秘钥(此时消息体内是A生成的代理秘钥)
            // 发送者对AES秘钥加密(现在消息体内存储的是加密后的AES秘钥)
            senderMessage = sender.encryptKeyByRsa(senderMessage);
            BigInteger midKey = receiver.rsa.e.multiply(sender.rsa.d);
            senderMessage.setMidKey(midKey);
            // Re-Encryption代理重加密
            MessageEntity middleMessage = server.reEncrypt(senderMessage);
            // 构造数据使用实体
            DataUsageEntity entity = new DataUsageEntity();
            entity.setTreatmentId("13A21378B");
            entity.setSenderPseudonymId("HDJK1780ASBC8912" + System.currentTimeMillis());
            entity.setReceiverPseudonymId("8912098GHSAIOJ87" + System.currentTimeMillis());
            entity.setTimestamp(System.currentTimeMillis());
            boolean success = channelThirdParty.saveDataUsageInfo(entity);
            if (!success) {
                throw new RuntimeException("Failed.");
            }
            // 接受者解密
            MessageEntity receiverEntity = receiver.decryptKey(middleMessage);
            // 获取明文
            String decryptedPlainText = receiver.decryptMessageByAes(receiverEntity);
            // Print Decrypted Message
            // System.out.println("Get shared message: \n" + decryptedPlainText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
