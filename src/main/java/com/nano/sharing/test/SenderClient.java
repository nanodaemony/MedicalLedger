package com.nano.sharing.test;

import com.nano.sharing.Encryption;
import com.nano.sharing.MessageEntity;

import java.math.BigInteger;
import java.util.Scanner;

/**
 * Description: Sender client for data sharing.
 *
 * @version: 1.0
 * @author: nano
 * @date: 2020/12/6 14:50
 */
public class SenderClient {


    private Encryption sender = new Encryption();

    BigInteger receiverPublicKey;

    /**
     * 向服务器进行注册(发送自己的公钥并获取接收方的公钥)
     */
    public void register() {

    }


    /**
     * 发送消息
     */
    public void sendMessage() {
        try {
            // Input Message
            String plainText;
            Scanner scanner = new Scanner(System.in);
            System.out.println("Enter message: ");
            plainText = scanner.nextLine();
            System.out.println();

            // 发送者对消息加密得到加密发送体
            System.out.println("Sender 公钥:" + sender.rsa.e);
            System.out.println("Sender 私钥:" + sender.rsa.d);
            // 发送者用AES加密消息明文
            MessageEntity senderMessage = sender.encryptMessageByAes(plainText);
            System.out.println("Key: " + senderMessage.getBigIntKey());

            // 加密消息内的AES秘钥(此时消息体内是A生成的代理秘钥)
            // 发送者对AES秘钥加密(现在消息体内存储的是加密后的AES秘钥)
            senderMessage = sender.encryptKeyByRsa(senderMessage);
            // Print Encrypted Key and Message
            System.out.println("Encrypted Key: " + senderMessage.getBigIntKey());
            System.out.println("Encrypted Message: " + senderMessage.getMessage());

//            BigInteger midKey = receiver.rsa.e.multiply(sender.rsa.d);

//            senderMessage.setMidKey(midKey);



        } catch (Exception e) {
            e.printStackTrace();
        }

    }



}
