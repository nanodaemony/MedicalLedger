/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.nano.sharing;

import java.util.Scanner;

/**
 * @author singh
 */
public class PREusingMultipleProxies {


    // This Java based implementation contains code for Proxy Re-Encryption using RSA+AES.
    // The message is encrypted at the Sender level with an AES Key.
    // The AES Key is encrypted with the Sender's Public RSA Key.
    // The AES Key is then Re-Encrypted at the Server so that it can be decrypted by the Reciever's Private RSA Key.
    // After the decryption of the AES Key at the Reciever level the ciphertext is decrypted to obtain the original message.

    public static void main(String[] args) {
        try {

            // 初始化发送方
            Encryption sender = new Encryption();
            // 初始化Server
            ProxyReEncryptionServer server1 = new ProxyReEncryptionServer();
            ProxyReEncryptionServer server2 = new ProxyReEncryptionServer();
            ProxyReEncryptionServer server3 = new ProxyReEncryptionServer();

            Encryption randomNode1 = new Encryption();
            Encryption randomNode2 = new Encryption();
            // 初始化接收方
            Encryption receiver = new Encryption();

            // 读取数据
            String data;
            Scanner sc = new Scanner(System.in);
            System.out.println("Enter message: ");
            data = sc.nextLine();
            System.out.println();

            // Encryption 对数据进行加密
            MessageEntity senderUtil = sender.encryptMessageByAes(data);

            // Print Key
            System.out.println("Key: " + senderUtil.getBigIntKey());

            // 加密Key
            senderUtil = sender.encryptKeyByRsa(senderUtil);

            // 打印加密后的Key和消息
            System.out.println("Encrypted Key: " + senderUtil.getBigIntKey());
            System.out.println("Encrypted Message: " + senderUtil.getMessage());

            // Re-Encryption 1
            MessageEntity serverUtil1 = server1.reEncrypt(senderUtil, sender, randomNode1);
            // Print Re-Encrypted Key
            System.out.println("Re-Encrypted Key at Step 1: " + serverUtil1.getBigIntKey());


            // Re-Encryption 2
            MessageEntity serverUtil2 = server2.reEncrypt(senderUtil, randomNode1, randomNode2);
            // Print Re-Encrypted Key
            System.out.println("Re-Encrypted Key at Step 2: " + serverUtil2.getBigIntKey());

            // Re-Encryption 3
            MessageEntity serverUtil3 = server3.reEncrypt(senderUtil, randomNode2, receiver);
            // Print Re-Encrypted Key
            System.out.println("Re-Encrypted Key at Step 3: " + serverUtil3.getBigIntKey());

            // Decryption
            MessageEntity receiverUtil = receiver.decryptKey(serverUtil3);
            // 获取解密后的信息
            String decryptedMessage = receiver.decryptMessageByAes(receiverUtil);

            // Print Decrypted Key
            System.out.println("Decrypted Key: " + receiverUtil.getBigIntKey() + "\n");

            // Print Decrypted Message
            System.out.println("Decrypted Message: \n" + decryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}

