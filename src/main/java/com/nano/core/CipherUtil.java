package com.nano.core;

import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.NullCipher;

import sun.security.ec.ECKeyFactory;
import sun.security.ec.ECKeyFactory;
import sun.security.ec.ECPrivateKeyImpl;
import sun.security.ec.ECPublicKeyImpl;
/**
 * Description: Some method of cipher.
 *
 * ref:https://blog.csdn.net/huangmingleiluo/article/details/108346537
 *
 * @version: 1.0
 * @author: nano
 * @date: 2020/11/26 13:06
 */
public class CipherUtil {


    /**
     * <p>
     * 用私钥对信息生成数字签名
     * </p>
     *
     * @param data       已加密数据
     * @param privateKey 私钥(BASE64编码)
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Signature signature = Signature.getInstance("SHA2");
        signature.initSign(privateK);
        signature.update(data);
        return Base64.getEncoder().encodeToString(signature.sign());
    }


    /**
     * 利用私钥进行签名
     *
     * @param data 数据
     * @param privateKey 私钥
     */
    public static String sign(byte[] data, PrivateKey privateKey) {
        try {
            // 签名算法
            Signature signature = Signature.getInstance("SHA384withECDSA");
            signature.initSign(privateKey);
            signature.update(data);
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 验证签名
     *
     * @param data 数据
     * @param publicKey 公钥
     * @param sign 签名
     */
    public static boolean verifySignature(byte[] data, PublicKey publicKey, String sign) {
        try {
            Signature signature = Signature.getInstance("SHA384withECDSA");
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(Base64.getDecoder().decode(sign));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }


    /**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 128;


    public static final String KEY_ALGORITHM = "RSA";


    /**
     * <P>
     * 私钥解密
     * </p>
     *
     * @param encryptedData 已加密数据
     * @param privateKey 私钥(BASE64编码)
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey)
            throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }




    /**
     * 公钥解密
     * @param encryptedData 已加密数据
     * @param publicKey 公钥(BASE64编码)
     */
    public static byte[] decryptByPublicKey(byte[] encryptedData, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("SHA384withECDSA");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            int inputLen = encryptedData.length;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            // 对数据分段解密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                    cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_DECRYPT_BLOCK;
            }
            byte[] decryptedData = out.toByteArray();
            out.close();
            return decryptedData;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * <p>
     * 私钥加密
     * </p>
     *
     * @param data 源数据
     * @param privateKey 私钥(BASE64编码)
     * @return
     */
    public static byte[] encryptByPrivateKey(byte[] data, PrivateKey privateKey)
            throws Exception {
        // byte[] keyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(((RSAPrivateKey)privateKey).getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

//    public byte[] encrypt(byte[] content) {
//        if (publicKey == null) {
//            throw new RuntimeException("public key is null.");
//        }
//        try {
//            Cipher cipher = Cipher.getInstance("ECIES", "BC");
//            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//            int size = SIZE;
//            ByteArrayOutputStream baos = new ByteArrayOutputStream((content.length + size - 1) / size * (size + 45));
//            int left = 0;
//            for (int i = 0; i < content.length; ) {
//                left = content.length - i;
//                if (left > size) {
//                    cipher.update(content, i, size);
//                    i += size;
//                } else {
//                    cipher.update(content, i, left);
//                    i += left;
//                }
//                baos.write(cipher.doFinal());
//            }
//            return baos.toByteArray();
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//    }


    /**
     * 公钥加密
     *
     * @param data 源数据
     * @param publicKey 公钥(BASE64编码)
     */
    public static byte[] encryptByPublicKey(byte[] data, PublicKey publicKey) {
        try {
            // 对数据加密
            Cipher cipher = Cipher.getInstance("SHA384withECDSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            int inputLen = data.length;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            // 对数据分段加密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                    cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(data, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_ENCRYPT_BLOCK;
            }
            byte[] encryptedData = out.toByteArray();
            out.close();
            return encryptedData;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }









}
