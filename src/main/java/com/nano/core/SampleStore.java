/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.encoders.Hex;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Serializable;
import java.io.StringReader;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * 存储键值对的本地文件存储对象 A local file-based key value store.
 *
 * @author nano
 */
public class SampleStore {

    /**
     * 属性文件路径
     */
    private final String propertyFilePath;

    /**
     * 日志
     */
    private final Log logger = LogFactory.getLog(SampleStore.class);

    /**
     * 加密套件
     */
    private CryptoSuite cryptoSuite;

    public SampleStore(File file) {
        this.propertyFilePath = file.getAbsolutePath();
    }

    /**
     * Get the value associated with name.
     */
    public String getValue(String name) {
        // 加载属性
        Properties properties = loadProperties();
        // 从属性中获取值
        return properties.getProperty(name);
    }

    /**
     * Has the value present.
     */
    public boolean hasValue(String name) {
        // 加载属性
        Properties properties = loadProperties();
        return properties.containsKey(name);
    }

    /**
     * 加载属性
     */
    private Properties loadProperties() {
        Properties properties = new Properties();
        // 读取传入的属性文件
        try (InputStream input = new FileInputStream(propertyFilePath)) {
            // 加载属性文件
            properties.load(input);
            input.close();
        } catch (FileNotFoundException e) {
            logger.info(String.format("Could not find the file \"%s\"", propertyFilePath));
        } catch (IOException e) {
            logger.warn(String.format("Could not load keyvalue store from file \"%s\", reason:%s", propertyFilePath, e.getMessage()));
        }
        return properties;
    }

    /**
     * 为某个具体用户设置键值对属性
     * Set the value associated with name.
     *
     * @param name  The name of the parameter
     * @param value Value for the parameter
     */
    public void setValue(String name, String value) {
        // 加载属性文件
        Properties properties = loadProperties();
        try (
                OutputStream output = new FileOutputStream(propertyFilePath)
        ) {
            properties.setProperty(name, value);
            // 属性存入文件中
            properties.store(output, "");
            output.close();
        } catch (IOException e) {
            logger.warn(String.format("Could not save the key value store, reason:%s", e.getMessage()));
        }
    }

    /**
     * 成员Map
     */
    private final Map<String, MedicalUser> userMap = new HashMap<>();

    /**
     * 通过给定用户名与组织获取用户
     * Get the user with a given name
     */
    public MedicalUser getUser(String name, String org) {
        // 如果已经有缓存的用户名,那么直接返回即可
        MedicalUser medicalUser = userMap.get(MedicalUser.toKeyValStoreName(name, org));
        if (medicalUser != null) {
            return medicalUser;
        }
        // 如果没有缓存用户信息则根据传入的信息构造一个即可,同时进行缓存
        // Create the SampleUser and try to restore it's state from the key value store (if found).
        medicalUser = new MedicalUser(name, org, this, cryptoSuite);
        System.out.println("新建一个用户:" + name + " in " + org);
        return medicalUser;
    }


    /**
     * Check if store has user.
     *
     * @param name 用户名
     * @param org  组织
     * @return true if the user exists.
     */
    public boolean hasUser(String name, String org) {
        // Try to get the SampleUser state from the cache
        if (userMap.containsKey(MedicalUser.toKeyValStoreName(name, org))) {
            return true;
        }
        return MedicalUser.isStored(name, org, this);
    }

    /**
     * 通过用户的各种信息文件获取用户
     * Get the user with a given name
     *
     * @param name            用户名
     * @param org             组织
     * @param mspId           MSPID
     * @param privateKeyFile  私钥文件
     * @param certificateFile 证书文件
     * @return user
     */
    public MedicalUser getUser(String name, String org, String mspId, File privateKeyFile,
                               File certificateFile) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        try {
            // Try to get the SampleUser state from the cache
            MedicalUser medicalUser = userMap.get(MedicalUser.toKeyValStoreName(name, org));
            if (null != medicalUser) {
                return medicalUser;
            }
            // Create the SampleUser and try to restore it's state from the key value store (if found).
            medicalUser = new MedicalUser(name, org, this, cryptoSuite);
            medicalUser.setMspId(mspId);
            String certificate = new String(IOUtils.toByteArray(new FileInputStream(certificateFile)), "UTF-8");
            PrivateKey privateKey = getPrivateKeyFromBytes(IOUtils.toByteArray(new FileInputStream(privateKeyFile)));
            medicalUser.setEnrollment(new SampleStoreEnrollement(privateKey, certificate));
            medicalUser.saveState();
            return medicalUser;
        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | ClassCastException e) {
            e.printStackTrace();
            throw e;
        }
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 从Byte数组获取私钥
     *
     * @param data 数组
     */
    static PrivateKey getPrivateKeyFromBytes(byte[] data) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        final Reader pemReader = new StringReader(new String(data));

        final PrivateKeyInfo pemPair;
        try (PEMParser pemParser = new PEMParser(pemReader)) {
            pemPair = (PrivateKeyInfo) pemParser.readObject();
        }
        PrivateKey privateKey = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getPrivateKey(pemPair);
        return privateKey;
    }

    // Use this to make sure SDK is not dependent on HFCA enrollment for non-Idemix
    static final class SampleStoreEnrollement implements Enrollment, Serializable {

        private static final long serialVersionUID = -2784835212445309006L;
        private final PrivateKey privateKey;
        private final String certificate;

        SampleStoreEnrollement(PrivateKey privateKey, String certificate) {

            this.certificate = certificate;

            this.privateKey = privateKey;
        }

        @Override
        public PrivateKey getKey() {

            return privateKey;
        }

        @Override
        public String getCert() {
            return certificate;
        }

    }

    /**
     * 持久化Channel
     *
     * @param channel channel
     */
    void saveChannel(Channel channel) throws IOException, InvalidArgumentException {
        setValue("channel." + channel.getName(), Hex.toHexString(channel.serializeChannel()));
    }

    /**
     * 获取Channel
     *
     * @param client 代理对象
     * @param name channel名称
     */
    Channel getChannel(HFClient client, String name) throws IOException, ClassNotFoundException, InvalidArgumentException {
        Channel channel = null;
        String channelHex = getValue("channel." + name);
        if (channelHex != null) {
            // 反序列化Channel
            channel = client.deSerializeChannel(Hex.decode(channelHex));
        }
        return channel;
    }

    /**
     * 存储客户端的PEM和TLS秘钥
     *
     * @param organization 组织
     * @param key 秘钥
     */
    public void storeClientPEMTLSKey(Organization organization, String key) {
        setValue("clientPEMTLSKey." + organization.getName(), key);
    }

    /**
     * 获取客户端的PEM和TLS秘钥
     *
     * @param organization 组织
     */
    public String getClientPEMTLSKey(Organization organization) {
        return getValue("clientPEMTLSKey." + organization.getName());
    }


    /**
     * 存储客户端的PEM和TLS证书
     *
     * @param organization 组织
     * @param certificate 秘钥
     */
    public void storeClientPEMTLCertificate(Organization organization, String certificate) {
        setValue("clientPEMTLSCertificate." + organization.getName(), certificate);
    }


    /**
     * 存储客户端的PEM和TLS证书
     *
     * @param organization 组织
     */
    public String getClientPEMTLSCertificate(Organization organization) {
        return getValue("clientPEMTLSCertificate." + organization.getName());
    }

}