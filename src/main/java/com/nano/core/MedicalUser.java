/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology - All Rights Reserved.
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

import com.nano.redis.utils.RedisUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Set;

import io.netty.util.internal.StringUtil;

import org.bouncycastle.util.encoders.Hex;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

/**
 * 系统用户类
 * @author nano
 */
public class MedicalUser implements User, Serializable {

    private static final long serialVersionUID = 8077132186383604355L;

    /**
     * 用户名
     */
    private String name;

    /**
     * 用户角色
     */
    private Set<String> roles;

    private String account;

    /**
     * 隶属组织
     */
    private String affiliation;

    /**
     * 组织
     */
    private String organization;

    /**
     * Enroll的秘钥
     */
    private String enrollmentSecret;

    /**
     * Enroll信息
     */
    Enrollment enrollment = null;

    /**
     * 存储的东西
     */
    private transient SampleStore keyValStore;

    /**
     * 秘钥保存的名称
     */
    private String keyValStoreName;

    /**
     * 加密套件
     */
    private transient CryptoSuite cryptoSuite;

    public MedicalUser(String name, String organization, SampleStore fs, CryptoSuite cryptoSuite) {
        this.name = name;
        this.cryptoSuite = cryptoSuite;
        this.keyValStore = fs;
        this.organization = organization;
        this.keyValStoreName = toKeyValStoreName(this.name, organization);
        String memberStr = keyValStore.getValue(keyValStoreName);
        // 持久化用户信息
        if (null == memberStr) {
            saveState();
        } else {
            restoreState();
        }
    }

    public MedicalUser(String name, String organization, CryptoSuite cryptoSuite) {
        this.name = name;
        this.cryptoSuite = cryptoSuite;
        this.organization = organization;
        this.keyValStoreName = toKeyValStoreName(this.name, organization);

        Object info = RedisUtil.get(name);
        if (info == null) {
            RedisUtil.set(name, this);
        }
    }


    static boolean isStored(String name, String org, SampleStore fs) {
        return fs.hasValue(toKeyValStoreName(name, org));
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public Set<String> getRoles() {
        return this.roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
        saveState();
    }

    @Override
    public String getAccount() {
        return this.account;
    }

    /**
     * Set the account.
     *
     * @param account The account.
     */
    public void setAccount(String account) {
        this.account = account;
        saveState();
    }

    @Override
    public String getAffiliation() {
        return this.affiliation;
    }

    /**
     * Set the affiliation.
     *
     * @param affiliation the affiliation.
     */
    public void setAffiliation(String affiliation) {
        this.affiliation = affiliation;
        saveState();
    }

    @Override
    public Enrollment getEnrollment() {
        return this.enrollment;
    }

    /**
     * 是否已经注册,注册完成之后enrollmentSecret是不为空的
     */
    public boolean isRegistered() {
        return !StringUtil.isNullOrEmpty(enrollmentSecret);
    }

    /**
     * 是否已经Enroll
     */
    public boolean isEnrolled() {
        return this.enrollment != null;
    }

    /**
     * 将用户的状态保存到键值对文件中
     * Save the state of this user to the key value store.
     */
    void saveState() {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(this);
            oos.flush();
            keyValStore.setValue(keyValStoreName, Hex.toHexString(bos.toByteArray()));
            bos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Restore the state of this user from the key value store (if found).  If not found, do nothing.
     */
    MedicalUser restoreState() {
        String memberStr = keyValStore.getValue(keyValStoreName);
        if (null != memberStr) {
            // The user was found in the key value store, so restore the
            // state.
            byte[] serialized = Hex.decode(memberStr);
            ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
            try {
                ObjectInputStream ois = new ObjectInputStream(bis);
                MedicalUser state = (MedicalUser) ois.readObject();
                if (state != null) {
                    this.name = state.name;
                    this.roles = state.roles;
                    this.account = state.account;
                    this.affiliation = state.affiliation;
                    this.organization = state.organization;
                    this.enrollmentSecret = state.enrollmentSecret;
                    this.enrollment = state.enrollment;
                    this.mspId = state.mspId;
                    return this;
                }
            } catch (Exception e) {
                throw new RuntimeException(String.format("Could not restore state of member %s", this.name), e);
            }
        }
        return null;
    }

    public String getEnrollmentSecret() {
        return enrollmentSecret;
    }

    public void setEnrollmentSecret(String enrollmentSecret) {
        this.enrollmentSecret = enrollmentSecret;
        saveState();
    }

    public void setEnrollment(Enrollment enrollment) {

        this.enrollment = enrollment;
        saveState();

    }

    public void setIdemixEnrollment(Enrollment enrollment) {
        this.enrollment = enrollment;
    }

    public static String toKeyValStoreName(String name, String org) {
        return "user." + name + org;
    }

    @Override
    public String getMspId() {
        return mspId;
    }

    String mspId;

    public void setMspId(String mspID) {
        this.mspId = mspID;
        saveState();

    }
}
