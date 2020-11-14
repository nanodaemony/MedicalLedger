/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *      http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric_ca.sdk;

import javax.json.JsonObject;

import org.junit.Assert;
import org.junit.Test;

/**
 * 注册请求测试
 * @author nano
 */
public class RegistrationRequestTest {
    /**
     * 属性名
     */
    private static final String attrName = "some name";

    /**
     * 属性值
     */
    private static final String attrValue = "some value";

    /**
     * 注册从属机构
     */
    private static final String regAffiliation = "corporation";

    /**
     * 注册CA名字
     */
    private static final String regCAName = "CA";

    /**
     * 注册ID
     */
    private static final String regID = "userid";

    /**
     * 注册密码
     */
    private static final String regSecret = "secret";

    /**
     * 注册类型: Peer Orderer Client User
     */
    private static final String regType = HFCAClient.HFCA_TYPE_CLIENT;

    /**
     * 注册最大的Enroll次数
     */
    private static final int regMaxEnrollments = 5;

    /**
     * 测试产生新实例
     */
    @Test
    public void testNewInstance() {
        try {
            RegistrationRequest testRegisterReq = new RegistrationRequest(regID, regAffiliation);
            Assert.assertEquals(testRegisterReq.getEnrollmentID(), regID);
            Assert.assertEquals(testRegisterReq.getType(), regType);
            Assert.assertEquals(testRegisterReq.getMaxEnrollments(), null);
            Assert.assertEquals(testRegisterReq.getAffiliation(), regAffiliation);
            Assert.assertTrue(testRegisterReq.getAttributes().isEmpty());

            JsonObject jo = testRegisterReq.toJsonObject();

            Assert.assertEquals(jo.getString("affiliation"), regAffiliation);
            Assert.assertFalse(jo.containsKey("max_enrollments"));
            Assert.assertEquals(regID, jo.getString("id"));

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test
    public void testNewInstanceNoAffiliation() {

        try {
            RegistrationRequest testRegisterReq = new RegistrationRequest(regID);
            testRegisterReq.setMaxEnrollments(3);

            Assert.assertEquals(regID, testRegisterReq.getEnrollmentID());
            Assert.assertEquals(regType, testRegisterReq.getType());
            Assert.assertEquals(new Integer(3), testRegisterReq.getMaxEnrollments());
            Assert.assertEquals(null, testRegisterReq.getAffiliation());
            Assert.assertTrue(testRegisterReq.getAttributes().isEmpty());

            JsonObject jo = testRegisterReq.toJsonObject();
            Assert.assertFalse(jo.containsKey("affiliation"));
            Assert.assertEquals(3, jo.getInt("max_enrollments"));
            Assert.assertEquals(regID, jo.getString("id"));

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test
    public void testNewInstanceSetNullID() {

        try {
            new RegistrationRequest(null, regAffiliation);
            Assert.fail("Expected exception when null is specified for id");

        } catch (Exception e) {
            Assert.assertEquals(e.getMessage(), "id may not be null");
        }
    }

    @Test
    public void testNewInstanceSetNullAffiliation() {

        try {
            new RegistrationRequest(regID, null);
            Assert.fail("Expected exception when null is specified for affiliation");

        } catch (Exception e) {
            Assert.assertEquals(e.getMessage(), "affiliation may not be null");
        }
    }

    @Test
    public void testRegisterReqSetGet() {

        try {
            RegistrationRequest testRegisterReq = new RegistrationRequest(regID, regAffiliation);
            testRegisterReq.setEnrollmentID(regID + "update");
            testRegisterReq.setSecret(regSecret);
            testRegisterReq.setMaxEnrollments(regMaxEnrollments);
            testRegisterReq.setType(regType);
            testRegisterReq.setAffiliation(regAffiliation + "update");
            testRegisterReq.setCAName(regCAName);
            testRegisterReq.addAttribute(new Attribute(attrName, attrValue));
            Assert.assertEquals(testRegisterReq.getEnrollmentID(), regID + "update");
            Assert.assertEquals(testRegisterReq.getSecret(), regSecret);
            Assert.assertEquals(testRegisterReq.getType(), regType);
            Assert.assertEquals(testRegisterReq.getAffiliation(), regAffiliation + "update");
            Assert.assertTrue(!testRegisterReq.getAttributes().isEmpty());

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test
    public void testRegisterReqToJson() {

        try {
            RegistrationRequest testRegisterReq = new RegistrationRequest(regID, regAffiliation);
            testRegisterReq.setEnrollmentID(regID + "update");
            testRegisterReq.setSecret(regSecret);
            testRegisterReq.setMaxEnrollments(regMaxEnrollments);
            testRegisterReq.setType(regType);
            testRegisterReq.setAffiliation(regAffiliation + "update");
            testRegisterReq.setCAName(regCAName);
            testRegisterReq.addAttribute(new Attribute(attrName, attrValue));

            Assert.assertTrue(testRegisterReq.toJson().contains(regAffiliation + "update"));

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }
}