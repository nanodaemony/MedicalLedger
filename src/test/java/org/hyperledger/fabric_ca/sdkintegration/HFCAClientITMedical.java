/*
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

package org.hyperledger.fabric_ca.sdkintegration;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.openssl.PEMParser;
import org.hyperledger.LogUtil;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.identity.IdemixEnrollment;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.hyperledger.fabric.sdkintegration.MedicalUser;
import org.hyperledger.fabric.sdkintegration.SampleStore;
import org.hyperledger.fabric_ca.sdk.Attribute;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAAffiliation;
import org.hyperledger.fabric_ca.sdk.HFCAAffiliation.HFCAAffiliationResp;
import org.hyperledger.fabric_ca.sdk.HFCACertificateRequest;
import org.hyperledger.fabric_ca.sdk.HFCACertificateResponse;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.HFCACredential;
import org.hyperledger.fabric_ca.sdk.HFCAIdentity;
import org.hyperledger.fabric_ca.sdk.HFCAInfo;
import org.hyperledger.fabric_ca.sdk.HFCAX509Certificate;
import org.hyperledger.fabric_ca.sdk.MockHFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric_ca.sdk.exception.IdentityException;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric_ca.sdk.exception.RevocationException;
import org.hyperledger.fabric_ca.sdk.helper.Config;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.StringReader;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.bind.DatatypeConverter;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.resetConfig;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.setField;
import static org.hyperledger.fabric_ca.sdk.HFCAClient.DEFAULT_PROFILE_NAME;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * HFCA测试
 *
 * @author nano
 */
public class HFCAClientITMedical {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    /**
     * 测试AdminName
     */
    private static final String ADMIN_NAME = "admin";

    /**
     * 测试Admin密码
     */
    private static final String ADMIN_PW = "adminpw";

    /**
     * 测试Admin的组织
     */
    private static final String ADMIN_ORG = "org1";

    /**
     * 测试User组织
     */
    private static final String USER1_ORG = "Org2";

    /**
     * 用户1的属性
     */
    private static final String USER1_AFFILIATION = "org1.department1";

    /**
     * 名称
     */
    private static final String TEST_WITH_INTEGRATION_ORG = "peerOrg1";
    private static final String TEST_WITH_INTEGRATION_ORG2 = "peerOrg2";

    /**
     * 文件存储变量
     */
    private SampleStore sampleStore;

    /**
     * CA代理对象
     */
    private HFCAClient caClient;

    /**
     * Admin用户
     */
    private MedicalUser adminUser;

    /**
     * 加密套件
     */
    private static CryptoSuite crypto;

    /**
     * 用户数
     */
    // Keeps track of how many test users we've created
    private static int userCount = 0;

    /**
     * 用户的统一前缀,加入随机时间保证不会重复
     */
    // Common prefix for all test users (the suffix will be the current user count)
    // Note that we include the time value so that these tests can be executed repeatedly
    // without needing to restart the CA (because you cannot register a username more than once!)
    private static String userNamePrefix = "user" + (System.currentTimeMillis() / 1000) + "_";

    /**
     * 采用默认配置
     */
    private static TestConfig testConfig = TestConfig.getConfig();

    /**
     * 类加载前初始化
     */
    @BeforeClass
    public static void init() throws Exception {

        out("\n\n\nRUNNING: HFCAClientEnrollIT.\n");
        // 重置配置
        resetConfig();
        // 获取默认的加密套件(此处可以指定算法的参数)
        crypto = CryptoSuite.Factory.getCryptoSuite();
    }

    /**
     * 测试之前初始化
     */
    @Before
    public void setup() throws Exception {

        // 初始化文件存储文件
        // C:\Users\nano\AppData\Local\Temp\HFCSampletest.properties
        // File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");
        // 指定文件存储位置
        File sampleStoreFile = new File("G:\\HFCSampletest.properties");
        // 如果存在先删除
        if (sampleStoreFile.exists()) { // For testing start fresh
            sampleStoreFile.delete();
        }
        // 重新生成
        sampleStore = new SampleStore(sampleStoreFile);
        Properties properties = new Properties();
        properties.setProperty("pemFile", "D:\\code\\11_Hyperledger\\blockchain-application-using-fabric-java-sdk\\network_resources\\crypto-config\\peerOrganizations\\org1.example.com\\ca\\ca.org1.example.com-cert.pem");
        properties.setProperty("allowAllHostNames", "true");

        // 创建CA实例
        caClient = HFCAClient.createNewInstance(
                // TEST_WITH_INTEGRATION_ORG = "peerOrg1"
                "http://172.20.29.67:7054",
                // testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                // {allowAllHostNames=true, pemFile=D:\code\12_Paper\fabric-sdk-java\src\test\fixture\sdkintegration\e2e-2Orgs\v1.3\crypto-config\peerOrganizations\org1.example.com\ca\ca.org1.example.com-cert.pem}
                // testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties()
                properties
        );

        // 设置加密套件
        caClient.setCryptoSuite(crypto);

        // 获取Admin用户
        // TEST_ADMIN_NAME = "admin"
        // TEST_ADMIN_ORG = "org1"
        adminUser = sampleStore.getMember(ADMIN_NAME, ADMIN_ORG);
        // Admin用户如果没有Enroll
        if (!adminUser.isEnrolled()) { // Preregistered admin only needs to be enrolled with Fabric CA.
            // 进行Enroll并获取Enrollment
            Enrollment enrollment = caClient.enroll("admin", "adminpw");
            adminUser.setEnrollment(enrollment);
            System.out.println(enrollment.toString() + "Enroll Admin------------------");
        }
        System.out.println(adminUser.toString() + "Enroll AdminUser------------------");
    }

    /**
     * 测试注册属性
     */
    @Test
    public void testRegisterAttributes() throws Exception {

        // 不会进入
        MedicalUser user = new MedicalUser("user8", "org1", sampleStore, crypto);
        // 构造注册请求
        // TEST_USER1_AFFILIATION = "org1.department1"
        RegistrationRequest regRequest = new RegistrationRequest(user.getName(), USER1_AFFILIATION);
        // 密码(如果自己设置了密码,后面的enrollmentSecret就是自己设置的密码,否则会自动返回一个密码)
        String password = "mrAttributespassword";
        regRequest.setSecret(null);

        // 添加Attribute属性
        regRequest.addAttribute(new Attribute("testattr1", "mrAttributesValue1"));
        regRequest.addAttribute(new Attribute("testattr2", "mrAttributesValue2"));
        regRequest.addAttribute(new Attribute("testattrDEFAULTATTR", "mrAttributesValueDEFAULTATTR", true));

        // 注册user并得到Enroll密码(需要传入AdminUser来注册)
        String enrollmentSecret = caClient.register(regRequest, adminUser);
        LogUtil.print(enrollmentSecret);
        // 给用户设置Enroll密码
        user.setEnrollmentSecret(enrollmentSecret);
        // 进行Enroll登记
        EnrollmentRequest enrollRequest = new EnrollmentRequest();
        // 添加Attribute
        enrollRequest.addAttrReq("testattr2").setOptional(false);
        // 利用上面得到的进行用户Enroll
        Enrollment userEnrollment = caClient.enroll(user.getName(), user.getEnrollmentSecret(), enrollRequest);
        // 设置Enrollment到用户属性中
        user.setEnrollment(userEnrollment);

        // 康康刚才得到的Enrollment信息
        Enrollment enrollment = user.getEnrollment();
        // 获取证书字符串
        String cert = enrollment.getCert();
        LogUtil.print(cert);
        // cert字符串长下面的样子
        // -----BEGIN CERTIFICATE-----
        //MIICXzCCAgWgAwIBAgIUFxRvTEfPtOU1mAq/8ZLc6ADrKggwCgYIKoZIzj0EAwIw
        //czELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
        //biBGcmFuY2lzY28xGTAXBgNVBAoTEG9yZzEuZXhhbXBsZS5jb20xHDAaBgNVBAMT
        //E2NhLm9yZzEuZXhhbXBsZS5jb20wHhcNMjAxMTEyMDkxMDAwWhcNMjExMTEyMDkx
        //NTAwWjBCMTAwDQYDVQQLEwZjbGllbnQwCwYDVQQLEwRvcmcxMBIGA1UECxMLZGVw
        //YXJ0bWVudDExDjAMBgNVBAMTBXVzZXI2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
        //QgAEWJlxjufW5+kAwmCduA4wd9QhgRzG16IUlbe+h+67K6Af9evLCjTKe5st2gK5
        //UDDkq5lHdAWuvGHNspectlnoHKOBpzCBpDAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0T
        //AQH/BAIwADAdBgNVHQ4EFgQUWliSF2ScqODwxkPQMCN6DXsB6OwwKwYDVR0jBCQw
        //IoAgscw0w/LQz4B4aPo6GhGHTSBBMIRf2O6zbS5ZRNd2dxwwOAYIKgMEBQYHCAEE
        //LHsiYXR0cnMiOnsidGVzdGF0dHIyIjoibXJBdHRyaWJ1dGVzVmFsdWUyIn19MAoG
        //CCqGSM49BAMCA0gAMEUCIQCcWwzNZ72YGl95xIGRWdR7zOaScCiyNOTmiff4QN3R
        //RQIgdNAMZ/896lHOcDxQFDxZLVnILIaUN69xgpuVCmx2iLc=
        //-----END CERTIFICATE-----

        String certDec = getStringCert(cert);
        LogUtil.print(certDec);
        // 下面是康康certDec中是否包含上述设置的属性
        assertTrue(format("Missing testattr2 in certficate decoded: %s", certDec), certDec.contains("\"testattr2\":\"mrAttributesValue2\""));
        //Since request had specific attributes don't expect defaults.
        assertFalse(format("Contains testattrDEFAULTATTR in certificate decoded: %s", certDec), certDec.contains("\"testattrDEFAULTATTR\"")
                || certDec.contains("\"mrAttributesValueDEFAULTATTR\""));
        assertFalse(format("Contains testattr1 in certificate decoded: %s", certDec), certDec.contains("\"testattr1\"") || certDec.contains("\"mrAttributesValue1\""));
    }


    /**
     * 测试登记时没有属性
     * Test that we get no attributes.
     */
    @Test
    public void testRegisterAttributesNONE() throws Exception {

        MedicalUser user = new MedicalUser("user" + System.currentTimeMillis(), "org1", sampleStore, crypto);

        RegistrationRequest registrationRequest = new RegistrationRequest(user.getName(), USER1_AFFILIATION);
        String password = "mrAttributespassword";
        registrationRequest.setSecret(password);

        registrationRequest.addAttribute(new Attribute("testattr1", "mrAttributesValue1"));
        registrationRequest.addAttribute(new Attribute("testattr2", "mrAttributesValue2"));
        registrationRequest.addAttribute(new Attribute("testattrDEFAULTATTR", "mrAttributesValueDEFAULTATTR", true));
        user.setEnrollmentSecret(caClient.register(registrationRequest, adminUser));

        EnrollmentRequest enrollmentRequest = new EnrollmentRequest();

        // 这里Enroll时不加任何属性
        // empty ensure no attributes.
        enrollmentRequest.addAttrReq();

        user.setEnrollment(caClient.enroll(user.getName(), user.getEnrollmentSecret(), enrollmentRequest));
        Enrollment enrollment = user.getEnrollment();
        String cert = enrollment.getCert();
        String certdec = getStringCert(cert);

        assertFalse(format("Contains testattrDEFAULTATTR in certificate decoded: %s", certdec),
                certdec.contains("\"testattrDEFAULTATTR\"") || certdec.contains("\"mrAttributesValueDEFAULTATTR\""));
        assertFalse(format("Contains testattr1 in certificate decoded: %s", certdec), certdec.contains("\"testattr1\"") || certdec.contains("\"mrAttributesValue1\""));
        assertFalse(format("Contains testattr2 in certificate decoded: %s", certdec), certdec.contains("\"testattr2\"") || certdec.contains("\"mrAttributesValue2\""));
    }

    /**
     * 解析Pattern
     */
    private static final Pattern compile = Pattern.compile("^-----BEGIN CERTIFICATE-----$"
                    + "(.*?)" + "\n-----END CERTIFICATE-----\n",
            Pattern.DOTALL | Pattern.MULTILINE);

    /**
     * 获取String形式的证书
     */
    static String getStringCert(String pemFormat) {
        String res = null;
        final Matcher matcher = compile.matcher(pemFormat);
        if (matcher.matches()) {
            final String base64part = matcher.group(1).replaceAll("\n", "");
            // 使用Base64解码
            Base64.Decoder b64dec = Base64.getDecoder();
            res = new String(b64dec.decode(base64part.getBytes(UTF_8)));
        } else {
            fail("Certificate failed to match expected pattern. Certificate:\n" + pemFormat);
        }
        return res;
    }

    /**
     * 测试重新登记用户
     * Tests re-enrolling a user that has had an enrollment revoked
     */
    @Test
    public void testReenrollAndRevoke() throws Exception {

        // 从本地获取User
        MedicalUser user = getTestUser("org1");

        // 如果没有注册与登记则重新注册与登记
        // users need to be registered AND enrolled
        if (!user.isRegistered()) {
            RegistrationRequest rr = new RegistrationRequest(user.getName(), USER1_AFFILIATION);
            String password = "testReenrollAndRevoke";
            rr.setSecret(password);
            user.setEnrollmentSecret(caClient.register(rr, adminUser));
            if (!user.getEnrollmentSecret().equals(password)) {
                fail("Secret returned from RegistrationRequest not match : " + user.getEnrollmentSecret());
            }
        }
        // 如果没有登记
        if (!user.isEnrolled()) {
            user.setEnrollment(caClient.enroll(user.getName(), user.getEnrollmentSecret()));
        }

        sleepALittle();

        // get another enrollment
        // 构造另一个登记请求
        EnrollmentRequest enrollmentRequest = new EnrollmentRequest(DEFAULT_PROFILE_NAME, "label 1", null);
        // 添加Host
        enrollmentRequest.addHost("example1.ibm.com");
        enrollmentRequest.addHost("example2.ibm.com");
        // 临时Enroll
        Enrollment tmpEnroll = caClient.reenroll(user, enrollmentRequest);
        // verify
        String cert = tmpEnroll.getCert();
        verifyOptions(cert, enrollmentRequest);

        sleepALittle();

        // revoke one enrollment of this user
        // 去掉这个用户的一个Enrollment
        caClient.revoke(adminUser, tmpEnroll, "remove user 2");

        // trying to reenroll should be ok (revocation above is only for a particular enrollment of this user)
        caClient.reenroll(user);
    }

    // Tests attempting to re-enroll a revoked user
    @Test
    public void testUserRevoke() throws Exception {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("Failed to re-enroll user");

        Calendar calendar = Calendar.getInstance(); // gets a calendar using the default time zone and locale.
        Date revokedTinyBitAgoTime = calendar.getTime(); //avoid any clock skewing.

        MedicalUser user = getTestUser(USER1_ORG);

        if (!user.isRegistered()) {
            RegistrationRequest rr = new RegistrationRequest(user.getName(), USER1_AFFILIATION);
            String password = "testUserRevoke";
            rr.setSecret(password);
            rr.addAttribute(new Attribute("user.role", "department lead"));
            rr.addAttribute(new Attribute(HFCAClient.HFCA_ATTRIBUTE_HFREVOKER, "true"));
            user.setEnrollmentSecret(caClient.register(rr, adminUser)); // Admin can register other users.
            if (!user.getEnrollmentSecret().equals(password)) {
                fail("Secret returned from RegistrationRequest not match : " + user.getEnrollmentSecret());
            }
        }

        if (!user.isEnrolled()) {
            EnrollmentRequest req = new EnrollmentRequest(DEFAULT_PROFILE_NAME, "label 2", null);
            req.addHost("example3.ibm.com");
            user.setEnrollment(caClient.enroll(user.getName(), user.getEnrollmentSecret(), req));

            // verify
            String cert = user.getEnrollment().getCert();
            verifyOptions(cert, req);
        }

        int startedWithRevokes = -1;

        if (!testConfig.isRunningAgainstFabric10()) {
            Thread.sleep(1000); //prevent clock skewing. make sure we request started with revokes.
            startedWithRevokes = getRevokes(null).length; //one more after we do this revoke.
            Thread.sleep(1000); //prevent clock skewing. make sure we request started with revokes.
        }

        // revoke all enrollment of this user
        caClient.revoke(adminUser, user.getName(), "revoke user 3");
        if (!testConfig.isRunningAgainstFabric10()) {

            final int newRevokes = getRevokes(null).length;

            assertEquals(format("Expected one more revocation %d, but got %d", startedWithRevokes + 1, newRevokes), startedWithRevokes + 1, newRevokes);

            // see if we can get right number of revokes that we started with by specifying the time: revokedTinyBitAgoTime
            // TODO: Investigate clock scew
//            final int revokestinybitago = getRevokes(revokedTinyBitAgoTime).length; //Should be same number when test case was started.
//            assertEquals(format("Expected same revocations %d, but got %d", startedWithRevokes, revokestinybitago), startedWithRevokes, revokestinybitago);
        }

        // trying to reenroll the revoked user should fail with an EnrollmentException
        caClient.reenroll(user);
    }

    /**
     * 测试撤销证书
     * Tests revoking a certificate
     */
    @Test
    public void testCertificateRevoke() throws Exception {

        MedicalUser user = getTestUser(USER1_ORG);

        // 如果用户没有注册
        if (!user.isRegistered()) {
            RegistrationRequest registrationRequest = new RegistrationRequest(user.getName(), "org1.department1");
            String password = "testUserRevoke";
            registrationRequest.setSecret(password);
            // 指定角色为部门领导
            registrationRequest.addAttribute(new Attribute("user.role", "department lead"));
            registrationRequest.addAttribute(new Attribute(HFCAClient.HFCA_ATTRIBUTE_HFREVOKER, "true"));
            // Admin can register other users.
            user.setEnrollmentSecret(caClient.register(registrationRequest, adminUser));
            if (!user.getEnrollmentSecret().equals(password)) {
                fail("Secret returned from RegistrationRequest not match : " + user.getEnrollmentSecret());
            }
        }

        if (!user.isEnrolled()) {
            EnrollmentRequest req = new EnrollmentRequest(DEFAULT_PROFILE_NAME, "label 2", null);
            req.addHost("example3.ibm.com");
            user.setEnrollment(caClient.enroll(user.getName(), user.getEnrollmentSecret(), req));
        }

        // verify
        String cert = user.getEnrollment().getCert();

        // 通过证书来获取输入流
        BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(cert.getBytes()));
        CertificateFactory certFactory = CertificateFactory.getInstance(Config.getConfig().getCertificateFormat());
        // 通过证书流产生证书,由此可以得到私钥公钥等文件
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(pem);

        // 获取证书的序列号
        String serial = DatatypeConverter.printHexBinary(certificate.getSerialNumber().toByteArray());

        // get its aki
        // 2.5.29.35 : AuthorityKeyIdentifier 颁发机构密钥标识符
        byte[] extensionValue = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        ASN1OctetString akiOc = ASN1OctetString.getInstance(extensionValue);
        String aki = DatatypeConverter.printHexBinary(AuthorityKeyIdentifier.getInstance(akiOc.getOctets()).getKeyIdentifier());

        int startedWithRevokes = -1;

        if (!testConfig.isRunningAgainstFabric10()) {
            Thread.sleep(1000); // prevent clock skewing. make sure we request started with revokes.
            startedWithRevokes = getRevokes(null).length; //one more after we do this revoke.
            Thread.sleep(1000); // prevent clock skewing. make sure we request started with revokes.
        }

        // 撤销这个用户的全部Enrollment
        caClient.revoke(adminUser, serial, aki, "revoke certificate");
        if (!testConfig.isRunningAgainstFabric10()) {
            final int newRevokes = getRevokes(null).length;
            assertEquals(format("Expected one more revocation %d, but got %d", startedWithRevokes + 1, newRevokes), startedWithRevokes + 1, newRevokes);
        }
    }


    // Tests revoking a user with genCRL using the revoke API
    @Test
    public void testUserRevokeGenCRL() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("Failed to re-enroll user");

        Calendar calendar = Calendar.getInstance(); // gets a calendar using the default time zone and locale.
        calendar.add(Calendar.SECOND, -1);
        Date revokedTinyBitAgoTime = calendar.getTime(); //avoid any clock skewing.

        MedicalUser user1 = getTestUser(USER1_ORG);
        MedicalUser user2 = getTestUser(USER1_ORG);

        MedicalUser[] users = new MedicalUser[]{user1, user2};

        for (MedicalUser user : users) {
            if (!user.isRegistered()) {
                RegistrationRequest rr = new RegistrationRequest(user.getName(), USER1_AFFILIATION);
                String password = "testUserRevoke";
                rr.setSecret(password);
                rr.addAttribute(new Attribute("user.role", "department lead"));
                rr.addAttribute(new Attribute(HFCAClient.HFCA_ATTRIBUTE_HFREVOKER, "true"));
                user.setEnrollmentSecret(caClient.register(rr, adminUser)); // Admin can register other users.
                if (!user.getEnrollmentSecret().equals(password)) {
                    fail("Secret returned from RegistrationRequest not match : " + user.getEnrollmentSecret());
                }
            }

            sleepALittle();

            if (!user.isEnrolled()) {
                EnrollmentRequest req = new EnrollmentRequest(DEFAULT_PROFILE_NAME, "label 2", null);
                req.addHost("example3.ibm.com");
                user.setEnrollment(caClient.enroll(user.getName(), user.getEnrollmentSecret(), req));

                // verify
                String cert = user.getEnrollment().getCert();
                verifyOptions(cert, req);
            }
        }

        sleepALittle();

        int startedWithRevokes = -1;

        startedWithRevokes = getRevokes(null).length; //one more after we do this revoke.

        // revoke all enrollment of this user and request back a CRL
        String crl = caClient.revoke(adminUser, user1.getName(), null, true);
        assertNotNull("Failed to get CRL using the Revoke API", crl);

        final int newRevokes = getRevokes(null).length;

        assertEquals(format("Expected one more revocation %d, but got %d", startedWithRevokes + 1, newRevokes), startedWithRevokes + 1, newRevokes);

        final int crlLength = parseCRL(crl).length;

        assertEquals(format("The number of revokes %d does not equal the number of revoked certificates (%d) in crl", newRevokes, crlLength), newRevokes, crlLength);

        // trying to reenroll the revoked user should fail with an EnrollmentException
        caClient.reenroll(user1);

        String crl2 = caClient.revoke(adminUser, user2.getName(), null, false);
        assertEquals("CRL not requested, CRL should be empty", "", crl2);

    }

    TBSCertList.CRLEntry[] getRevokes(Date r) throws Exception {

        String crl = caClient.generateCRL(adminUser, r, null, null, null);

        return parseCRL(crl);
    }

    TBSCertList.CRLEntry[] parseCRL(String crl) throws Exception {

        Base64.Decoder b64dec = Base64.getDecoder();
        final byte[] decode = b64dec.decode(crl.getBytes(UTF_8));

        PEMParser pem = new PEMParser(new StringReader(new String(decode)));
        X509CRLHolder holder = (X509CRLHolder) pem.readObject();

        return holder.toASN1Structure().getRevokedCertificates();
    }

    /**
     * 测试获取一个身份☆
     * Tests getting an identity
     */
    @Test
    public void testCreateAndGetIdentity() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        // 获取一个identity(看方法进行深度定义)
        HFCAIdentity identity = getIdentityReq("testuser2", HFCAClient.HFCA_TYPE_PEER);

        // 使用admin用户创建定义的identity
        identity.create(adminUser);

        // 从CA获取Identity
        // 这里EnrollmentId就是上面传入的ID
        HFCAIdentity hfcaIdentity = caClient.newHFCAIdentity(identity.getEnrollmentId());
        // 读取检索特定标识
        hfcaIdentity.read(adminUser);

        assertEquals("Incorrect response for id", identity.getEnrollmentId(), hfcaIdentity.getEnrollmentId());
        assertEquals("Incorrect response for type", identity.getType(), hfcaIdentity.getType());
        assertEquals("Incorrect response for affiliation", identity.getAffiliation(), hfcaIdentity.getAffiliation());
        assertEquals("Incorrect response for max enrollments", identity.getMaxEnrollments(), hfcaIdentity.getMaxEnrollments());

        // 获取属性
        Collection<Attribute> attributes = hfcaIdentity.getAttributes();
        boolean found = false;
        for (Attribute attr : attributes) {
            if (attr.getName().equals("testattr1")) {
                found = true;
                break;
            }
        }
        if (!found) {
            fail("Incorrect response for attribute");
        }
    }


    /**
     * 测试获取一个调用者的全部identity
     * Tests getting all identities for a caller
     */
    @Test
    public void testGetAllIdentity() throws Exception {
        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        HFCAIdentity identity = getIdentityReq("testuser2", HFCAClient.HFCA_TYPE_CLIENT);
        identity.create(adminUser);

        Collection<HFCAIdentity> foundIdentities = caClient.getHFCAIdentities(adminUser);
        String[] expectedIdentities = new String[]{"testuser2", "admin"};
        int found = 0;

        for (HFCAIdentity id : foundIdentities) {
            for (String name : expectedIdentities) {
                if (id.getEnrollmentId().equals(name)) {
                    found++;
                }
            }
        }
        if (found != 2) {
            fail("Failed to get the correct number of identities");
        }

    }

    /**
     * 测试修改一个Identity
     * Tests modifying an identity
     */
    @Test
    public void testModifyIdentity() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        HFCAIdentity identity = getIdentityReq("testuser3", HFCAClient.HFCA_TYPE_ORDERER);
        identity.create(adminUser);
        assertEquals("Incorrect response for type", "orderer", identity.getType());
        assertNotEquals("Incorrect value for max enrollments", identity.getMaxEnrollments(), new Integer(5));

        identity.setMaxEnrollments(5);
        identity.update(adminUser);
        assertEquals("Incorrect value for max enrollments", identity.getMaxEnrollments(), new Integer(5));

        // 修改最大的登记数量
        identity.setMaxEnrollments(100);
        // 200
        System.out.println(identity.read(adminUser));
        assertEquals("Incorrect value for max enrollments", new Integer(5), identity.getMaxEnrollments());
    }

    /**
     * 测试删除一个Identity
     * Tests deleting an identity
     */
    @Test
    public void testDeleteIdentity() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        thrown.expect(IdentityException.class);
        thrown.expectMessage("Failed to get User");

        MedicalUser user = new MedicalUser("testuser4", ADMIN_ORG, sampleStore, caClient.getCryptoSuite());

        HFCAIdentity identity = caClient.newHFCAIdentity(user.getName());
        // 创建
        identity.create(adminUser);
        // 删除
        identity.delete(adminUser);
        // read(失败)
        System.out.println(identity.read(adminUser));
    }

    /**
     * 测试删除一个Identity并确保它不能再update
     * Tests deleting an identity and making sure it can't update after deletion
     */
    @Test
    public void testDeleteIdentityFailUpdate() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        thrown.expect(IdentityException.class);
        thrown.expectMessage("Identity has been deleted");

        HFCAIdentity identity = caClient.newHFCAIdentity("deletedUser");
        // 创建
        identity.create(adminUser);
        // 删除
        identity.delete(adminUser);
        // 更新(失败)
        identity.update(adminUser);
    }


    /**
     * 测试获取一个affiliation隶属关系
     * Tests getting an affiliation
     */
    @Test
    public void testGetAffiliation() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        HFCAAffiliation hfcaAffiliation = caClient.newHFCAAffiliation("org2");
        // org2
        LogUtil.print(hfcaAffiliation.getName());
        // 200
        int resp = hfcaAffiliation.read(adminUser);

        // 获取子Affiliation,这里是org2.department1
        System.out.println(hfcaAffiliation.getChild("department1").getName());

        assertEquals("Incorrect response for affiliation name", "org2", hfcaAffiliation.getName());
        assertEquals("Incorrect response for child affiliation name", "org2.department1", hfcaAffiliation.getChild("department1").getName());
        assertEquals("Incorrect status code", new Integer(200), new Integer(resp));
    }

    /**
     * 测试获取所有的affiliation
     * Tests getting all affiliation
     */
    @Test
    public void testGetAllAffiliation() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        HFCAAffiliation resp = caClient.getHFCAAffiliations(adminUser);

        // 期望的第一级组织
        ArrayList<String> expectedFirstLevelAffiliations = new ArrayList<String>(Arrays.asList("org2", "org1"));

        int found = 0;

        // org1 org2
        for (HFCAAffiliation affiliation : resp.getChildren()) {
            LogUtil.print(affiliation.getName());
        }

        // 不断移除看列表是不是为空
        for (HFCAAffiliation aff : resp.getChildren()) {
            for (Iterator<String> iter = expectedFirstLevelAffiliations.iterator(); iter.hasNext();) {
                String element = iter.next();
                if (aff.getName().equals(element)) {
                    iter.remove();
                }
            }
        }

        if (!expectedFirstLevelAffiliations.isEmpty()) {
            fail("Failed to get the correct of affiliations, affiliations not returned: %s" + expectedFirstLevelAffiliations.toString());
        }

        // 打印全部的二级部门
        // org2.department1
        // org1.department1
        // org1.department2
        for (HFCAAffiliation aff : resp.getChildren()) {
            for (HFCAAffiliation aff2 : aff.getChildren()) {
                LogUtil.print(aff2.getName());
            }
        }

        // 期待的第二级属性
        ArrayList<String> expectedSecondLevelAffiliations = new ArrayList<String>(Arrays.asList("org2.department1", "org1.department1", "org1.department2"));
        for (HFCAAffiliation aff : resp.getChildren()) {
            for (HFCAAffiliation aff2 : aff.getChildren()) {
                expectedSecondLevelAffiliations.removeIf(element -> aff2.getName().equals(element));
            }
        }
        if (!expectedSecondLevelAffiliations.isEmpty()) {
            fail("Failed to get the correct child affiliations, affiliations not returned: %s" + expectedSecondLevelAffiliations.toString());
        }
    }

    /**
     * 测试添加一个联盟affiliation
     * Tests adding an affiliation
     */
    @Test
    public void testCreateAffiliation() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        // 创建新的联盟Org3对象
        HFCAAffiliation aff = caClient.newHFCAAffiliation("org3");
        // 使用Admin用户创建联盟
        HFCAAffiliationResp resp = aff.create(adminUser);

        assertEquals("Incorrect status code", new Integer(201), new Integer(resp.getStatusCode()));
        assertEquals("Incorrect response for id", "org3", aff.getName());
        // 获取联盟下面的子联盟(应该是0)
        Collection<HFCAAffiliation> children = aff.getChildren();
        assertEquals("Should have no children", 0, children.size());
    }

    /**
     * 测试更新一个联盟
     * Tests updating an affiliation
     */
    @Test
    public void testUpdateAffiliation() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }
        // 新建一个联盟4
        HFCAAffiliation aff = caClient.newHFCAAffiliation("org4");
        aff.create(adminUser);
        // 创建一个Identity
        HFCAIdentity identity = caClient.newHFCAIdentity("testuser_org4");
        // 设置当前用户属于什么联盟
        identity.setAffiliation(aff.getName());
        // 创建Identity
        identity.create(adminUser);

        // 在联盟4下面再次创建二级联盟org4.dept1
        HFCAAffiliation aff2 = caClient.newHFCAAffiliation("org4.dept1");
        aff2.create(adminUser);

        // 创建这个二级联盟下的Identity
        HFCAIdentity identity2 = caClient.newHFCAIdentity("testuser_org4.dept1");
        identity2.setAffiliation("org4.dept1");
        identity2.create(adminUser);

        // 在联盟4下面再次创建三级联盟org4.dept1.team1
        HFCAAffiliation aff3 = caClient.newHFCAAffiliation("org4.dept1.team1");
        aff3.create(adminUser);

        HFCAIdentity identity3 = caClient.newHFCAIdentity("testuser_org4.dept1.team1");
        identity3.setAffiliation("org4.dept1.team1");
        identity3.create(adminUser);

        // 将org4设置为org5
        aff.setUpdateName("org5");
        // Set force option to true, since their identities associated with affiliations
        // that are getting updated
        // 设置强制更新,这样关联的联盟都会更新(重要！！！☆)
        HFCAAffiliationResp resp = aff.update(adminUser, true);

        int found = 0;
        int idCount = 0;
        // Should contain the affiliations affected by the update request
        HFCAAffiliation child = aff.getChild("dept1");
        assertNotNull(child);
        // 现在一级联盟已经变成org5.dept1
        assertEquals("Failed to get correct child affiliation", "org5.dept1", child.getName());
        for (HFCAIdentity id : child.getIdentities()) {
            if (id.getEnrollmentId().equals("testuser_org4.dept1")) {
                idCount++;
            }
        }
        HFCAAffiliation child2 = child.getChild("team1");
        assertNotNull(child2);
        assertEquals("Failed to get correct child affiliation", "org5.dept1.team1", child2.getName());
        for (HFCAIdentity id : child2.getIdentities()) {
            if (id.getEnrollmentId().equals("testuser_org4.dept1.team1")) {
                idCount++;
            }
        }

        for (HFCAIdentity id : aff.getIdentities()) {
            if (id.getEnrollmentId().equals("testuser_org4")) {
                idCount++;
            }
        }

        if (idCount != 3) {
            fail("Incorrect number of ids returned");
        }

        assertEquals("Incorrect response for id", "org5", aff.getName());
        assertEquals("Incorrect status code", new Integer(200), new Integer(resp.getStatusCode()));
    }


    /**
     * 测试更新一个联盟但是不配置强制更新(跟上一个测试对应)
     * Tests updating an affiliation that doesn't require force option
     */
    @Test
    public void testUpdateAffiliationNoForce() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        HFCAAffiliation aff = caClient.newHFCAAffiliation("org_5");
        aff.create(adminUser);
        aff.setUpdateName("org_6");
        // 不设置强制更新
        HFCAAffiliationResp resp = aff.update(adminUser, false);

        assertEquals("Incorrect status code", new Integer(200), new Integer(resp.getStatusCode()));
        assertEquals("Failed to delete affiliation", "org_6", aff.getName());
    }

    /**
     * 尝试更新一个拥有子联盟和身份的联盟
     * 如果不指定force属性会失败
     * Trying to update affiliations with child affiliations and identities should fail if not using 'force' option.
     */
    @Test
    public void testUpdateAffiliationInvalid() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        thrown.expectMessage("Need to use 'force' to remove identities and affiliation");

        HFCAAffiliation aff = caClient.newHFCAAffiliation("org1.dept1");
        aff.create(adminUser);

        HFCAAffiliation aff2 = aff.createDecendent("team1");
        aff2.create(adminUser);

        HFCAIdentity ident = getIdentityReq("testorg1dept1", "client");
        ident.setAffiliation(aff.getName());
        ident.create(adminUser);

        aff.setUpdateName("org1.dept2");
        // 不指定force属性
        HFCAAffiliationResp resp = aff.update(adminUser);
        // 会更新失败
        assertEquals("Incorrect status code", new Integer(400), new Integer(resp.getStatusCode()));
    }

    /**
     * 测试删除一个联盟
     * Tests deleting an affiliation
     */
    @Test
    public void testDeleteAffiliation() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        thrown.expectMessage("Affiliation has been deleted");

        HFCAAffiliation aff = caClient.newHFCAAffiliation("org6");
        aff.create(adminUser);

        HFCAIdentity identity = caClient.newHFCAIdentity("testuser_org6");
        identity.setAffiliation("org6");
        identity.create(adminUser);

        HFCAAffiliation aff2 = caClient.newHFCAAffiliation("org6.dept1");
        aff2.create(adminUser);

        HFCAIdentity ident2 = caClient.newHFCAIdentity("testuser_org6.dept1");
        ident2.setAffiliation("org6.dept1");
        ident2.create(adminUser);

        HFCAAffiliationResp resp = aff.delete(adminUser, true);
        int idCount = 0;
        boolean found = false;
        for (HFCAAffiliation childAff : resp.getChildren()) {
            if (childAff.getName().equals("org6.dept1")) {
                found = true;
            }
            for (HFCAIdentity id : childAff.getIdentities()) {
                if (id.getEnrollmentId().equals("testuser_org6.dept1")) {
                    idCount++;
                }
            }
        }

        for (HFCAIdentity id : resp.getIdentities()) {
            if (id.getEnrollmentId().equals("testuser_org6")) {
                idCount++;
            }
        }

        if (!found) {
            fail("Incorrect response received");
        }

        if (idCount != 2) {
            fail("Incorrect number of ids returned");
        }

        assertEquals("Incorrect status code", new Integer(200), new Integer(resp.getStatusCode()));
        assertEquals("Failed to delete affiliation", "org6", aff.getName());

        // 删除联盟
        aff.delete(adminUser);
    }

    /**
     * 尝试不用force配置删除联盟
     */
    @Test
    public void testDeleteAffiliationNoForce() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        HFCAAffiliation aff = caClient.newHFCAAffiliation("org6");
        aff.create(adminUser);
        HFCAAffiliationResp resp = aff.delete(adminUser);

        assertEquals("Incorrect status code", new Integer(200), new Integer(resp.getStatusCode()));
        assertEquals("Failed to delete affiliation", "org6", aff.getName());
    }


    /**
     * 尝试不用force配置删除带有子联盟与身份的联盟,会失败
     * Trying to delete affiliation with child affiliations and identities should result in an error without force option.
     */
    @Test
    public void testForceDeleteAffiliationInvalid() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        thrown.expectMessage("Authorization failure");

        HFCAAffiliation aff = caClient.newHFCAAffiliation("org1.dept3");
        aff.create(adminUser);

        HFCAAffiliation aff2 = caClient.newHFCAAffiliation("org1.dept3.team1");
        aff2.create(adminUser);

        HFCAIdentity identity = getIdentityReq("testorg1dept3", "client");
        identity.setAffiliation("org1.dept3");
        identity.create(adminUser);

        HFCAAffiliationResp resp = aff.delete(adminUser);
        assertEquals("Incorrect status code", new Integer(401), new Integer(resp.getStatusCode()));
    }

    /**
     * 测试在不允许删除联盟的CA删除联盟
     * Tests deleting an affiliation on CA that does not allow affiliation removal
     */
    @Test
    public void testDeleteAffiliationNotAllowed() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        thrown.expectMessage("Authorization failure");

        HFCAClient client2 = HFCAClient.createNewInstance(
                "http://172.20.29.67:8054",
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG2).getCAProperties());
        client2.setCryptoSuite(crypto);

        MedicalUser admin2 = sampleStore.getMember(ADMIN_NAME, "org2");
        if (!admin2.isEnrolled()) { // Preregistered admin only needs to be enrolled with Fabric CA.
            admin2.setEnrollment(client2.enroll(admin2.getName(), ADMIN_PW));
        }

        // CA2不允许删除联盟
        HFCAAffiliation aff = client2.newHFCAAffiliation("org6");
        HFCAAffiliationResp resp = aff.delete(admin2);
        assertEquals("Incorrect status code", new Integer(400), new Integer(resp.getStatusCode()));
    }

    /**
     * 测试获取CA的信息
     * Tests getting server/ca information
     */
    @Test
    public void testGetInfo() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            HFCAInfo info = caClient.info();
            assertNull(info.getVersion());
        }
        // 进入这里
        if (testConfig.isFabricVersionAtOrAfter("1.3")) {
            HFCAInfo info = caClient.info();
            assertNotNull("client.info returned null.", info);
            String version = info.getVersion();
            assertNotNull("client.info.getVersion returned null.", version);
            assertTrue(format("Version '%s' didn't match expected pattern", version), version.matches("^\\d+\\.\\d+\\.\\d+($|-.*)"));

            // 下面是可以看的CA信息
            // LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNRekNDQWVxZ0F3SUJBZ0lSQU0vdmFEdlBzeUlpQzlodm41bm5SOEF3Q2dZSUtvWkl6ajBFQXdJd2N6RUwKTUFrR0ExVUVCaE1DVlZNeEV6QVJCZ05WQkFnVENrTmhiR2xtYjNKdWFXRXhGakFVQmdOVkJBY1REVk5oYmlCRwpjbUZ1WTJselkyOHhHVEFYQmdOVkJBb1RFRzl5WnpFdVpYaGhiWEJzWlM1amIyMHhIREFhQmdOVkJBTVRFMk5oCkxtOXlaekV1WlhoaGJYQnNaUzVqYjIwd0hoY05NVGd3TWpJMU1USTBNekk1V2hjTk1qZ3dNakl6TVRJME16STUKV2pCek1Rc3dDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVDQk1LUTJGc2FXWnZjbTVwWVRFV01CUUdBMVVFQnhNTgpVMkZ1SUVaeVlXNWphWE5qYnpFWk1CY0dBMVVFQ2hNUWIzSm5NUzVsZUdGdGNHeGxMbU52YlRFY01Cb0dBMVVFCkF4TVRZMkV1YjNKbk1TNWxlR0Z0Y0d4bExtTnZiVEJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUEKQkxxSTlkWDdkOU5HbzNndUw1RlA4b3RHc2lCak43QnpkNmRHL0NheUpEZmpOUkczNFlPOHQyOTl1NkVvRlh2egpwY2pBTUd1MFVLVHJ6TWZjeU91emNNeWpYekJkTUE0R0ExVWREd0VCL3dRRUF3SUJwakFQQmdOVkhTVUVDREFHCkJnUlZIU1VBTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3S1FZRFZSME9CQ0lFSUxITU5NUHkwTStBZUdqNk9ob1IKaDAwZ1FUQ0VYOWp1czIwdVdVVFhkbmNjTUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUY3V2wzQTExekVOcjFDbwpxR3l1M2g0ZkN1a2t0RlZ5Ry9XUEpVeWxWWGpJQWlCOUxqcFhtOUVSZ0pNZlpzakRJekNqOU00YVF1Vk45WExrClhueDB1b0t6N2c9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
            LogUtil.print(info.getCACertificateChain());
            // 1.4.9
            LogUtil.print(info.getVersion());
            // ca0
            LogUtil.print(info.getCAName());
            // CgJPVQoEUm9sZQoMRW5yb2xsbWVudElEChBSZXZvY2F0aW9uSGFuZGxlEkQKIDwI9XgGar29lWsgJQ5P++7nzIIlwWWGLEJ51ykde2A1EiCqCseWTnj4fux5l9ozepRqBhlZDfRZQFOKy755TIRikhpECiBvNt5Wcruon1yTI2OEtyActT1S0GLFcfCWXRMFykliiBIgL2P8/HJvbEI5pLb0LgoTUA1JDYYS+/MKC5irpY6t25wiRAogCAVRXVLX9SAwPD64Io0XEBFzpU0AOLnlUO84CJEN/XMSINGlHg7UFotyrB8gssFv3O56azHl+2X+k0nC2fS4IJY7IkQKILXIuSKsaLPOEnzyALvLpiW5rwRrAZZGHtkGx4CDUyY3EiDTMRCTEROrAXB/ZINA+RP3FzeUgnDLxLOes+OubkOQIyJECiA0wS8aoljJ6XkaAm6viC3+OY1WhN+zlEgfckCrIeFzixIgOKoxJtgZrFma+LPjLye6/RYlejeNegmSePueBMhOctYiRAogP3UpF6MJUiwgP1WAEdcEUmA1qBzM/pnh/P4DvTClVNsSII0ME/JUvx2G/KanqXhHSdiOPO8JMvl/oT9j86NE5acMKogBCiAkGHyPPIpfZ62j37rU+vuyhyVn3GTzHxzfENb4L81d9hIg4lovQafbr+EQ8oOgJNQYJTNoxrwt03gX0KoS351tA9AaIAprAFVW8Rj/oz5qv8EgezttuHVW6CeYxhClVaUXgkv8IiCB5IQt3kHBcfaLZ0G6T07NcgX0yEcLq/SCjjIzC+OMITJECiBjX+SptFK5yiKrp6p2unJEQzicZrOl7pcjQaYCRscHxBIgNa9BFzQiJmywsmJlMcjSexW66XrrJZzTGZIGjeuiobU6RAogiyMMfc2QIHR94xmd+qIfFFeu8C0G3x/as3asLSH63YcSIEPbCHzdb/sMxS5h42sPx+bhLbJ0UzYMapdOKilxyluFQiC+JXB0Nrg+JUDkXOO30VuNa1OWTaY+uui66lvI59+s/EogS5zQNR8QLbjptQUWittI672tran5xUvtidx7QeTSjQVSIHRZz7ANrFN/racCNVLnIrCqzxKU+QGje3+AuKvFasmy
            LogUtil.print(info.getIdemixIssuerPublicKey());
            // LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUU3TUduNTRPb3NTRUE5MTVVWVhKZEVITlFWeW9LTjFMNgpReTIzZWJ0cWZlUWZWWjNEeVdBNld5eEV5NzJ4SldPMVp6YVJraHFvbmtrSS9IQnVIamRwaGNkNXFIbGlvUEcwClZYK1JUY08zcDB1ZG9jVm1kVnBRMko1bENISm8zZVRZCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=
            LogUtil.print(info.getIdemixIssuerRevocationPublicKey());
        }

    }

    /**
     * 测试获取证书
     * Tests getting certificates
     */
    @Test
    public void testGetCertificates() throws Exception {

        // 构造证书请求
        HFCACertificateRequest certRequest = caClient.newHFCACertificateRequest();
        // 获取联盟2的Admin
        MedicalUser admin2 = sampleStore.getMember("admin2", "org2.department1");
        // 注册请求
        RegistrationRequest registerRequest = new RegistrationRequest(admin2.getName(), "org2.department1");
        // 密码
        String password = "password";
        // 设置密码
        registerRequest.setSecret(password);
        // 添加属性
        registerRequest.addAttribute(new Attribute("hf.Registrar.Roles", "client,peer,user"));

        // 注册AdminUser
        caClient.register(registerRequest, adminUser);
        // 进行Enroll
        admin2.setEnrollment(caClient.enroll(admin2.getName(), password));

        // 再次创建一个测试User
        registerRequest = new RegistrationRequest("testUser", "org2.department1");
        registerRequest.setSecret(password);
        caClient.register(registerRequest, adminUser);
        Enrollment enroll = caClient.enroll("testUser", password);

        // 获取“admin2”允许查看的所有证书，因为证书请求中未设置任何属性。这将返回2个证书，
        // 一个证书用于调用方本身“admin2”，另一个证书用于“testuser2”。只有这两个用户属于调用者“org2.department1”
        // Get all certificates that 'admin2' is allowed to see because no attributes are set
        // in the certificate request. This returns 2 certificates, one certificate for the caller
        // itself 'admin2' and the other certificate for 'testuser2'. These are the only two users
        // that fall under the caller's affiliation of 'org2.department1'.
        HFCACertificateResponse certResponse = caClient.getHFCACertificates(admin2, certRequest);
        // 证书数量为2
        assertEquals(2, certResponse.getCerts().size());
        // 证书
        assertTrue(resultContains(certResponse.getCerts(), new String[]{"admin", "testUser"}));

        // Get certificate for a specific enrollment id
        // 获取指定的EnrollmentID来获取证书cert
        // admin2是用户名
        certRequest.setEnrollmentID("admin2");
        certResponse = caClient.getHFCACertificates(adminUser, certRequest);
        assertEquals(1, certResponse.getCerts().size());
        assertTrue(resultContains(certResponse.getCerts(), new String[]{"admin"}));

        // Get certificate for a specific serial number
        // 通过指定的序列号获取证书
        certRequest = caClient.newHFCACertificateRequest();
        // 通过Enrollment获取X509证书
        X509Certificate cert = getCert(enroll.getCert().getBytes());
        // 获取证书的序列号
        String serial = cert.getSerialNumber().toString(16);
        certRequest.setSerial(serial);
        // 重新获取证书
        certResponse = caClient.getHFCACertificates(adminUser, certRequest);
        assertEquals(1, certResponse.getCerts().size());
        assertTrue(resultContains(certResponse.getCerts(), new String[]{"testUser"}));

        // Get certificate for a specific AKI(AuthorityKeyIdentifier 颁发机构密钥标识符)
        // 通过AKI获取证书
        certRequest = caClient.newHFCACertificateRequest();
        // oid = 2.5.29.35
        String oid = Extension.authorityKeyIdentifier.getId();
        byte[] extensionValue = cert.getExtensionValue(oid);
        ASN1OctetString aki0c = ASN1OctetString.getInstance(extensionValue);
        AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(aki0c.getOctets());
        String aki2 = DatatypeConverter.printHexBinary(aki.getKeyIdentifier());
        certRequest.setAki(aki2);
        certResponse = caClient.getHFCACertificates(admin2, certRequest);
        assertEquals(2, certResponse.getCerts().size());

        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");

        // Get certificates that expired before a specific date
        // In this case, using a really old date should return 0 certificates
        // 获取在某个时间之前有效的证书
        certRequest = caClient.newHFCACertificateRequest();
        certRequest.setExpiredEnd(formatter.parse("2014-30-31"));
        certResponse = caClient.getHFCACertificates(adminUser, certRequest);
        assertEquals(0, certResponse.getCerts().size());

        // Get certificates that expired before a specific date
        // In this case, using a date far into the future should return all certificates
        certRequest = caClient.newHFCACertificateRequest();
        Calendar cal = Calendar.getInstance();
        Date date = new Date();
        cal.setTime(date);
        cal.add(Calendar.YEAR, 20);
        date = cal.getTime();
        certRequest.setExpiredEnd(date);
        certResponse = caClient.getHFCACertificates(admin2, certRequest);
        assertEquals(2, certResponse.getCerts().size());
        assertTrue(resultContains(certResponse.getCerts(), new String[]{"admin2", "testUser"}));

        // Get certificates that expired after specific date
        // In this case, using a really old date should return all certificates that the caller is
        // allowed to see because they all have a future expiration date
        certRequest = caClient.newHFCACertificateRequest();
        certRequest.setExpiredStart(formatter.parse("2014-03-31"));
        certResponse = caClient.getHFCACertificates(admin2, certRequest);
        assertEquals(2, certResponse.getCerts().size());

        // Get certificates that expired after specified date
        // In this case, using a date far into the future should return zero certificates
        certRequest = caClient.newHFCACertificateRequest();
        certRequest.setExpiredStart(date);
        certResponse = caClient.getHFCACertificates(adminUser, certRequest);
        assertEquals(0, certResponse.getCerts().size());

        // 撤销testUser用户
        caClient.revoke(adminUser, "testUser", "baduser");

        // Get certificates that were revoked after specific date
        // 撤销用户之后再次测试
        certRequest = caClient.newHFCACertificateRequest();
        certRequest.setRevokedStart(formatter.parse("2014-03-31"));
        certResponse = caClient.getHFCACertificates(admin2, certRequest);
        assertEquals(1, certResponse.getCerts().size());

        certRequest = caClient.newHFCACertificateRequest();
        certRequest.setRevokedEnd(formatter.parse("2014-03-31"));
        certResponse = caClient.getHFCACertificates(admin2, certRequest);
        assertEquals(0, certResponse.getCerts().size());

        certRequest = caClient.newHFCACertificateRequest();
        certRequest.setRevoked(false);
        certResponse = caClient.getHFCACertificates(admin2, certRequest);
        assertEquals(1, certResponse.getCerts().size());
        assertTrue(resultContains(certResponse.getCerts(), new String[]{"admin2"}));
        assertFalse(resultContains(certResponse.getCerts(), new String[]{"testUser"}));

        certRequest = caClient.newHFCACertificateRequest();
        certRequest.setRevoked(true);
        certResponse = caClient.getHFCACertificates(admin2, certRequest);
        assertTrue(resultContains(certResponse.getCerts(), new String[]{"admin2", "testUser"}));
        assertEquals(2, certResponse.getCerts().size());

        certRequest = caClient.newHFCACertificateRequest();
        certRequest.setExpired(false);
        certResponse = caClient.getHFCACertificates(admin2, certRequest);
        assertEquals(2, certResponse.getCerts().size());
    }


    private boolean resultContains(Collection<HFCACredential> credentials, String[] names) {
        int numFound = 0;
        for (HFCACredential cred : credentials) {
            for (int i = 0; i < names.length; i++) {
                HFCAX509Certificate cert = (HFCAX509Certificate) cred;
                if (cert.getX509().getSubjectDN().toString().contains(names[i])) {
                    numFound++;
                    break;
                }
            }
        }
        if (numFound == names.length) {
            return true;
        }
        return false;
    }


    /**
     * 通过Enrollment获取到X509证书
     */
    private X509Certificate getCert(byte[] certBytes) throws CertificateException {
        BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(certBytes));
        CertificateFactory certFactory = CertificateFactory.getInstance("X509");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(pem);
        return certificate;
    }

    /**
     * 测试Enroll但是没有秘钥对
     */
    @Test
    public void testEnrollNoKeyPair() throws Exception {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("Failed to enroll user");

        MedicalUser user = getEnrolledUser("org1");

        EnrollmentRequest enrollmentRequest = new EnrollmentRequest(DEFAULT_PROFILE_NAME, "label 1", null);
        // 设置CSR
        enrollmentRequest.setCsr("test");
        // 会失败If certificate signing request is supplied the key pair needs to be supplied too.
        caClient.enroll(user.getName(), user.getEnrollmentSecret(), enrollmentRequest);
    }




    // Tests getting an Idemix credential(凭据) using an x509 enrollment credential
    @Test
    public void testGetIdemixCred() throws Exception {
        if (testConfig.isFabricVersionBefore("1.3")) {
            return; // needs v1.3
        }
        // 获取一个User
        MedicalUser user = getTestUser("org1");
        RegistrationRequest registrationRequest = new RegistrationRequest(user.getName(), USER1_AFFILIATION);
        String password = "password";
        registrationRequest.setSecret(password);
        user.setEnrollmentSecret(caClient.register(registrationRequest, adminUser));
        user.setEnrollment(caClient.enroll(user.getName(), user.getEnrollmentSecret()));
        // 获取Enrollment
        Enrollment enrollment = caClient.idemixEnroll(user.getEnrollment(), "idemixMsp");
        assertNotNull(enrollment);
        assertTrue(enrollment instanceof IdemixEnrollment);
    }

    // revoke2: revoke(User revoker, String revokee, String reason)
    @Test
    public void testRevoke2UnknownUser() throws Exception {

        thrown.expect(RevocationException.class);
        thrown.expectMessage("Error while revoking");

        caClient.revoke(adminUser, "unknownUser", "remove user2");
    }

    @Test
    public void testMockEnrollSuccessFalse() throws Exception {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("failed enrollment for user");

        MockHFCAClient mockClient = MockHFCAClient.createNewInstance(
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties());
        mockClient.setCryptoSuite(crypto);

        MedicalUser user = getEnrolledUser(ADMIN_ORG);

        mockClient.setHttpPostResponse("{\"success\":false}");
        mockClient.enroll(user.getName(), user.getEnrollmentSecret());
    }

    @Ignore
    @Test
    public void testMockEnrollNoCert() throws Exception {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("failed enrollment for user");

        MockHFCAClient mockClient = MockHFCAClient.createNewInstance(
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties());
        mockClient.setCryptoSuite(crypto);

        MedicalUser user = getEnrolledUser(ADMIN_ORG);

        mockClient.setHttpPostResponse("{\"success\":true}");
        mockClient.enroll(user.getName(), user.getEnrollmentSecret());
    }

    @Test
    public void testMockEnrollNoResult() throws Exception {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("response did not contain a result");

        MockHFCAClient mockClient = MockHFCAClient.createNewInstance(
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties());
        mockClient.setCryptoSuite(crypto);

        MedicalUser user = getEnrolledUser(ADMIN_ORG);

        mockClient.setHttpPostResponse("{\"success\":true}");
        mockClient.enroll(user.getName(), user.getEnrollmentSecret());
    }

    @Test
    public void testMockEnrollWithMessages() throws Exception {

        MockHFCAClient mockClient = MockHFCAClient.createNewInstance(
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties());
        mockClient.setCryptoSuite(crypto);

        MedicalUser user = getEnrolledUser(ADMIN_ORG);

        mockClient.setHttpPostResponse(
                "{\"success\":true, \"result\":{\"Cert\":\"abc\"}, \"messages\":[{\"code\":123, \"message\":\"test message\"}]}");
        mockClient.enroll(user.getName(), user.getEnrollmentSecret());
    }

    @Test
    public void testMockReenrollNoResult() throws Exception {

        thrown.expect(EnrollmentException.class);
        // thrown.expectMessage("failed");

        MockHFCAClient mockClient = MockHFCAClient.createNewInstance(
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties());
        mockClient.setCryptoSuite(crypto);

        MedicalUser user = getEnrolledUser(ADMIN_ORG);

        mockClient.setHttpPostResponse("{\"success\":true}");
        mockClient.reenroll(user);
        out("That's all folks!");
    }

    @Ignore
    @Test
    public void testMockReenrollNoCert() throws Exception {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("failed re-enrollment for user");

        MockHFCAClient mockClient = MockHFCAClient.createNewInstance(
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties());
        mockClient.setCryptoSuite(crypto);

        MedicalUser user = getEnrolledUser(ADMIN_ORG);

        mockClient.setHttpPostResponse("{\"success\":true}");
        mockClient.reenroll(user);
    }

    // ==========================================================================================
    // Helper methods
    // ==========================================================================================

    private void verifyOptions(String cert, EnrollmentRequest req) throws CertificateException {
        try {
            BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(cert.getBytes()));
            CertificateFactory certFactory = CertificateFactory.getInstance(Config.getConfig().getCertificateFormat());
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(pem);

            // check Subject Alternative Names
            Collection<List<?>> altNames = certificate.getSubjectAlternativeNames();
            if (altNames == null) {
                if (req.getHosts() != null && !req.getHosts().isEmpty()) {
                    fail("Host name is not included in certificate");
                }
                return;
            }
            ArrayList<String> subAltList = new ArrayList<>();
            for (List<?> item : altNames) {
                int type = (Integer) item.get(0);
                if (type == 2) {
                    subAltList.add((String) item.get(1));
                }
            }
            if (!subAltList.equals(req.getHosts())) {
                fail("Subject Alternative Names not matched the host names specified in enrollment request");
            }

        } catch (CertificateParsingException e) {
            fail("Cannot parse certificate. Error is: " + e.getMessage());
            throw e;
        } catch (CertificateException e) {
            fail("Cannot regenerate x509 certificate. Error is: " + e.getMessage());
            throw e;
        }
    }

    /**
     * 返回一个联盟的独一无二的用户(用于测试)
     * Returns a new (unique) user for use in a single test
     */
    private MedicalUser getTestUser(String org) {
        String userName = userNamePrefix + (++userCount);
        return sampleStore.getMember(userName, org);
    }

    /**
     * 返回一个Enroll了的用户
     * Returns an enrolled user
     * @param org 组织名称
     */
    private MedicalUser getEnrolledUser(String org) throws Exception {
        MedicalUser user = getTestUser(org);
        RegistrationRequest rr = new RegistrationRequest(user.getName(), "org1.department1");
        String password = "password";
        rr.setSecret(password);
        user.setEnrollmentSecret(caClient.register(rr, adminUser));
        if (!user.getEnrollmentSecret().equals(password)) {
            fail("Secret returned from RegistrationRequest not match : " + user.getEnrollmentSecret());
        }
        user.setEnrollment(caClient.enroll(user.getName(), user.getEnrollmentSecret()));
        return user;
    }

    /**
     * 获取一个Identity
     *
     * @param enrollmentID 登记ID
     * @param type 类型
     */
    private HFCAIdentity getIdentityReq(String enrollmentID, String type) throws InvalidArgumentException {
        // 密码
        String password = "password";
        // 创建一个身份
        HFCAIdentity identity = caClient.newHFCAIdentity(enrollmentID);
        identity.setSecret(password);
        identity.setAffiliation("org1.department1");
        // 设置最大的登记数
        identity.setMaxEnrollments(1);
        identity.setType(type);

        Collection<Attribute> attributes = new ArrayList<Attribute>();
        // 设置属性
        attributes.add(new Attribute("testattr1", "valueattr1"));
        identity.setAttributes(attributes);
        return identity;
    }

    private void sleepALittle() {
        // Seems to be an odd that calling back too quickly can once in a while generate an error on the fabric_ca
        // try {
        // Thread.sleep(5000);
        // } catch (InterruptedException e) {
        // e.printStackTrace();
        // }
    }

    static void out(String format, Object... args) {

        System.err.flush();
        System.out.flush();

        System.out.println(format(format, args));
        System.err.flush();
        System.out.flush();
    }

}
