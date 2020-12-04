package com.nano.core;

import org.apache.commons.compress.utils.IOUtils;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.hyperledger.fabric.sdk.ChaincodeID;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.TransactionRequest;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.identity.X509Enrollment;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.HFCAInfo;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.bind.DatatypeConverter;

import static com.nano.core.TestUtils.resetConfig;
import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Description:
 *
 * @version: 1.0
 * @author: nano
 * @date: 2020/11/25 18:51
 */
public class TestRegisterUser {

    private static final Logger logger = LoggerFactory.getLogger("ChannelThirdParty");

    /**
     * 测试配置
     */
    private final MedicalConfig medicalConfig = MedicalConfig.getConfig();

    /**
     * 随机数生成器
     */
    private static final Random random = new Random();


    private static final byte[] EXPECTED_EVENT_DATA = "!".getBytes(UTF_8);
    private static final String EXPECTED_EVENT_NAME = "event";
    private static final Map<String, String> TX_EXPECTED;

    /**
     * 链码相关配置
     */
//    private static final String CHAIN_CODE_FILEPATH = "sdkintegration/gocc/sample1";
//    private static final String CHAIN_CODE_NAME = "example_cc_go";
//    private static final String CHAIN_CODE_PATH = "github.com/example_cc";
//    private static final String CHAIN_CODE_VERSION = "1";
//    private static final Type CHAIN_CODE_LANG = Type.GO_LANG;


    /**
     * 链码相关配置
     */
    private static final String CHAIN_CODE_FILEPATH = "sdkintegration/gocc/thirdparty";
    private static final String CHAIN_CODE_NAME = "datause_cc_go";
    private static final String CHAIN_CODE_PATH = "github.com/example_cc";
    private static final String CHAIN_CODE_VERSION = "1";
    private static final TransactionRequest.Type CHAIN_CODE_LANG = TransactionRequest.Type.GO_LANG;


    // 静态初始化
    static {
        TX_EXPECTED = new HashMap<>();
        TX_EXPECTED.put("readset1", "Missing readset for channel bar block 1");
        TX_EXPECTED.put("writeset1", "Missing writeset for channel bar block 1");
    }

    /***
     * 配置帮助器
     */
    private final MedicalConfigHelper configHelper = new MedicalConfigHelper();

    /**
     * 测试的TransactionId
     */
    private String testTxId = null;

    /**
     * 文件本地键值对存储
     */
    private LocalStore localStore = null;

    /**
     * 测试组织集合
     */
    private Set<Organization> organizationSet;

    /**
     * 测试用户
     */
    static String normalUser1 = "user" + System.currentTimeMillis();

    /**
     * Fabric代理对象
     */
    public HFClient fabricClientThirdParty;

    /**
     * Foo通道对象
     */
    public Channel channelThirdParty;

    /**
     * 链码ID对象
     */
    public ChaincodeID chaincodeId;


    /**
     * 链码ID对象(DataUse链码)
     */
    public ChaincodeID chaincodeIdDataUse;


    /**
     * 客户端TLS属性
     */
    Map<String, Properties> clientTLSProperties = new HashMap<>();


    /**
     * 两个组织
     */
    private Organization organizationPatient;
    private Organization organizationThirdParty;


    // 链码事件列表
    // Test list to capture chaincode events.
    List<MedicalChannelThirdParty.ChaincodeEventCapture> chaincodeEventList = new LinkedList<>();

    /**
     * 链码事件监听器处理器
     */
    String chaincodeEventListenerHandler;

    /**
     * 是否已经初始化
     */
    private boolean isInit = false;


    // run End2EndIT.java test and copy from first peer ProposalResponse (fabric at commit level 230f3cc)
    // 明文HEX
    public static final String PLAIN_TEXT_HEX = "0A205E87B04D3B137E4F2BD2B7E435C96D86E62F3DA5147863A2051F39803AB519BD12E60F0AE30F02046C636363010D6578616D706C655F63632E676F00010D6578616D706C655F63632E676F009D0F0A0D6578616D706C655F63632E676F1201301A880F0A2B0801120F120D6578616D706C655F63632E676F1A160A04696E69740A01610A033130300A01620A03323030120708B2B4FFAF9D2B1ACF0E1F8B08000000000000FFED586D73DA4610CE57F42BB69A26869420C0A49E71EB0F603B2D93165C709A64624FE610075C2D24727702D34EFE7B77EF2410183B4E4CD2990E3B9380B8BBBD67DF9E5DF924F2AFB81C88803FFA6A52AE94CB3FD66A50B6B2FE59AE1E54A0B25FAE552BFBD5F2F30328572ACF0F6A8FA0FCF5202D25569AC947E507DFB56EDC16A07D0B79D169FF0EA3F984CB80F7875C7A03D693C27FE6FB3C9C3A8072DC3E7B0B25F8FE97F659FDFC574F49DFEBC522E83FF3474C847ED4E79ED9F7BADD7979D2ECA41BCD6F9D572D18462042747210C0DA3980274F603C5DA8EE89705DF5CA1ABF66E349C0DFFB7E6918FDD78EFB9FC8B7F0E9DDF55FA9D69E574DFD570EF66BCF0FF6B1FEABD5DAC1AEFEBF85784F9DE36832976238D2D06CFC0EC7919C94A05AAEFC08752CD90E2D28E870C5E594F74B8EF39B406A50BC0F71D8E712F488437DC27CFC48568AF027974A4421544B65C8D3063759720B3F39F32886319B4318698815470542013520E0D73E9F68640BF0234C4AC1429FC34CE891B924515172DE260AA29E46960086BB27F834C8EE02A61D27978391D69343CF9BCD66256640962239F402BB4979BF358F4F5BDDD36708D4715E8501570A24FF100B89F6F5E6C02608C3673D0417B0194412D850725CD3446A3093428B705804150DF48C49EEF485D252F462BDE29F14141A9ADD801E6221B8F52E34BB2E34EADD66B7E8BC6E9EFFDA7E750EAFEB9D4EBD75DE3CED42BB8324DC3A699E37DB2D7C7A01F5D65B78D96C9D1481A377F0127E3D91841D010AF21C05AACBF9CAE583C8825113EE8B81F0D1A27018B32147869E7219A221806D602C14C54E21B4BE1388B1D04C9BE71BE6949CA79EE3A057AF48C91863E1380E5E1F490D7927E7722923A95CFC36186BFA40CBFD289CBA18197788C0E35E0903EDDDEC3E9E1F49EE2DFB8B1A89B1EB141CC7F3A04B06F2E3458348080C94F91D960BE679CC438BDFD178CB8DC38828F635FCE37C749C411CFA98ADF0746D53019AA1D079A5E31E1090D262A58B3F35438DE313F3715BFEDD656FAE31FD8DE105D49A7B5F0426870A0E8F80CE977EE1FA055E4380EA61FF8C4936E6785EE50B4E6ECA24D48BD02050140B1434F734D498635C25EB5316E016FC1FD34FD37A5D29AE6114057D3C93ECC2FB2D0674B41840C0C33CA128C0774750235839C9752C43084590A055A5169FE5DD26DA2525479784F1B887E1C6AAC2A331B95195E0F41A7387321E6A2E2246A7E51002B947B040FC6DF36D11362757872363FFBBF2253E18EC848D9C6132A154D79130D8DE552E0B062CAD234C447627D02512F403C7CC01D41EDB24675997589CB9468AA48A481A7722D9FFBA48B0164A6718603DC8BBE412C4F0B89FC494BE5E846E3113E782F5F16B641AEB5E6C57F42D320FB66A9C5C6A0BA6D859ACBBB4258FB96413329FDAD8D411CB93EA42E13E26DA006F52DDD8ACBAF199AAB33FE27F7717E11F3197F32FABC25B63F72ABC0AA359082A9E106B2125FB38A662A03E1AAA39972C54CC542BD2DB15573061732A052A8B374888023BE3404663A853401A7752C834BAE25F067F9030C667708909417A8EE2E00A03C0BD973B1607136F9860AD10C9CF50DD0E8F308D5A99D250CDDC9350061C21EE3E0FD02A8B1B4372621EA9390127669C5BFF53204C612C31E9923D6A7C6E5DB7F9860F94588B0BE849AC5C7043EF87452666D4AE6B1D634FFD22D474F086F24F458C250982038E7F65986120247A35F57911C638E7428FE3CCC129187BD6397B45D833E6E017E4AB3DBA7CCFE6FFEDB9BC4078572627C9FAEED276B38D898D9E4961A1676C866EB30FBE318B0B59AB6843D3DFAE61169765358882209AD909B30A21D6AD99B6A06231A595B0E89E95CBD506663C87E59FE907269FB21D818C6D9FB40F717EA6176F8ED07DD336466C8AEEA6E338DE1B3A37654E4BE959F22EC54AD92699219CA4B37C56837CC170B63713F310211BB8EEA264165751D17CB2D5DADAA117874184E368A2C626C3FBF5666ED327BFB8A140ADB4F109D31ADB33ADB105D31A779AD658310D237E86B517499B08FC9AFBB1997C736FB636EC601BC3410F2DCED4111B23606418BE24F5D551281326C4603E9EC11B6B1CFE603E7EA01FB6331AF51851E0FF613EF2BCF50929DD976827877527198F1DA5FE2277AD3AABB098B16E6F48B619DDCEFC998EFA50EE5FA7D9CA7668B6B224CFC3257B3ACB266CD2E28ACF978C69B306DFE6B3C99212031E7A18E7599765B961E3DC8BF8CC806BB8D864B0E4F44A4FD141B308A7E9D3C6F0CC2BD6EDB1FA70AF79F91EA14A3A6EDA8E6FF4E2BB9AE796A6446A91E91F782638E222EBA06BEDE0B6A159DEA73F7E598FFB0BAFEE7035A1FDEE3F17EE295973E11E5E6C6A05E615D0456AABE33FF7C2FDE8DEEE8B54F17244DDD8196FBFBF853B2C133FE0DA75F52DF4BBD19E5157BC70EBE69EC5C28D46BBBC37CBE836BF497D142A7EF858193ACF2048306622937D29A4BF2FE50D75A4F1A2ACC660499D0FD194F502D818BF2C1EE33B8A94343966CF2F4BEB101E2BD738CB38E7A3F35FFFA576273BD9C94E76B2939DEC64273BD9C94E1E26FF02F35EC2D1002800000D6578616D706C655F63632E676F000201610003313030016200033230300A0744454641554C54129A072D2D2D2D2D424547494E202D2D2D2D2D0A4D4949436A444343416A4B6741774942416749554245567773537830546D7164627A4E776C654E42427A6F4954307777436759494B6F5A497A6A3045417749770A667A454C4D416B474131554542684D4356564D78457A415242674E5642416754436B4E6862476C6D62334A7561574578466A415542674E564241635444564E680A62694247636D467559326C7A59323878487A416442674E5642416F54466B6C7564475679626D5630494664705A47646C64484D7349456C75597934784444414B0A42674E564241735441316458567A45554D4249474131554541784D4C5A586868625842735A53356A623230774868634E4D5459784D5445784D5463774E7A41770A5768634E4D5463784D5445784D5463774E7A4177576A426A4D517377435159445651514745774A56557A45584D4255474131554543424D4F546D3979644767670A5132467962327870626D45784544414F42674E564241635442314A68624756705A326778477A415A42674E5642416F54456B6835634756796247566B5A3256790A49455A68596E4A70597A454D4D416F474131554543784D44513039514D466B77457759484B6F5A497A6A3043415159494B6F5A497A6A304441516344516741450A4842754B73414F34336873344A4770466669474D6B422F7873494C54734F766D4E32576D77707350485A4E4C36773848576533784350517464472F584A4A765A0A2B433735364B457355424D337977355054666B7538714F42707A43427044414F42674E56485138424166384542414D4342614177485159445652306C424259770A464159494B7759424251554841774547434373474151554642774D434D41774741315564457745422F7751434D414177485159445652304F42425945464F46430A6463555A346573336C746943674156446F794C66567050494D42384741315564497751594D4261414642646E516A32716E6F492F784D55646E3176446D6447310A6E4567514D43554741315564455151654D427943436D31356147397A6443356A62323243446E6433647935746557687663335175593239744D416F47434371470A534D343942414D43413067414D4555434944663948626C34786E337A3445774E4B6D696C4D396C58324671346A5770416152564239374F6D56456579416945410A32356144505148474771324176684B54307776743038635831475447434962666D754C704D774B516A33383D0A2D2D2D2D2D454E44202D2D2D2D2D0A";
    // 签名HEX
    public static final String SIGNATURE_HEX = "3045022100BAA3D3DBED52CD5FF2169FE0699E5739983D89A495EE4E5661B0C6ED6AF7914F022009E6D11458E37F44D137BA0F840DC9D7303E569AC9B8F4A2367213F4121C510D";
    // 证书文件HEX
    public static final String PEM_CERT_HEX = "2D2D2D2D2D424547494E2043455254494649434154452D2D2D2D2D0A4D4949434E6A43434164796741774942416749515251692F672B4D79355468732F677536725A494B5844414B42676771686B6A4F50515144416A43426754454C0A4D416B474131554542684D4356564D78457A415242674E5642416754436B4E6862476C6D62334A7561574578466A415542674E564241635444564E68626942470A636D467559326C7A593238784754415842674E5642416F54454739795A7A45755A586868625842735A53356A623230784444414B42674E564241735441304E500A554445634D426F474131554541784D545932457562334A6E4D53356C654746746347786C4C6D4E7662544165467730784E7A45784D5449784D7A51784D5446610A467730794E7A45784D5441784D7A51784D5446614D476B78437A414A42674E5642415954416C56544D524D77455159445651514945777044595778705A6D39790A626D6C684D52597746415944565151484577315459573467526E4A68626D4E7063324E764D517777436759445651514C45774E4454314178487A416442674E560A42414D4D466C567A5A584978514739795A7A45755A586868625842735A53356A623230775754415442676371686B6A4F5051494242676771686B6A4F50514D420A42774E43414152776B7773647A664945753549554F6D6C5A6A4259644755724B566D5841713857757174676E76306375684A4C666F73697277664E38307745740A6B395A637856706C5657703732484A736E5A6A73386C75412B3232756F303077537A414F42674E56485138424166384542414D434234417744415944565230540A4151482F424149774144417242674E5648534D454A4441696743434B6335456947633851566C534665627035594753627372746C7A78486A2F507374626765690A79774F554B7A414B42676771686B6A4F5051514441674E49414442464169454176437773694B374465724A5333647A375A35562B5248644A624D654C625961660A32396234643871467A736F4349483338637A394C7A306B783856615974347453784A4B3550526F695850696A37466C6E794F6248615246330A2D2D2D2D2D454E442043455254494649434154452D2D2D2D2D";
    // 不合法的PEM证书
    public static final String INVALID_PEM_CERT = "2D2D224547494E202D2D2D2D2D0A4D4949436A444343416A4B6741774942416749554245567773537830546D7164627A4E776C654E42427A6F4954307777436759494B6F5A497A6A3045417749770A667A454C4D416B474131554542684D4356564D78457A415242674E5642416754436B4E6862476C6D62334A7561574578466A415542674E564241635444564E680A62694247636D467559326C7A59323878487A416442674E5642416F54466B6C7564475679626D5630494664705A47646C64484D7349456C75597934784444414B0A42674E564241735441316458567A45554D4249474131554541784D4C5A586868625842735A53356A623230774868634E4D5459784D5445784D5463774E7A41770A5768634E4D5463784D5445784D5463774E7A4177576A426A4D517377435159445651514745774A56557A45584D4255474131554543424D4F546D3979644767670A5132467962327870626D45784544414F42674E564241635442314A68624756705A326778477A415A42674E5642416F54456B6835634756796247566B5A3256790A49455A68596E4A70597A454D4D416F474131554543784D44513039514D466B77457759484B6F5A497A6A3043415159494B6F5A497A6A304441516344516741450A4842754B73414F34336873344A4770466669474D6B422F7873494C54734F766D4E32576D77707350485A4E4C36773848576533784350517464472F584A4A765A0A2B433735364B457355424D337977355054666B7538714F42707A43427044414F42674E56485138424166384542414D4342614177485159445652306C424259770A464159494B7759424251554841774547434373474151554642774D434D41774741315564457745422F7751434D414177485159445652304F42425945464F46430A6463555A346573336C746943674156446F794C66567050494D42384741315564497751594D4261414642646E516A32716E6F492F784D55646E3176446D6447310A6E4567514D43554741315564455151654D427943436D31356147397A6443356A62323243446E6433647935746557687663335175593239744D416F47434371470A534D343942414D43413067414D4555434944663948626C34786E337A3445774E4B6D696C4D396C58324671346A5770416152564239374F6D56456579416945410A32356144505148474771324176684B54307776743038635831475447434962666D754C704D774B516A33383D0A2D2D2D2D2D454E44202D2D2D2D2D0A";
    // 签名算法
    private static final String SIGNING_ALGORITHM = "SHA256withECDSA";

    // File create_key_cert_for_testing.md has info on the other keys and certificates used in this test suite
    private static byte[] plainText, signature, pemCert, invalidPemCert;

    /**
     * 秘钥工厂
     */
    private static KeyFactory keyFactory;

    /**
     * 证书工厂
     */
    private static CertificateFactory certificateFactory;

    /**
     * 密码原语
     */
    public static CryptoPrimitives cryptoPrimitives;

    /**
     * 证书
     */
    private static Certificate testCACert;

    /**
     * 配置类
     */
    private static Config config;


    public static void main(String[] args) {
        TestRegisterUser testRegisterUser = new TestRegisterUser();

        try {
            // 实例化配置类
            config = Config.getConfig();
            // 获取明文(明文与明文16进制互相转换)
            plainText = DatatypeConverter.parseHexBinary(PLAIN_TEXT_HEX);
            // 获取签名
            signature = DatatypeConverter.parseHexBinary(SIGNATURE_HEX);


            // 获取合法证书
            pemCert = DatatypeConverter.parseHexBinary(PEM_CERT_HEX);
            // 不合法证书:证书格式有问题
            invalidPemCert = DatatypeConverter.parseHexBinary(INVALID_PEM_CERT);
            // 生成秘钥工厂:采用ECC算法
            keyFactory = KeyFactory.getInstance("EC");
            // 证书工厂: 设置证书类型为X.509
            certificateFactory = CertificateFactory.getInstance("X.509");
            // 初始化
            cryptoPrimitives = new CryptoPrimitives();
            cryptoPrimitives.init();
            //System.out.println("明文:" + new String(plainText));

            // 这里读取的路径时resource下面的路径
            BufferedInputStream inputStream = new BufferedInputStream(testRegisterUser.getClass().getResourceAsStream("D:\\code\\12_Paper\\MedicalLedger\\src\\main\\resources\\ca.crt"));
            testCACert = certificateFactory.generateCertificate(inputStream);
            inputStream.close();
            cryptoPrimitives.addCACertificateToTrustStore(new File("D:\\code\\12_Paper\\MedicalLedger\\src\\main\\resources\\ca.crt"), "ca");
//        cryptoPrimitives.addCACertificateToTrustStore(testCACert, "ca");

            inputStream = new BufferedInputStream(testRegisterUser.getClass().getResourceAsStream("/keypair-signed.crt"));
            Certificate cert = certificateFactory.generateCertificate(inputStream);
            inputStream.close();

            PEMParser pemParser = new PEMParser(new FileReader(testRegisterUser.getClass().getResource("/keypair-signed.key").getFile()));
            // 密钥对
            PEMKeyPair bcKeyPair = (PEMKeyPair) pemParser.readObject();
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bcKeyPair.getPrivateKeyInfo().getEncoded());
            // 生成私钥
            PrivateKey key = keyFactory.generatePrivate(keySpec);
            // 生成证书
            Certificate[] certificates = new Certificate[]{cert, testCACert};

            // 将给定的密钥分配给给定的别名，并使用给定的密码保护它
            // alias: 别名
            // key: 秘钥
            // password: 密码
            // certificate chain: 证书链
            cryptoPrimitives.getTrustStore().setKeyEntry("key", key, "123456".toCharArray(), certificates);
            pemParser.close();


        } catch (Exception e) {
            e.printStackTrace();
        }


        testRegisterUser.init();
    }


    /**
     * 初始化方法
     */
    public void init() {
        try {
            logger.info("开始初始化配置.");
            // 初始化配置
            initConfig();
            logger.info("完成初始化配置.");
            // 持久化不是SDK的一部分,生产环境别用SampleFile这个类,需要自己做实现!!!!!!
            // 每次都删除掉之前的存储文件
            File localStoreFilePath = new File(MedicalConfig.FIXTURES_PATH + "/HFCSampletest.properties");
            if (localStoreFilePath.exists()) {
                localStoreFilePath.delete();
            }
            localStore = new LocalStore(localStoreFilePath);
            // This enrolls users with fabric ca and setups sample store to get users later.
            // enrollAndRegisterUsers(sampleStore);
            // 分别为两个组织注册用户信息(AdminUser, NormalUser, AdminPeer)
            registerAndEnrollForOrg(localStore, organizationPatient);
            //registerAndEnrollForOrg(localStore, organizationThirdParty);


            registerUser(organizationPatient);
            logger.info("Finished all the steps.");


        } catch (Exception e) {
            e.printStackTrace();
            fail("Test failed with error : " + e.getMessage());
        }
    }

    HFCAClient caClient;

    /**
     * 进行用户注册
     */
    public void registerUser(Organization organization) {

        // 获取CA代理
        caClient = organization.getCAClient();
        try {
            // 获取组织名称
            final String orgName = organization.getName();
            // 获取组织MSPID
            final String mspId = organization.getMSPID();

            // 设置加密套件
            caClient.setCryptoSuite(cryptoPrimitives);
            // 判断是否开启了TLS(默认为false)
            if (true) {
                final EnrollmentRequest enrollmentRequestTls = new EnrollmentRequest();
                // 添加Host
                enrollmentRequestTls.addHost("localhost");
                enrollmentRequestTls.setProfile("tls");

                // 通过CA获取Enrollment(使用Admin的账号和密码)
                final Enrollment enroll = caClient.enroll("admin", "adminpw", enrollmentRequestTls);
                // 获取TLS证书的Pem
                final String tlsCertPem = enroll.getCert();
                // 获取TLS秘钥的Pem
                final String tlsKeyPem = MedicalUtil.getPemStringFromPrivateKey(enroll.getKey());
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

            /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // 在这里生成多个结点的Admin用户
            /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

            // 获取这个组织的Admin用户
            MedicalUser adminXinQiao = new MedicalUser("adminXinQiao", orgName, localStore, caClient.getCryptoSuite());
            logger.info("Admin用户信息: " + adminXinQiao.toString());
            // Preregistered admin only needs to be enrolled with Fabric caClient.
            // 如果Admin没有登记就进行登记
            if (!adminXinQiao.isEnrolled()) {
                logger.info("登记AdminUser");
                // Admin登记(使用CA启动时的用户名与密码)
                Enrollment enrollment = caClient.enroll("admin", "adminpw");
                logger.info("AdminUser的私钥:" + enrollment.getKey().toString());
                adminXinQiao.setEnrollment(enrollment);
                // 设置MSPID
                // Org1MSP Org2MSP
                adminXinQiao.setMspId(mspId);
            }

            // 获取这个组织的Admin用户
            MedicalUser adminKunYi = new MedicalUser("adminKunYi", orgName, localStore, caClient.getCryptoSuite());
            logger.info("Admin用户信息: " + adminKunYi.toString());
            // Preregistered admin only needs to be enrolled with Fabric caClient.
            // 如果Admin没有登记就进行登记
            if (!adminKunYi.isEnrolled()) {
                logger.info("登记AdminUser");
                // Admin登记(使用CA启动时的用户名与密码)
                Enrollment enrollment = caClient.enroll("admin", "adminpw");
                logger.info("AdminUser的私钥:" + enrollment.getKey().toString());
                adminKunYi.setEnrollment(enrollment);
                // 设置MSPID
                // Org1MSP Org2MSP
                adminKunYi.setMspId(mspId);
            }

            // 生成一个User
            MedicalUser user = new MedicalUser("user1" + System.currentTimeMillis(), orgName, localStore, caClient.getCryptoSuite());
            // 对普通User用户进行登记与注册
            if (!user.isRegistered()) {
                logger.info("注册普通User");
                // 设置用户的名称及其所属组织属性
                RegistrationRequest registerRequest = new RegistrationRequest(user.getName());
                // 这里可以设置用户的密码!!!!!
                registerRequest.setSecret("password");
                // 利用组织的Admin用户进行注册并获取登记密码
                String secret = caClient.register(registerRequest, adminXinQiao);
                user.setEnrollmentSecret(secret);
            }
            // 用户登记
            if (!user.isEnrolled()) {
                logger.info("登记普通User");

                // 生成秘钥对
                KeyPair pair = cryptoPrimitives.keyGen();

                // 获取公钥私钥
                PublicKey publicKey = pair.getPublic();
                PrivateKey privateKey = pair.getPrivate();

                logger.info("自己生产的公钥:" + publicKey.toString());
                logger.info("自己生产的私钥:" + privateKey.toString());

                String signature = CipherUtil.sign("1234545".getBytes(UTF_8), privateKey);
                boolean verified = CipherUtil.verifySignature("1234545".getBytes(UTF_8), publicKey, signature);
                System.out.println("自定义方法验证:" + verified);

                EnrollmentRequest enrollmentRequest = new EnrollmentRequest();
                // 设置密钥对
                enrollmentRequest.setKeyPair(pair);

                Enrollment enrollment = caClient.enroll(user.getName(), user.getEnrollmentSecret(), enrollmentRequest);
                user.setEnrollment(enrollment);
                // Org1MSP Org2MSP
                user.setMspId(mspId);
            }


            Enrollment enrollment = user.enrollment;
            PrivateKey privateKey = enrollment.getKey();
            String signature22 = CipherUtil.sign("1234545".getBytes(UTF_8), privateKey);

            logger.info("返回的私钥:" + privateKey);
            logger.info("Private Key:" + privateKey.toString());
            logger.info("Private Key:" + privateKey.getFormat());
            String cert = enrollment.getCert();
            logger.info("Cert:" + cert);
            // -----BEGIN CERTIFICATE-----
            //MIICZzCCAg6gAwIBAgIUR8egdisOo7qHrlYkh7+jY14x2BowCgYIKoZIzj0EAwIw
            //fzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
            //biBGcmFuY2lzY28xHzAdBgNVBAoTFm9yZ3BhdGllbnQubWVkaWNhbC5jb20xIjAg
            //BgNVBAMTGWNhLm9yZ3BhdGllbnQubWVkaWNhbC5jb20wHhcNMjAxMTI1MTEwMDAw
            //WhcNMjExMTI1MTEwNTAwWjAgMQ8wDQYDVQQLEwZjbGllbnQxDTALBgNVBAMTBHVz
            //ZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ2MNxm/i9G728NMajWu0XwzUas
            //pTLD5MLdxDT/TvhrwFAM9oHz8NJefKk1+CtPg5+yFSlUST72LvBk2O8t5xB8o4HG
            //MIHDMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQqBAhA
            //yz5FzZg30BNKuRBiL28uVjArBgNVHSMEJDAigCCvpsLO0MqJjYKGE5KFqWd8DRiK
            //8jzc4JkppLByo7Jx0DBXBggqAwQFBgcIAQRLeyJhdHRycyI6eyJoZi5BZmZpbGlh
            //dGlvbiI6IiIsImhmLkVucm9sbG1lbnRJRCI6InVzZXIiLCJoZi5UeXBlIjoiY2xp
            //ZW50In19MAoGCCqGSM49BAMCA0cAMEQCICLGKiEsH1Vns+FMSEZP35jI/kQqkhsb
            //83JzeM6vsVOdAiAqRYbKtP85rNHnde9HFmEHaFe789C2hzXDpeMOuj3BQQ==
            //-----END CERTIFICATE-----

            // 通过证书来获取输入流
            BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(cert.getBytes()));
            CertificateFactory certFactory = CertificateFactory.getInstance(org.hyperledger.fabric_ca.sdk.helper.Config.getConfig().getCertificateFormat());
            // 通过证书流产生证书,由此可以得到私钥公钥等文件
            X509Certificate x509Certificate = (X509Certificate) certFactory.generateCertificate(pem);

            logger.info("certDec:" + getStringCert(cert));

            logger.info("HexCert:" + stringToHexString(cert));

            // 证书存入本地crt文件
            string2File(cert, "G:\\" + user.getName() + ".crt");

            System.out.println(x509Certificate.toString());
            System.out.println("----");
            // 从证书获取签名
            // 0E! �,,���z�R���g�~DwIlǋm�����wʅ�� }�s?K�I1�V���RĒ�="\���Yg���iw
            System.out.println(new String(x509Certificate.getSignature()));
            System.out.println("----");
            // 从证书获取公钥
            //  Sun EC public key, 256 bits
            //  public x coord: 50918842282585106460755471350696073546812271424132902375661705355892818914948
            //  public y coord: 66432806281588174649157141113246971496950139544830570332248457713006719757742
            //  parameters: secp256r1 [NIST P-256, X9.62 prime256v1] (1.2.840.10045.3.1.7)
            PublicKey publicKey = x509Certificate.getPublicKey();

            boolean verified = CipherUtil.verifySignature("1234545".getBytes(UTF_8), publicKey, signature22);
            System.out.println("自定义方法验证2:" + verified);

            logger.info("返回的公钥:" + publicKey.toString());
            System.out.println(publicKey.toString());
            System.out.println("----");
            // EC
            System.out.println(publicKey.getAlgorithm());
            System.out.println("----");


            byte[] plainText1 = "123456".getBytes(UTF_8);
            logger.info("进行签名");
            byte[] sign = caClient.getCryptoSuite().sign(privateKey, plainText1);

            BufferedInputStream inputStream = new BufferedInputStream(
                    new FileInputStream("G:\\" + user.getName() + ".crt"));

            cryptoPrimitives.addCACertificateToTrustStore(new File("G:\\" + user.getName() + ".crt"), user.getName());

            // 获取证书
            byte[] certificate1 = IOUtils.toByteArray(inputStream);
            inputStream.close();

            System.out.println("验证:::" + cryptoPrimitives.verify(certificate1, SIGNING_ALGORITHM, sign, plainText1));

            //caClient.getCryptoSuite().verify();

            System.out.println(sign.length);
            System.out.println(new String(sign));


            x509Certificate.getSignature();

            cryptoPrimitives.getTrustStore().setKeyEntry("Jakc", privateKey, "12331".toCharArray(), new X509Certificate[]{x509Certificate});

            Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(cert.getBytes(UTF_8)));

            String plainText = "123456";

            byte[] signature = caClient.getCryptoSuite().sign(privateKey, plainText.getBytes());


            //caClient.getCryptoSuite().getTrustStore().setKeyEntry("Jack", privateKey, "123456".toCharArray(), new X509Certificate[]{x509Certificate});

            boolean isValid = caClient.getCryptoSuite().verify(x509Certificate.getEncoded(), "SHA256withECDSA", signature, plainText.getBytes(UTF_8));

            logger.info("验证签名:" + isValid);

            String data = "123456";

            EccHelper eccHelper = new EccHelper(publicKey.getEncoded(), privateKey.getEncoded());

            System.out.println("完成构建ECCHelper.");
            //byte[] engypt = CipherUtil.encryptByPrivateKey(data.getBytes(), privateKey);


            byte[] sig = eccHelper.sign(data.getBytes());

            System.out.println(eccHelper.verifySignature(sig, data.getBytes()));

            byte[] secret = EccHelper.encrypt(data.getBytes(), publicKey.getEncoded());
            System.out.println("密文:" + new String(secret));
            byte[] plain = EccHelper.decrypt(secret, privateKey.getEncoded());
            System.out.println("明文:" + new String(plain));


            //byte[] res = CipherUtil.decrypt(engypt, privateKey);

            //System.out.println("采用公钥加密私钥解密:" + new String(res));


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
            organization.setAdminUser(adminXinQiao);
            logger.info("完成组织用户加载.");
        } catch (Exception e) {
            e.printStackTrace();
        }


    }


    private Enrollment loadFromPemFile(String keyFile, String certFile) throws Exception {
        byte[] keyPem = Files.readAllBytes(Paths.get(keyFile));     //载入私钥PEM文本
        byte[] certPem = Files.readAllBytes(Paths.get(certFile));   //载入证书PEM文本
        CryptoPrimitives suite = new CryptoPrimitives();            //载入密码学套件
        PrivateKey privateKey = suite.bytesToPrivateKey(keyPem);    //将PEM文本转换为私钥对象
        return new X509Enrollment(privateKey, new String(certPem));  //创建并返回X509Enrollment对象
    }


    /**
     * 获取String形式的证书
     */
    private static String getStringCert(String pemFormat) {
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
     * 解析Pattern
     */
    private static final Pattern compile = Pattern.compile("^-----BEGIN CERTIFICATE-----$"
                    + "(.*?)" + "\n-----END CERTIFICATE-----\n",
            Pattern.DOTALL | Pattern.MULTILINE);


    public static File string2File(String res, String filePath) {
        boolean flag = true;
        BufferedReader bufferedReader = null;
        BufferedWriter bufferedWriter = null;
        try {
            File distFile = new File(filePath);
            if (!distFile.getParentFile().exists()) distFile.getParentFile().mkdirs();
            bufferedReader = new BufferedReader(new StringReader(res));
            bufferedWriter = new BufferedWriter(new FileWriter(distFile));
            char buf[] = new char[1024];         //字符缓冲区
            int len;
            while ((len = bufferedReader.read(buf)) != -1) {
                bufferedWriter.write(buf, 0, len);
            }
            bufferedWriter.flush();
            bufferedReader.close();
            bufferedWriter.close();
            return distFile;
        } catch (IOException e) {
            e.printStackTrace();
            flag = false;
        } finally {
            if (bufferedReader != null) {
                try {
                    bufferedReader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }

    public static String stringToHexString(String s) {
        String str = "";
        for (int i = 0; i < s.length(); i++) {
            int ch = s.charAt(i);
            String s4 = Integer.toHexString(ch);
            str = str + s4;
        }
        return str;
    }

    /**
     * 测试之前执行的默认配置
     */
    public void initConfig() {
        try {
            CryptoPrimitives cryptoPrimitives = new CryptoPrimitives();
            cryptoPrimitives.init();

            resetConfig();
            configHelper.customizeConfig();
            // 获取组织的Set
            organizationSet = medicalConfig.getOrganizationSet();
            logger.info("当前组织数: " + organizationSet.size());
            // 将组织对象映射到本类中
            organizationPatient = medicalConfig.getOrganizationMap().get("peerOrgPatient");
            organizationThirdParty = medicalConfig.getOrganizationMap().get("peerOrgThirdParty");
            String caNamePatient = organizationPatient.getCAName();
            logger.info("组织PatientCA名称: " + caNamePatient);
            // 构造组织1的CA代理对象
            HFCAClient caClientPatient = HFCAClient.createNewInstance(
                    // CA名称
                    caNamePatient,
                    // CA地址
                    organizationPatient.getCALocation(),
                    // CA属性
                    organizationPatient.getCAProperties());

            // 设置Primitive
            caClientPatient.setCryptoSuite(cryptoPrimitives);


            organizationPatient.setCAClient(caClientPatient);

            // 构造组织ThirdParty的CA代理对象
            String caNameThirdParty = organizationThirdParty.getCAName();
            HFCAClient caClientThirdParty = HFCAClient.createNewInstance(
                    // CA名称
                    caNameThirdParty,
                    // CA地址
                    organizationThirdParty.getCALocation(),
                    // CA属性
                    organizationThirdParty.getCAProperties());
            caClientThirdParty.setCryptoSuite(cryptoPrimitives);
            organizationThirdParty.setCAClient(caClientThirdParty);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 组织1的注册与登记
     *
     * @param localStore 持久化文件
     */
    private void registerAndEnrollForOrg(LocalStore localStore, Organization organization) {
        logger.info("开始为组织" + organization.name + "注册登记用户.");
        try {
            // 获取CA代理
            HFCAClient caClient = organization.getCAClient();
            // 获取组织名称
            final String orgName = organization.getName();
            // 获取组织MSPID
            final String mspId = organization.getMSPID();

            // "ca0.example.com"
            logger.info("CA代理的名称:" + caClient.info().getCAName());

            // 设置加密套件
            caClient.setCryptoSuite(cryptoPrimitives);
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
                final String tlsKeyPem = MedicalUtil.getPemStringFromPrivateKey(enroll.getKey());
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
            // 获取CA信息来判断是否连接成功
            HFCAInfo info = caClient.info();
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
                admin.setMspId(mspId);
            }

            // 创建一个新的普通用户
            MedicalUser user = localStore.getUser(normalUser1, organization.getName());
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
                user.setMspId(mspId);
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

}
