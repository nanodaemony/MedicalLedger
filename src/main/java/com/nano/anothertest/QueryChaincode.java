package com.nano.anothertest;
import org.apache.commons.compress.utils.IOUtils;
import org.bouncycastle.openssl.PEMWriter;
import org.hyperledger.fabric.sdk.ChaincodeID;
import org.hyperledger.fabric.sdk.ChaincodeResponse;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.EventHub;
import org.hyperledger.fabric.sdk.Orderer;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.ProposalResponse;
import org.hyperledger.fabric.sdk.TransactionProposalRequest;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.nio.charset.StandardCharsets.UTF_8;
/**
 * Description:
 *
 * @version: 1.0
 * @author: nano
 * @date: 2020/11/20 17:00
 */
public class QueryChaincode {


    private static final byte[] EXPECTED_EVENT_DATA = "!".getBytes(UTF_8);
    private static final String EXPECTED_EVENT_NAME = "event";


    static String getPEMStringFromPrivateKey(PrivateKey privateKey) throws IOException {
        StringWriter pemStrWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(pemStrWriter);

        pemWriter.writeObject(privateKey);

        pemWriter.close();

        return pemStrWriter.toString();
    }


    public static HFCAClient enableTLS(HFCAClient hfcaclient , String uesrName , String userpasswd , String orgName , String caHsotIp) {
        final EnrollmentRequest enrollmentRequestTLS  = new EnrollmentRequest();
        enrollmentRequestTLS.addHost(caHsotIp);
        enrollmentRequestTLS.setProfile("tls");
        try {
            final Enrollment enroll =hfcaclient.enroll(uesrName, userpasswd,enrollmentRequestTLS);
            final String tlsCertPEM = enroll.getCert();
            final String tlsKeyPEM = getPEMStringFromPrivateKey(enroll.getKey());
            final Properties tlsProperties = new Properties ();
            tlsProperties.put("clientKeyBytes", tlsKeyPEM.getBytes(UTF_8));
            tlsProperties.put("clientCertBytes", tlsCertPEM.getBytes(UTF_8));

        } catch (EnrollmentException | InvalidArgumentException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return hfcaclient;

    }




    public static void main(String args[]) {
        try {
            Util.cleanUp();
            UserContext adminUser = new UserContext();
            adminUser.setName(Config.ADMIN);
            adminUser.setAffiliation(Config.ORG1);
            adminUser.setMspId(Config.ORG1_MSP);
            File f = new File (Config.CA1_TLSFILE);
            String certficate = new String (IOUtils.toByteArray(new FileInputStream(f)),"UTF-8");
            Properties properties = new Properties();
            properties.put("pemBytes", certficate.getBytes());
            properties.setProperty("pemFile", f.getAbsolutePath());
            properties.setProperty("allowAllHostNames", "true");
            CAClient caclient=new  CAClient(Config.CA1NAME, Config.CA_ORG1_URL, properties);
            caclient.setAdminUserContext(adminUser);
            adminUser =  caclient.enrollAdminUserTLS("admin", "adminpw");
            FabricClient fabClient = new FabricClient(adminUser);
            ChannelClient channelClient = fabClient.createChannelClient(Config.CHANNEL_NAME);
            Channel channel = channelClient.getChannel();
            Properties properties1 = Util.gete2ePro("peer",Config.ORG1_PEER_0);
            Peer peer = fabClient.getInstance().newPeer(Config.ORG1_PEER_0, Config.ORG1_PEER_0_URL,properties1);

            EventHub eventHub = fabClient.getInstance().newEventHub("eventhub01",Config.grpc+ Config.baseUrl+":7053");
            Properties orderPro = Util.gete2ePro("orderer", Config.ORDERER_NAME);
            Orderer orderer = fabClient.getInstance().newOrderer(Config.ORDERER_NAME, Config.ORDERER_URL,orderPro);
            channel.addPeer(peer);
            channel.addOrderer(orderer);
            channel.initialize();
            Logger.getLogger(QueryChaincode.class.getName()).log(Level.INFO, "Querying   ...");
            Collection<ProposalResponse>  responsesQuery = channelClient.queryByChainCode("mycc", "query", new String[] {"b"});
            for (ProposalResponse pres : responsesQuery) {
                String stringResponse = new String(pres.getChaincodeActionResponsePayload());
                Logger.getLogger(QueryChaincode.class.getName()).log(Level.INFO, stringResponse);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
