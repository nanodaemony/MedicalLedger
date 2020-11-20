package com.nano.anothertest;

import org.apache.commons.compress.utils.IOUtils;
import org.hyperledger.fabric.sdk.ChaincodeID;
import org.hyperledger.fabric.sdk.ChaincodeResponse;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.EventHub;
import org.hyperledger.fabric.sdk.Orderer;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.ProposalResponse;
import org.hyperledger.fabric.sdk.TransactionProposalRequest;

import java.io.File;
import java.io.FileInputStream;
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
public class InvokeChaincode {

    private static final byte[] EXPECTED_EVENT_DATA = "!".getBytes(UTF_8);
    private static final String EXPECTED_EVENT_NAME = "event";

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
            Properties properties2 = Util.gete2ePro("peer",Config.ORG2_PEER_0);
            Peer peer2 = fabClient.getInstance().newPeer(Config.ORG2_PEER_0, Config.ORG2_PEER_0_URL,properties2);
            EventHub eventHub = fabClient.getInstance().newEventHub("eventhub01", Config.grpc+Config.baseUrl+":7053",properties1);
//			EventHub eventHub2 = fabClient.getInstance().newEventHub("eventhub02", "grpcs://"+Config.baseUrl+":9053");
            Properties orderPro = Util.gete2ePro("orderer",Config.ORDERER_NAME);
            Orderer orderer = fabClient.getInstance().newOrderer(Config.ORDERER_NAME, Config.ORDERER_URL,orderPro);
            channel.addPeer(peer);
            channel.addPeer(peer2);//背书策略为OR的话不需要添加 peer2
            channel.addEventHub(eventHub);
            channel.addOrderer(orderer);
            channel.initialize();

            TransactionProposalRequest request = fabClient.getInstance().newTransactionProposalRequest();
            ChaincodeID ccid = ChaincodeID.newBuilder().setName(Config.CHAINCODE_1_NAME).build();
            request.setChaincodeID(ccid);
            request.setFcn("invoke");
            String[] arguments = { "a", "b", "11" };
            request.setArgs(arguments);
            request.setProposalWaitTime(1000);

            Map<String, byte[]> tm2 = new HashMap<>();
            tm2.put("HyperLedgerFabric", "TransactionProposalRequest:JavaSDK".getBytes(UTF_8));
            tm2.put("method", "TransactionProposalRequest".getBytes(UTF_8));
            tm2.put("result", ":)".getBytes(UTF_8));
            tm2.put(EXPECTED_EVENT_NAME, EXPECTED_EVENT_DATA);
            request.setTransientMap(tm2);
            Collection<ProposalResponse> responses = channelClient.sendTransactionProposal(request);
            for (ProposalResponse res: responses) {
                ChaincodeResponse.Status status = res.getStatus();
                Logger.getLogger(InvokeChaincode.class.getName()).log(Level.INFO,"Invoked on "+Config.CHAINCODE_1_NAME + ". Status - " + status);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
