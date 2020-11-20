/****************************************************** 
 *  Copyright 2018 IBM Corporation 
 *  Licensed under the Apache License, Version 2.0 (the "License"); 
 *  you may not use this file except in compliance with the License. 
 *  You may obtain a copy of the License at 
 *  http://www.apache.org/licenses/LICENSE-2.0 
 *  Unless required by applicable law or agreed to in writing, software 
 *  distributed under the License is distributed on an "AS IS" BASIS, 
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 *  See the License for the specific language governing permissions and 
 *  limitations under the License.
 */
package com.nano.anothertest;

import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.ChannelConfiguration;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.Orderer;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

import java.io.File;
import java.util.Collection;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * 创建通道
 *
 * @author Balaji Kadambi
 */

public class CreateChannel {

    public static void main(String[] args) {
        try {
            CryptoSuite.Factory.getCryptoSuite();
            // 删除指定的"users"路径
            Util.cleanUp();
            // 构造Channel
            // 初始化org1的Admin用户
            UserContext org1Admin = new UserContext();
            // 打开组织1的用户管理员的私钥
            File pkFolder1 = new File(Config.ORG1_USR_ADMIN_PK);
            File[] pkFiles1 = pkFolder1.listFiles();
            // 打开组织1的用户管理员的证书
            File certFolder1 = new File(Config.ORG1_USR_ADMIN_CERT);
            File[] certFiles1 = certFolder1.listFiles();

            // 登记Org1的Admin 需传入Admin私钥与证书的路径
            Enrollment enrollOrg1Admin = Util.getEnrollment(Config.ORG1_USR_ADMIN_PK, pkFiles1[0].getName(),
                    Config.ORG1_USR_ADMIN_CERT, certFiles1[0].getName());
            // 设置AdminUser的属性
            org1Admin.setEnrollment(enrollOrg1Admin);
            org1Admin.setMspId(Config.ORG1_MSP);
            org1Admin.setName(Config.ADMIN);

            // 下面同样的步骤初始化org2的Admin用户
            UserContext org2Admin = new UserContext();
            File pkFolder2 = new File(Config.ORG2_USR_ADMIN_PK);
            File[] pkFiles2 = pkFolder2.listFiles();
            File certFolder2 = new File(Config.ORG2_USR_ADMIN_CERT);
            File[] certFiles2 = certFolder2.listFiles();
            Enrollment enrollOrg2Admin = Util.getEnrollment(Config.ORG2_USR_ADMIN_PK, pkFiles2[0].getName(),
                    Config.ORG2_USR_ADMIN_CERT, certFiles2[0].getName());
            org2Admin.setEnrollment(enrollOrg2Admin);
            org2Admin.setMspId(Config.ORG2_MSP);
            org2Admin.setName(Config.ADMIN);

            // 构造操作Fabric的客户端
            FabricClient fabClient = new FabricClient(org1Admin);

            // Create a new channel
            // 获取排序结点的代理对象,ORDERER_NAME = "orderer.example.com",ORDERER_URL = "grpc://localhost:7050"
            Orderer orderer = fabClient.getInstance().newOrderer(Config.ORDERER_NAME, Config.ORDERER_URL);

            // 初始化通道配置类,传入通道配置文件的路径: "config/channel.tx"
            ChannelConfiguration channelConfiguration = new ChannelConfiguration(new File(Config.CHANNEL_CONFIG_PATH));

            // 获取通道配置文件的签名,这里传入的是组织1的Admin
            byte[] channelConfigurationSignatures = fabClient.getInstance()
                    .getChannelConfigurationSignature(channelConfiguration, org1Admin);

            // 使用上面的对象与配置类创建通道
            Channel mychannel = fabClient.getInstance().newChannel(Config.CHANNEL_NAME, orderer, channelConfiguration,
                    channelConfigurationSignatures);

            // 获取几个Peer结点的代理对象
            Peer peer0_org1 = fabClient.getInstance().newPeer(Config.ORG1_PEER_0, Config.ORG1_PEER_0_URL);
            Peer peer1_org1 = fabClient.getInstance().newPeer(Config.ORG1_PEER_1, Config.ORG1_PEER_1_URL);
            Peer peer0_org2 = fabClient.getInstance().newPeer(Config.ORG2_PEER_0, Config.ORG2_PEER_0_URL);
            Peer peer1_org2 = fabClient.getInstance().newPeer(Config.ORG2_PEER_1, Config.ORG2_PEER_1_URL);
            // 将组织1中对应的Peer结点加入Channel中
            mychannel.joinPeer(peer0_org1);
            mychannel.joinPeer(peer1_org1);
            // 将排序结点加入channel
            mychannel.addOrderer(orderer);
            // 通道初始化
            mychannel.initialize();

            // 这里传入的是组织2的Admin
            fabClient.getInstance().setUserContext(org2Admin);
            // 获取Channel代理对象
            mychannel = fabClient.getInstance().getChannel("mychannel");
            // 再次加入组织2中的相应结点
            mychannel.joinPeer(peer0_org2);
            mychannel.joinPeer(peer1_org2);

            // 打印创建成功的通道名
            Logger.getLogger(CreateChannel.class.getName()).log(Level.INFO, "Channel created " + mychannel.getName());

            // 获取当前通道中的全部peer结点
            Collection peers = mychannel.getPeers();
            // 迭代遍历当前通道的全部结点
            Iterator iterator = peers.iterator();
            while (iterator.hasNext()) {
                Peer peer = (Peer) iterator.next();
                // 打印当前结点的信息
                Logger.getLogger(CreateChannel.class.getName()).log(Level.INFO, peer.getName() + ", whose URL is " + peer.getUrl());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //  本例输出日志:
    //	log4j:WARN No appenders could be found for logger (org.hyperledger.fabric.sdk.helper.Config).
    //	log4j:WARN Please initialize the log4j system properly.
    //	log4j:WARN See http://logging.apache.org/log4j/1.2/faq.html#noconfig for more info.
    //	Nov 06, 2020 11:33:38 AM org.example.util.Util deleteDirectory
    //	INFO: Deleting - users
    //	Nov 06, 2020 11:33:38 AM org.example.network.CreateChannel main
    //	INFO: Channel created mychannel
    //	Nov 06, 2020 11:33:38 AM org.example.network.CreateChannel main
    //	INFO: peer0.org2.example.com at grpc://localhost:8051
    //	Nov 06, 2020 11:33:38 AM org.example.network.CreateChannel main
    //	INFO: peer1.org1.example.com at grpc://localhost:7056
    //	Nov 06, 2020 11:33:38 AM org.example.network.CreateChannel main
    //	INFO: peer1.org2.example.com at grpc://localhost:8056
    //	Nov 06, 2020 11:33:38 AM org.example.network.CreateChannel main
    //	INFO: peer0.org1.example.com at grpc://localhost:7051

}
