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

import org.hyperledger.fabric.sdk.BlockEvent.TransactionEvent;
import org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy;
import org.hyperledger.fabric.sdk.ChaincodeID;
import org.hyperledger.fabric.sdk.ChaincodeResponse;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.InstantiateProposalRequest;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.ProposalResponse;
import org.hyperledger.fabric.sdk.QueryByChaincodeRequest;
import org.hyperledger.fabric.sdk.TransactionInfo;
import org.hyperledger.fabric.sdk.TransactionProposalRequest;
import org.hyperledger.fabric.sdk.TransactionRequest.Type;
import org.hyperledger.fabric.sdk.exception.ChaincodeEndorsementPolicyParseException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Channel client的包装类.
 *
 * @author nano
 */
public class ChannelClient {
    /**
     * channel名称
     */
    String channelName;

    /**
     * Channel
     */
    Channel channel;

    /**
     * Fabric代理类
     */
    FabricClient fabClient;

    public String getChannelName() {
        return channelName;
    }

    public Channel getChannel() {
        return channel;
    }

    public FabricClient getFabClient() {
        return fabClient;
    }

    /**
     * 构造器
     *
     * @param channelName  通道名
     * @param channel      通道
     * @param fabricClient Fabric代理对象
     */
    public ChannelClient(String channelName, Channel channel, FabricClient fabricClient) {
        this.channelName = channelName;
        this.channel = channel;
        this.fabClient = fabricClient;
    }

    /**
     * 通过Chaincode查询
     * Query by chaincode.
     *
     * @param chaincodeName 链码名称
     * @param functionName  函数名称
     * @param args          参数
     */
    public Collection<ProposalResponse> queryByChainCode(String chaincodeName, String functionName, String[] args)
            throws InvalidArgumentException, ProposalException {
        Logger.getLogger(ChannelClient.class.getName()).log(Level.INFO,
                "Querying " + functionName + " on channel " + channel.getName());
        // 构造query的提案
        QueryByChaincodeRequest request = fabClient.getInstance().newQueryProposalRequest();
        // 链码ID
        ChaincodeID chaincodeId = ChaincodeID.newBuilder().setName(chaincodeName).build();
        request.setChaincodeID(chaincodeId);
        request.setFcn(functionName);
        if (args != null) {
            request.setArgs(args);
        }
        // 通过channel执行query请求
        Collection<ProposalResponse> response = channel.queryByChaincode(request);
        return response;
    }

    /**
     * 发送交易提案
     * Send transaction proposal.
     *
     * @param proposalRequest 交易提案请求
     */
    public Collection<ProposalResponse> sendTransactionProposal(TransactionProposalRequest proposalRequest)
            throws ProposalException, InvalidArgumentException {
        Logger.getLogger(ChannelClient.class.getName()).log(Level.INFO,
                "Sending transaction proposal on channel :" + channel.getName());
        // 往通道中不同的Peer结点发送交易请求
        Collection<ProposalResponse> responses = channel.sendTransactionProposal(proposalRequest, channel.getPeers());
        // 遍历各个Peer背书的响应结果
        for (ProposalResponse response : responses) {
            String stringResponse = new String(response.getChaincodeActionResponsePayload());
            System.out.println("是否验证:" + response.isVerified());
            Logger.getLogger(ChannelClient.class.getName()).log(Level.INFO,
                    "Transaction proposal on channel " + channel.getName() + " " + response.getMessage() + " "
                            + response.getStatus() + " with transaction id:" + response.getTransactionID());
            Logger.getLogger(ChannelClient.class.getName()).log(Level.INFO, stringResponse);
            if (response.getChaincodeActionResponseStatus() == ChaincodeResponse.Status.SUCCESS.getStatus()) {
                System.out.println("执行背书成功");
            }
        }
        // 将背书的结果当成交易发送到排序结点
        CompletableFuture<TransactionEvent> cf = channel.sendTransaction(responses);
        Logger.getLogger(ChannelClient.class.getName()).log(Level.INFO, cf.toString());
        return responses;
    }

    /**
     * 实例化Chaincode
     * Instantiate chaincode.
     *
     * @param chaincodeName 链码名称
     * @param version       版本
     * @param chaincodePath 链码路径
     * @param language      语言
     * @param functionName  函数名
     * @param functionArgs  函数参数
     * @param policyPath    背书策略
     */
    public Collection<ProposalResponse> instantiateChainCode(String chaincodeName, String version, String chaincodePath,
                                                             String language, String functionName, String[] functionArgs,
                                                             String policyPath)
            throws InvalidArgumentException, ProposalException, ChaincodeEndorsementPolicyParseException, IOException {
        Logger.getLogger(ChannelClient.class.getName()).log(Level.INFO,
                "Instantiate proposal request " + chaincodeName + " on channel " + channel.getName()
                        + " with Fabric client " + fabClient.getInstance().getUserContext().getMspId() + " "
                        + fabClient.getInstance().getUserContext().getName());
        InstantiateProposalRequest instantiateProposalRequest = fabClient.getInstance()
                .newInstantiationProposalRequest();
        // 设置超时时间
        instantiateProposalRequest.setProposalWaitTime(180000);
        // 获取链码ID
        ChaincodeID.Builder chaincodeIDBuilder = ChaincodeID.newBuilder().setName(chaincodeName).setVersion(version)
                .setPath(chaincodePath);
        ChaincodeID chaincodeId = chaincodeIDBuilder.build();
        Logger.getLogger(ChannelClient.class.getName()).log(Level.INFO,
                "Instantiating Chaincode ID " + chaincodeName + " on channel " + channel.getName());
        instantiateProposalRequest.setChaincodeID(chaincodeId);
        // 判断链码的语言
        if (language.equals(Type.GO_LANG.toString())) {
            instantiateProposalRequest.setChaincodeLanguage(Type.GO_LANG);
        } else {
            instantiateProposalRequest.setChaincodeLanguage(Type.JAVA);
        }
        // 设置函数名与参数
        instantiateProposalRequest.setFcn(functionName);
        instantiateProposalRequest.setArgs(functionArgs);
        Map<String, byte[]> tm = new HashMap<>();
        tm.put("HyperLedgerFabric", "InstantiateProposalRequest:JavaSDK".getBytes(UTF_8));
        tm.put("method", "InstantiateProposalRequest".getBytes(UTF_8));
        instantiateProposalRequest.setTransientMap(tm);
        // 指定背书策略
        if (policyPath != null) {
            ChaincodeEndorsementPolicy endorsementPolicy = new ChaincodeEndorsementPolicy();
            endorsementPolicy.fromYamlFile(new File(policyPath));
            instantiateProposalRequest.setChaincodeEndorsementPolicy(endorsementPolicy);
        }
        // 在各个peer结点实例化链码
        Collection<ProposalResponse> responses = channel.sendInstantiationProposal(instantiateProposalRequest);
        CompletableFuture<TransactionEvent> cf = channel.sendTransaction(responses);
        Logger.getLogger(ChannelClient.class.getName()).log(Level.INFO,
                "Chaincode " + chaincodeName + " on channel " + channel.getName() + " instantiation " + cf);
        return responses;
    }

    /**
     * 通过一个ID查询交易
     * Query a transaction by id.
     *
     * @param transactionId 交易ID
     */
    public TransactionInfo queryByTransactionId(String transactionId) throws ProposalException, InvalidArgumentException {
        Logger.getLogger(ChannelClient.class.getName()).log(Level.INFO,
                "Querying by transaction id " + transactionId + " on channel " + channel.getName());
        // 获取channel里面的全部Peer结点
        Collection<Peer> peers = channel.getPeers();
        for (Peer peer : peers) {
            // 通过Peer结点查询交易信息
            TransactionInfo info = channel.queryTransactionByID(peer, transactionId);
            return info;
        }
        return null;
    }

}
