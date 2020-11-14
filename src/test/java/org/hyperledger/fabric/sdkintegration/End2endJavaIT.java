/*
 *
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.hyperledger.fabric.sdkintegration;

import java.io.IOException;

import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.TransactionRequest.Type;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.junit.Test;


/*
    This runs a version of end2end but with Java chaincode.
    It requires that End2endIT has been run already to do all enrollment and setting up of orgs,
    creation of the channels. None of that is specific to chaincode deployment language.
 */

/**
 * EndToEnd的Java链码版本,需要使用EndToEnd完成网络的搭建,这里只是采用不同的链码而已
 * @author nano
 *
 */
public class End2endJavaIT extends End2endIT {

    // 初始化,覆盖父类的路径设置
    {
        // Just print out what test is really running.
        testName = "End2endJavaIT";

        // this is relative to src/test/fixture and is where the Java chaincode source is.
        CHAIN_CODE_FILEPATH = "sdkintegration/javacc/sample1";
        // This is used only for GO.
        // 只需要对GO语言配置,其他的不需要
        CHAIN_CODE_PATH = null;
        // 链码名称
        CHAIN_CODE_NAME = "example_cc_java";
        CHAIN_CODE_LANG = Type.JAVA;
    }

    @Override
    void blockWalker(HFClient fabricClient, Channel channel) throws InvalidArgumentException, ProposalException, IOException {
        // block walker depends on the state of the chain after go's end2end. Nothing here is language specific so
        // there is no loss in coverage for not doing this.
    }

    /**
     * 初始化
     */
    @Override
    @Test
    public void setup() throws Exception {
        // 初始化存储文件
        sampleStore = new SampleStore(sampleStoreFile);
        // 注册与登记用户
        enrollUsersSetup(sampleStore);
        // 跑起来!
        runFabricTest(sampleStore);
    }

    /**
     * 构造通道
     *
     * @param channelName 通道名称
     * @param fabricClient Client
     * @param organization org
     */
    @Override
    Channel constructChannel(String channelName, HFClient fabricClient, SampleOrg organization) throws Exception {
        // override this method since we don't want to construct the channel that's been done.
        // Just get it out of the samplestore!
        // 覆写这个方法是因为不需要再重新构造通道了,只需要从本地存储中获取到即可
        fabricClient.setUserContext(organization.getAdminPeer());
        return sampleStore.getChannel(fabricClient, channelName).initialize();
    }
}
