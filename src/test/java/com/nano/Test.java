package com.nano;

import com.nano.core.LocalStore;
import com.nano.core.MedicalUtil;
import com.nano.redis.utils.RedisUtil;

import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.File;

/**
 * Description:
 *
 * @version: 1.0
 * @author: nano
 * @date: 2020/11/19 19:51
 */
@SpringBootTest
@RunWith(SpringRunner.class)
public class Test {



    @org.junit.Test
    public void test() {

        try {
            RedisUtil.set("b", "12");
            System.out.println(RedisUtil.get("b"));

            LocalStore localStore = new LocalStore(new File("G:\\HFCSampletest.properties"));

            HFClient fabricClient = HFClient.createNewInstance();

            // 设置加密套件
            fabricClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

            Channel channelthirdparty = localStore.getChannel(fabricClient, "channelthirdparty");

            System.out.println(channelthirdparty.getName());

        } catch (Exception e) {
            e.printStackTrace();
        }




    }



}
