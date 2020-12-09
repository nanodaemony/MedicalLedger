package com.nano.sharing.test;

import com.nano.sharing.Encryption;

import org.springframework.stereotype.Component;

/**
 * Description: Receiver client for data sharing.
 *
 * @version: 1.0
 * @author: nano
 * @date: 2020/12/6 14:53
 */
@Component
public class ReceiverClient implements ShareEvent {


    private Encryption receiver = new Encryption();


    /**
     * 向服务器进行注册
     */
    public void register() {

    }


    /**
     * 完成代理并进行消息解析
     */
    @Override
    public void finishProxyAndGetMessage() {

    }
}
