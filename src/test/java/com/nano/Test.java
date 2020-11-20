package com.nano;

import com.nano.redis.utils.RedisUtil;

import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

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

        RedisUtil.set("b", "12");
        System.out.println(RedisUtil.get("b"));

    }



}
