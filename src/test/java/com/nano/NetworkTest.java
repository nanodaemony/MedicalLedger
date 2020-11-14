package com.nano;

import com.nano.redis.utils.RedisUtil;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * Description: Network Test
 *
 * @version: 1.0
 * @author: nano
 * @date: 2020/11/14 14:02
 */
@SpringBootTest
@RunWith(SpringRunner.class)
public class NetworkTest {


    @Test
    public void testRedisSetAndGet() {
        RedisUtil.set("Jack", 12);
        System.out.println(RedisUtil.get("Jack"));
    }


}
