package com.nano.common.utils;

import com.alibaba.fastjson.JSON;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonSyntaxException;


import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Objects;

/**
 * @author lx
 * @version V1.0
 * @date 2019/3/10 9:55
 * @email vinicolor.violet.end@gmail.com
 * Description:
 */
public class ParseJsonUtil {

    private static Gson getGsonObject() {
        return new GsonBuilder()
                .registerTypeAdapter(LocalDateTime.class, (JsonDeserializer<LocalDateTime>) (json, type, jsonDeserializationContext) -> {
                    String datetime = json.getAsJsonPrimitive().getAsString();
                    return LocalDateTime.parse(datetime, DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
                })
                .registerTypeAdapter(LocalDate.class, (JsonDeserializer<LocalDate>) (json, type, jsonDeserializationContext) -> {
                    String datetime = json.getAsJsonPrimitive().getAsString();
                    return LocalDate.parse(datetime, DateTimeFormatter.ofPattern("yyyy-MM-dd"));
                })
                .registerTypeAdapter(LocalDateTime.class, (JsonDeserializer<LocalDateTime>)
                        (json, type, context) -> LocalDateTime.ofEpochSecond(json.getAsJsonPrimitive().getAsLong() / 1000,
                                0, ZoneOffset.ofHours(8)))
                .create();
    }

    /**
     * 解析json字符串并转换成类
     *
     * @param tClass 转换的类
     * @param json   带解析的json字符串
     * @param <T>    泛型
     * @return 泛型类
     * @throws JsonSyntaxException 需要捕获处理
     */
    public static <T> T getObject(Class<T> tClass, String json) throws JsonSyntaxException {
        return getGsonObject().fromJson(json, tClass);
    }



    /**
     * 解析json字符串并转换成类
     * <p>必须要放在try catch块中才能捕获到</p>
     *
     * @param jsonData 待解析的json字符串
     * @param tClass   转换的类
     * @param <T>      泛型
     * @return T解析json字符串并转换成类
     */
    public static <T> T parseAndCheck(String jsonData, Class<T> tClass) {
        T t = null;
        try {
            t = ParseJsonUtil.getObject(tClass, jsonData);
        } catch (JsonSyntaxException j) {

        }

        // 进行数据校验
        Map<String, String> validResult = ValidatorUtils.validate(t);
        if (Objects.nonNull(validResult) && !validResult.isEmpty()) {
        }
        return t;
    }



}
