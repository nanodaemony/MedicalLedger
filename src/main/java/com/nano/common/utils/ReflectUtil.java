package com.nano.common.utils;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * @author luoxin
 * @version V1.0
 * @date 2019/10/12
 * @email vinicolor.violet.end@gmail.com
 * Description:
 */
public class ReflectUtil {

    public static Object randomFillAllStringFieldExclude(String className, String... arg) {
        Object t;
        Class<?> tClass;
        try {
            tClass = Class.forName(className);
            t = tClass.getConstructor().newInstance();
        } catch (NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException | ClassNotFoundException e) {
            e.printStackTrace();
            return null;
        }

        Set<String> excludeFieldSet = new HashSet<>(Arrays.asList(arg));

        /*
         * 得到类中的所有属性集合
         */
        Field[] fs = tClass.getDeclaredFields();
        for (Field f : fs) {
            // 设置些属性是可以访问的
            f.setAccessible(true);
            // 检查是否是需要排除的Field
            if (excludeFieldSet.contains(f.getName())) {
                continue;
            }
            // 得到此属性的类型
            String type = f.getType().toString();
            if (type.endsWith("String")) {
                try {
                    // 给属性设值
                    f.set(t, StringUtils.getRandomString(16));
                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                }
            }
        }
        return t;
    }

    public static <T> T randomFillAllStringFieldExclude(Class<T> tClass, String... arg) {
        if (Objects.isNull(tClass)) {
            return null;
        }
        T t = null;
        try {
            t = tClass.getConstructor().newInstance();
        } catch (NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            e.printStackTrace();
        }

        Set<String> excludeFieldSet = new HashSet<>(Arrays.asList(arg));

        /*
         * 得到类中的所有属性集合
         */
        Field[] fs = tClass.getDeclaredFields();
        for (Field f : fs) {
            // 设置些属性是可以访问的
            f.setAccessible(true);
            // 检查是否是需要排除的Field
            if (excludeFieldSet.contains(f.getName())) {
                continue;
            }
            // 得到此属性的类型
            String type = f.getType().toString();
            if (type.endsWith("String")) {
                try {
                    // 给属性设值
                    f.set(t, StringUtils.getRandomString(16));
                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                }
            }
        }
        return t;
    }

}

