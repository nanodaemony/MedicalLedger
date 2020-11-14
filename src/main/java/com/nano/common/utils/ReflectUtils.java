package com.nano.common.utils;

import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.persistence.Id;

/**
 * @author luoxin
 * @version V1.0
 * @date 2019/10/12
 * @email vinicolor.violet.end@gmail.com
 * Description:
 */
public class ReflectUtils {

    /**
     * 随机填充给定类名称的所有String字段
     *
     * @param className 类全限定名
     * @param arg       不定类型，排除填充的字段名
     * @return 填充完成的对象
     */
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
        return randomFillAllStringFieldExclude(t, arg, tClass.getDeclaredFields());
    }

    /**
     * 随机填充给定类名称的所有String字段
     *
     * @param tClass 传入Class
     * @param arg    不定类型，排除填充的字段名
     * @param <T>    返回类型
     * @return 填充完成的对象
     */
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
        return randomFillAllStringFieldExclude(t, arg, tClass.getDeclaredFields());
    }

    /**
     * 随机填充给实例名称的所有String字段
     *
     * @param t              待填充的实例
     * @param arg            不定类型，排除填充的字段名
     * @param declaredFields 需要扫描的字段
     * @param <T>            返回类型
     * @return 返回类型
     */
    private static <T> T randomFillAllStringFieldExclude(T t, String[] arg, Field[] declaredFields) {
        Set<String> excludeFieldSet = new HashSet<>(Arrays.asList(arg));

        /*
         * 得到类中的所有属性集合
         */
        for (Field f : declaredFields) {
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

    /**
     * 反射获取带有注解的字段的名称和类型
     *
     * @param t   带获取的对象
     * @param c   注解类
     * @param <T> 继承注解
     * @return 带有注解的字段的名称和类型的Map
     */
    @SuppressWarnings("rawtypes")
    public static <T extends Annotation> Map<String, Class> getAnnotationValue(Object t, Class<T> c) {
        if (Objects.isNull(t)) {
            return null;
        }
        Map<String, Class> propertyMap = new HashMap<>(4);
        // 获得带有传入公共注解的字段
        Field[] fields = t.getClass().getFields();
        Set<Field> fieldSet = new HashSet<>(Arrays.asList(fields));
        fields = t.getClass().getDeclaredFields();
        Collections.addAll(fieldSet, fields);
        for (Field field : fieldSet) {
            if (!field.isAccessible()) {
                field.setAccessible(true);
            }
            Annotation annotation = field.getAnnotation(c);
            if (Objects.nonNull(annotation)) {
                propertyMap.put(field.getName(), field.getType());
            }
        }
        return propertyMap;
    }

    /**
     * 反射获取带有注解的字段的名称和类型
     *
     * @param t   带获取的对象
     * @param a   注解类
     * @param <T> 继承注解
     * @return 带有注解的字段的名称和类型的Map
     */
    @SuppressWarnings("rawtypes")
    public static <A extends Annotation, T> Map<String, Class> getAnnotationValue(Class<T> t, Class<A> a) {
        Object o;
        try {
            Constructor c = t.getDeclaredConstructor();
            o = c.newInstance();
        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException | InstantiationException e) {
            e.printStackTrace();
            return null;
        }
        return getAnnotationValue(o, a);
    }

    /**
     * 获得带有@Id注解的字段的值
     * 如果没有将返回null
     * 如果存在则返回数据
     *
     * @param t 待检查的对象
     * @return Object
     * @throws IllegalAccessException 对象访问失败将会抛出
     */
    public static Object getIdAnnotationValue(Object t) throws IllegalAccessException {
        if (Objects.isNull(t)) {
            return null;
        }
        Object idAnnotationValue = null;
        // 获得带有@Id注解的字段
        Field[] fields = t.getClass().getDeclaredFields();
        for (Field field : fields) {
            if (!field.isAccessible()) {
                field.setAccessible(true);
            }
            Annotation annotation = field.getAnnotation(Id.class);
            if (Objects.nonNull(annotation)) {
                idAnnotationValue = field.get(t);
            }
        }
        return idAnnotationValue;
    }

}

