package com.nano.common.utils;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 * @author lx
 * @version V1.0
 * @date 2019/5/30 16:45
 * @email vinicolor.violet.end@gmail.com
 * Description:
 */
public class ObjectUtils {

    /**
     * 返回一个对象的属性和属性值
     */
    @SuppressWarnings("unchecked")
    public static Map<String, String> getProperty(Object entityName) {
        Map<String, String> map = new HashMap<String, String>();
        try {
            Class c = entityName.getClass();
            // 获得对象属性
            Field field[] = c.getDeclaredFields();
            for (Field f : field) {
                Object v = invokeMethod(entityName, f.getName(), null);
                map.put(f.getName(), v.toString());
            }
        } catch (Exception e) {
            map = null;
        }
        return map;
    }

    /**
     * 获得对象属性的值
     */
    @SuppressWarnings("unchecked")
    private static Object invokeMethod(Object owner, String methodName,
                                       Object[] args) throws Exception {
        Class ownerClass = owner.getClass();
        methodName = methodName.substring(0, 1).toUpperCase()
                + methodName.substring(1);
        Method method = null;
        try {
            method = ownerClass.getMethod("get" + methodName);
        } catch (SecurityException e) {
        } catch (NoSuchMethodException e) {
            return " can't find 'get" + methodName + "' method";
        }
        return method.invoke(owner);
    }
}
