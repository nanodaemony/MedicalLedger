package com.nano.common.utils;

import org.springframework.beans.BeanWrapper;
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.util.HashSet;
import java.util.Set;

/**
 * @author Vinicolor
 * @date 2018/10/6
 * <p>
 * Description:
 * 对实体类进行判断
 * 判断实体类中属性是否为空
 */
public class BeanUtils {

    public static Pageable getPageable(int page, int size) {
        Pageable pageable;
        try {
            pageable = PageRequest.of(page, size);
        } catch (IllegalArgumentException e) {
            return null;
        }
        return pageable;
    }

    /**
     * <p>获取到对象中属性为null的属性名  </P>
     *
     * @param source source 要拷贝的对象
     * @return 对象中属性为null的属性名
     */
    public static String[] getNullPropertyNames(Object source) {
        final BeanWrapper src = new BeanWrapperImpl(source);
        java.beans.PropertyDescriptor[] pds = src.getPropertyDescriptors();

        Set<String> emptyNames = new HashSet<>();
        for (java.beans.PropertyDescriptor pd : pds) {
            Object srcValue = src.getPropertyValue(pd.getName());
            if (srcValue == null) {
                emptyNames.add(pd.getName());
            }
        }
        String[] result = new String[emptyNames.size()];
        return emptyNames.toArray(result);
    }

    /**
     * <p>获取到对象中属性不为null的属性名  </P>
     *
     * @param source source 要拷贝的对象
     * @return 对象中属性不为null的属性名
     */
    public static String[] getNotNullPropertyNames(Object source) {
        final BeanWrapper src = new BeanWrapperImpl(source);
        java.beans.PropertyDescriptor[] pds = src.getPropertyDescriptors();

        Set<String> emptyNames = new HashSet<>();
        for (java.beans.PropertyDescriptor pd : pds) {
            Object srcValue = src.getPropertyValue(pd.getName());
            if (srcValue != null) {
                emptyNames.add(pd.getName());
            }
        }
        String[] result = new String[emptyNames.size()];
        return emptyNames.toArray(result);
    }

    /**
     * 复制source的属性到target对象中
     * 但是要求复制的属性在target中的对应属性要为空
     * 如果target对象中的该属性不为空，将不被复制，将跳过
     *
     * @param source 需要被复制的对象
     * @param target 需要复制的对象
     */
    public static void copyPropertiesTargetNotNull(Object source, Object target) {
        org.springframework.beans.BeanUtils.copyProperties(source, target, getNotNullPropertyNames(target));
    }

}
