package com.nano.common.utils;

import org.springframework.beans.BeanUtils;
import org.springframework.data.domain.Page;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;

/**
 * @author lx
 * @version V1.0
 * @date 2019/4/1 16:28
 * @email vinicolor.violet.end@gmail.com
 * Description:
 */
public class ConvertUtils {

    public static <T, R> R convert(T source, Class<R> destClass) {
        if (null == source) {
            return null;
        }

        R r = null;
        try {
            r = destClass.getConstructor().newInstance();
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            e.printStackTrace();
        }
        BeanUtils.copyProperties(source, r);
        return r;
    }

    /**
     * @param sourcePage 待转换的Page
     * @param destClass  转换的类型
     * @param <T>        源
     * @param <R>        转换的类型
     * @return
     */
    public static <T, R> List<R> convert(Page<T> sourcePage, Class<R> destClass) {

        List<R> destList = new ArrayList<>();

        if (sourcePage.getTotalElements() <= 0) {
            return destList;
        }

        sourcePage.stream().forEach((t) -> {
            R r = null;
            try {
                r = destClass.getConstructor().newInstance();
            } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
                e.printStackTrace();
            }
            BeanUtils.copyProperties(t, r);
            destList.add(r);
        });
        return destList;
    }
}
