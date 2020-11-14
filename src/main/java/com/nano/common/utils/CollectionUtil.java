package com.nano.common.utils;

import java.util.List;

/**
 * 集合工具类
 * @author nano
 */
public class CollectionUtil {

    public static <T> void printList(List<T> list) {
        if (list == null) {
            return;
        }
        list.stream().map(Object::toString)
        .forEach(System.out::println);
    }


}
