package com.nano.common.utils;

import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author luoxin
 * @version V1.0
 * @date 2019/10/12
 * @email vinicolor.violet.end@gmail.com
 * Description:
 */
public class StringUtils {

    private static final Pattern linePattern = Pattern.compile("_(\\w)");

    /**
     * 生成随机字符串
     *
     * @param lengths 用户要求产生字符串的长度
     * @return 生成的随机字符串
     */
    public static String getRandomString(int... lengths) {
        int length = 16;
        if (lengths.length != 0) {
            length = lengths[0];
        }
        String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(62);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }


    /**
     * 将下划线大写常量名转换为标准驼峰格式命名
     * 常量名一般以下划线分割，整体为大写
     * 例如EVAL_CONSTANT
     * 输出evalConstant
     *
     * @param constantName 待转换的常量名
     * @return 标准驼峰格式的命名
     */
    private static String constantNameConvertHumpName(String constantName) {
        constantName = constantName.toLowerCase();
        Matcher matcher = linePattern.matcher(constantName);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            matcher.appendReplacement(sb, matcher.group(1).toUpperCase());
        }
        matcher.appendTail(sb);
        return sb.toString();
    }



    /**
     * 将下划线大写常量名转换为标准驼峰格式类命名
     * 常量名一般以下划线分割，整体为大写
     * 例如EVAL_CONSTANT
     * 输出EvalConstant
     *
     * @param constantName 待转换的常量名
     * @return 标准驼峰格式的类名
     */
    public static String constantNameConvertCamel(String constantName) {
        return constantNameConvertHumpName(constantName);
    }

    /**
     * 将下划线大写常量名转换为标准驼峰格式类命名
     * 常量名一般以下划线分割，整体为大写
     * 例如EVAL_CONSTANT
     * 输出EvalConstant
     * 用在枚举类型的转换上
     *
     * @param constantName 待转换的常量名
     * @return 标准驼峰格式的类名
     */
    public static String constantNameConvertClassName(String constantName) {
        String humpName = constantNameConvertHumpName(constantName);
        StringBuilder sb = new StringBuilder(humpName);
        // 处理第一个字符，将其替换为大写
        sb.replace(0, 1, constantName.substring(0, 1).toUpperCase());
        return sb.toString();
    }

    public static String constantNameRemoveUnderscores(String constantName) {
        return constantName.replaceAll("_", "");
    }
}