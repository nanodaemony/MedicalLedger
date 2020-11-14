package com.nano.common.vo;


import com.nano.common.enums.ExceptionEnum;
import com.nano.common.enums.ResultCodeEnum;

import java.io.Serializable;

/**
 * 通用返回对象
 * @author nano
 */
public class CommonResult<T> implements Serializable {

    private static final long serialVersionUID = -2927490351829187712L;

    /**
     * 状态码 用于返回各种状态信息 如200 401 403 500
     */
    private Integer code;

    /**
     * 消息
     */
    private String message;

    /**
     * 数据
     */
    private T data;

    protected CommonResult() {
    }

    /**
     * 私有构造器
     *
     * @param code code
     * @param message 信息
     * @param data 数据
     */
    private CommonResult(Integer code, String message, T data) {
        this.code = code;
        this.message = message;
        this.data = data;
    }

    /**
     * 成功返回结果
     *
     * @param <T> String 获取的数据
     */
    public static <T> CommonResult<String> success() {
        return new CommonResult<>(ResultCodeEnum.SUCCESS.getCode(), ResultCodeEnum.SUCCESS.getMessage(), "");
    }

    /**
     * 成功返回结果
     *
     * @param data 获取的数据
     */
    public static <T> CommonResult<T> success(T data) {
        return new CommonResult<T>(ResultCodeEnum.SUCCESS.getCode(), ResultCodeEnum.SUCCESS.getMessage(), data);
    }


    /**
     * 成功返回结果
     *
     * @param data 获取的数据
     * @param  message 提示信息
     */
    public static <T> CommonResult<T> success(T data, String message) {
        return new CommonResult<>(ResultCodeEnum.SUCCESS.getCode(), message, data);
    }


    /**
     * 失败返回结果
     * @param exceptionEnum 错误枚举
     */
    public static <T> CommonResult<ExceptionEnum> failed(ExceptionEnum exceptionEnum) {
        return new CommonResult<>(ResultCodeEnum.FAILED.getCode(), ResultCodeEnum.FAILED.getMessage(), exceptionEnum);
    }


    /**
     * 失败返回结果
     */
    public static <T> CommonResult<T> failed(Integer code, String message) {
        return new CommonResult<T>(code, message, null);
    }



    /**
     * 失败返回结果
     * @param message 提示信息
     */
    public static <T> CommonResult<String> failed(String message) {
        return new CommonResult<>(ResultCodeEnum.FAILED.getCode(), ResultCodeEnum.FAILED.getMessage(), message);
    }

    /**
     * 失败返回结果
     */
    public static <T> CommonResult<String> failed() {
        return failed("");
    }


    /**
     * 参数验证失败返回结果
     */
    public static <T> CommonResult<T> validateFailed() {
        return failed(ResultCodeEnum.VALIDATE_FAILED.getCode(), ResultCodeEnum.VALIDATE_FAILED.getMessage());
    }


    /**
     * 参数验证失败返回结果
     * @param message 提示信息
     */
    public static <T> CommonResult<T> validateFailed(String message) {
        return new CommonResult<T>(ResultCodeEnum.VALIDATE_FAILED.getCode(), message, null);
    }

    /**
     * 未登录返回结果
     */
    public static <T> CommonResult<T> unauthorized(T data) {
        return new CommonResult<T>(ResultCodeEnum.UNAUTHORIZED.getCode(), ResultCodeEnum.UNAUTHORIZED.getMessage(), data);
    }

    /**
     * 未授权返回结果
     */
    public static <T> CommonResult<T> forbidden(T data) {
        return new CommonResult<T>(ResultCodeEnum.FORBIDDEN.getCode(), ResultCodeEnum.FORBIDDEN.getMessage(), data);
    }


    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }
}
