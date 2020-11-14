package com.nano.common.enums;


import lombok.Getter;

/**
 * 枚举了一些常用API操作码
 * @author: nano
 */
@Getter
public enum ResultCodeEnum {

    /**
     * 成功
     */
    SUCCESS(200, "SUCCESS"),

    /**
     * 失败
     */
    FAILED(500, "ERROR"),

    /**
     * 参数校验失败
     */
    VALIDATE_FAILED(404, "参数校验失败"),

    /**
     * 未认证
     */
    UNAUTHORIZED(401, "请登录或Token已过期"),

    /**
     * 无权限
     */
    FORBIDDEN(403, "FORBIDDEN")
    ;

    /**
     * 代号
     */
    private Integer code;

    /**
     * 提示消息
     */
    private String message;

    private ResultCodeEnum(Integer code, String message) {
        this.code = code;
        this.message = message;
    }

}
