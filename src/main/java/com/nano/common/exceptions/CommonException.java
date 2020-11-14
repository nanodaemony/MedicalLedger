package com.nano.common.exceptions;



import com.nano.common.enums.ExceptionEnum;

import lombok.Getter;

/**
 * 自定义API异常
 * @author: nano
 */
@Getter
public class CommonException extends RuntimeException {

    /**
     * 错误视图对象
     */
    private Integer errorCode;

    /**
     * 异常信息
     */
    private String msg;


    public CommonException(ExceptionEnum exceptionEnum) {
        this.errorCode = exceptionEnum.getErrorCode();
        this.msg = exceptionEnum.getMessage();
    }

    public CommonException(ExceptionEnum exceptionEnum, String cause) {
        super(cause);
        this.errorCode = exceptionEnum.getErrorCode();
        this.msg = exceptionEnum.getMessage();
    }

    public CommonException(String message) {
        super(message);
    }

    public CommonException(Throwable cause) {
        super(cause);
    }

    public CommonException(String message, Throwable cause) {
        super(message, cause);
    }

}
