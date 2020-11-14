package com.nano.common.enums;

import lombok.Getter;

/**
 * 采集器请求码的枚举
 *
 * @author nano
 * 根据项目情况来自定义
 */
@Getter
public enum CollectorCodeEnum {

    /**
     * 服务器是否在线请求
     */
    SERVER_STATUS(101, "服务器在线"),
    RESPONSE_SERVER_STATUS(102, "服务器在线"),

    // URL:  103  param=103

    // URL:  105

    /**
     * 上传手术信息
     */
    COLLECTION_OPERATION_INFO(103, "收到手术信息"),
    RESPONSE_COLLECTION_OPERATION_INFO(104, "收到手术信息"),

    /**
     * 开始手术采集数据
     */
    COLLECTION_START_OPERATION(105, "开始采集数据"),
    RESPONSE_COLLECTION_START_OPERATION(106, "开始采集数据"),

    /**
     * 仪器数据
     */
    COLLECTION_DEVICE_DATA(107, "Device Data"),
    RESPONSE_COLLECTION_DEVICE_DATA(108, "Store Device Data"),
    RESPONSE_COLLECTION_DEVICE_DATA_BUT_NOT_STORE_CURRENT_DATA(108, "当前手术暂未开始或者已经结束"),

    /**
     * 标记数据
     */
    COLLECTION_OPERATION_MARK(109, "收到手术标记数据"),
    RESPONSE_COLLECTION_OPERATION_MARK(110, "收到手术标记数据"),

    /**
     * 停止手术采集数据
     */
    COLLECTION_STOP_OPERATION(111, "停止采集数据"),
    RESPONSE_COLLECTION_STOP_OPERATION(112, "停止采集数据"),

    /**
     * 术后仪器评价信息
     */
    COLLECTION_DEVICE_EVALUATION(113, "收到术后仪器评价数据"),
    RESPONSE_COLLECTION_DEVICE_EVALUATION(114, "收到术后仪器评价数据"),

    /**
     * 采集器采集发生异常
     */
    COLLECTION_ERROR_OCCURS(119, "采集器异常"),
    RESPONSE_COLLECTION_ERROR_OCCURS(120, "采集器异常"),
    ;

    private int code;

    private String msg;

    public int getCode() {
        return code;
    }

    CollectorCodeEnum(int code, String msg) {
        this.code = code;
        this.msg = msg;
    }
}
