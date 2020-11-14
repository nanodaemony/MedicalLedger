package com.nano.common.enums;

/**
 * CRUD类型枚举
 * @author nano
 */
public enum CrudTypeEnum {

    /**
     * NON
     */
    NON(0, "NON"),

    /**
     * SELECT
     */
    SELECT(1, "SELECT"),

    /**
     * SAVE
     */
    SAVE(2, "SAVE"),

    /**
     * UPDATE
     */
    UPDATE(3, "UPDATE"),

    /**
     * DELETE
     */
    DELETE(4, "DELETE");

    private Integer code;
    private String msg;

    CrudTypeEnum(Integer code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public Integer getCode() {
        return code;
    }

    public String getMsg() {
        return msg;
    }

}
