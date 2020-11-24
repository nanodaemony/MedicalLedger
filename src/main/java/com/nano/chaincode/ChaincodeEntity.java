package com.nano.chaincode;

import org.hyperledger.fabric.sdk.ChaincodeID;
import org.hyperledger.fabric.sdk.TransactionRequest;

import lombok.Data;

/**
 * Description: Chaincode
 *
 * @version: 1.0
 * @author: nano
 * @date: 2020/11/24 17:03
 */
@Data
public class ChaincodeEntity {

    private String filePath;

    private String codeName;

    private String codePath;

    private String version;

    private TransactionRequest.Type language;

    private ChaincodeID chaincodeId;


    public ChaincodeEntity(String chainCodeFilePath, String chainCodeName, String codePath, String version, TransactionRequest.Type language) {
        this.filePath = chainCodeFilePath;
        this.codeName = chainCodeName;
        this.codePath = codePath;
        this.version = version;
        this.language = language;
    }


    public ChaincodeEntity() {
    }
}
