package com.nano.chaincode;

import org.hyperledger.fabric.sdk.ChaincodeID;

import java.util.HashMap;
import java.util.Map;

/**
 * Description: ChainCode Manager
 *
 * @version: 1.0
 * @author: nano
 * @date: 2020/11/24 17:07
 */
public class ChaincodeManager {


    public static Map<String, ChaincodeEntity> chaincodeEntityMap = new HashMap<>();

    private static ChaincodeID chainCodeIdPatient;
    private static ChaincodeID chainCodeIdThirdParty;


    public static ChaincodeEntity chaincodeEntityPatient;
    public static ChaincodeEntity chaincodeEntityThirdParty;


    static {
        chaincodeEntityPatient = new ChaincodeEntity();
        chaincodeEntityPatient.setFilePath("github.com/example_cc");
        chaincodeEntityPatient.setCodeName("example_cc_go");
        chaincodeEntityPatient.setVersion("1");
        chaincodeEntityPatient.setChaincodeId(getChainCodeIdPatient());

        chaincodeEntityThirdParty = new ChaincodeEntity();
        chaincodeEntityThirdParty.setFilePath("github.com/example_cc");
        chaincodeEntityThirdParty.setCodeName("example_cc_go");
        chaincodeEntityThirdParty.setVersion("1");
        chaincodeEntityThirdParty.setChaincodeId(getChainCodeIdThirdParty());
    }


    /**
     * 获取Patient链码ID
     */
    private static ChaincodeID getChainCodeIdPatient() {
        if (chainCodeIdPatient == null) {
            // 这里开始设置链码相关了!
            ChaincodeID.Builder chaincodeIdBuilder = ChaincodeID.newBuilder()
                    // 链码名称: "example_cc_go"
                    .setName("example_cc_go")
                    // 链码版本: 1
                    .setVersion("1");
            // 如果路径不为空则设置路径(GO意外的语言为空)
            chaincodeIdBuilder.setPath("github.com/example_cc");
            // 使用生成器生成链码Id
            chainCodeIdPatient = chaincodeIdBuilder.build();
        }
        return chainCodeIdPatient;
    }

    /**
     * 获取ThirdParty链码ID
     */
    private static ChaincodeID getChainCodeIdThirdParty() {
        if (chaincodeEntityThirdParty == null) {
            // 这里开始设置链码相关了!
            ChaincodeID.Builder chaincodeIdBuilder = ChaincodeID.newBuilder()
                    // 链码名称: "example_cc_go"
                    .setName("example_cc_go")
                    // 链码版本: 1
                    .setVersion("1");
            // 如果路径不为空则设置路径(GO意外的语言为空)
            chaincodeIdBuilder.setPath("github.com/example_cc");
            // 使用生成器生成链码Id
            chainCodeIdThirdParty = chaincodeIdBuilder.build();
        }
        return chainCodeIdThirdParty;
    }

}
