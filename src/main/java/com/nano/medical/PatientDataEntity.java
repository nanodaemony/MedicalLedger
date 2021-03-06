package com.nano.medical;

import com.alibaba.fastjson.JSON;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import lombok.Data;

/**
 * Description: Patient数据实体
 *
 * @version: 1.0
 * @author: nano
 * @date: 2020/12/3 9:56
 */
@Data
public class PatientDataEntity implements Serializable {

    private String treatmentId;

    private String dataSaveUrl;

    private String dataMessageDigest;

    private String dataSignatureDoctor;

    private String dataSignaturePatient;

    private String patientPseudonymId;

    private String doctorPseudonymId;

    private Long timestamp;


    @Override
    public String toString() {
        return "PatientDataEntity{" +
                "treatmentId='" + treatmentId + '\'' +
                ", dataSaveUrl='" + dataSaveUrl + '\'' +
                ", dataMessageDigest='" + dataMessageDigest + '\'' +
                ", dataSignatureDoctor='" + dataSignatureDoctor + '\'' +
                ", dataSignaturePatient='" + dataSignaturePatient + '\'' +
                ", patientPseudonymId='" + patientPseudonymId + '\'' +
                ", doctorPseudonymId='" + doctorPseudonymId + '\'' +
                ", timestamp=" + timestamp +
                '}';
    }


    public static PatientDataEntity getInstance() {
        PatientDataEntity entity = new PatientDataEntity();
        entity.setTreatmentId("13A21378B" + System.currentTimeMillis());
        entity.setDataSaveUrl("https://blog.csdn.net/bean_business/article/details/108792976");
        entity.setDataMessageDigest("ACD129830123809209ABD2218931C898EF9009FAB789789");
        entity.setDataSignatureDoctor(System.currentTimeMillis() + "143534565464563809209ABD2218931C81212398EF9009FAB789789" + System.currentTimeMillis());
        entity.setDataSignaturePatient(System.currentTimeMillis() + "BCDA12394364563809209ABD2218931C81212398EF9009FAB789789" + System.currentTimeMillis());
        entity.setPatientPseudonymId("HDJK1780" + System.currentTimeMillis());
        entity.setDoctorPseudonymId("8912098GHSAIOJ879");
        entity.setTimestamp(System.currentTimeMillis());
        return entity;
    }


    /**
     * Test
     */
    public static void main(String[] args) {
        PatientDataEntity entity = new PatientDataEntity();
        entity.setTreatmentId("13A21378B");
        entity.setDataSaveUrl("https://nano-mall.oss-cn-shenzhen.aliyuncs.com/13A21378B.txt?Expires=1607156324&OSSAccessKeyId=TMP.3KfeDvLHey4S1QWoHDebJyFWaxPkcn3H4vm74cjN2BsnN6y92GAnJ28Rn47i6eHx2RSLwDD4eSeVnBVKearHvY7WoygxPp&Signature=BMLoNvgewwH02YV9LpP7r2b%2B8Vs%3D");
        entity.setDataMessageDigest("AF1ACD6AFCA06AB0D2790048FFB90AD9593FB8C2");
        entity.setDataSignatureDoctor("304502206E9D083FD8B9B0F2D01B898F2B4332E0A2C7D0657B3C07D041FFB375C9512638022100EDBA5855606ED236EF1ADA3122A5AA3A824698D5EAA860DC19D8E126E79F797F");
        entity.setDataSignaturePatient("18F920DC10283DAF392EC29EE9301293F29102AEF920F0102CD01D1030194857AEF1274723D5AE57A7E782889102102392BCBB1286128DBCA8128392B38D8129B129812A1288DC");
        entity.setPatientPseudonymId("HDJK1780ASBC8912");
        entity.setDoctorPseudonymId("8912098GHSAIOJ87");
        entity.setTimestamp(System.currentTimeMillis());

        PatientDataEntity entity1 = new PatientDataEntity();
        entity1.setTreatmentId("123890123");
        entity1.setDataSaveUrl("https://blog.csdn.net/bean_business/article/details/108792976");
        entity1.setDataMessageDigest("ACD129830123809209ABD2218931C898EF9009FAB789789");
        entity1.setDataSignatureDoctor("143534565464563809209ABD2218931C81212398EF9009FAB789789");
        entity1.setDataSignaturePatient("BCDA12394364563809209ABD2218931C81212398EF9009FAB789789");
        entity1.setPatientPseudonymId("HDJK1780ASBC8912");
        entity1.setDoctorPseudonymId("8912098GHSAIOJ879");
        entity1.setTimestamp(System.currentTimeMillis());

        List<PatientDataEntity> list = new ArrayList<>();
        list.add(entity);
        list.add(entity1);
        String data = JSON.toJSONString(entity);
        String data2 = JSON.toJSONString(list);

        System.out.println(data);
        System.out.println(data2);


    }

}
