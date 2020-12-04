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
        entity.setPatientPseudonymId("HDJK1780ASBC8912");
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
        entity.setDataSaveUrl("https://blog.csdn.net/bean_business/article/details/108792976");
        entity.setDataMessageDigest("ACD129830123809209ABD2218931C898EF9009FAB789789");
        entity.setDataSignatureDoctor("143534565464563809209ABD2218931C81212398EF9009FAB789789");
        entity.setDataSignaturePatient("BCDA12394364563809209ABD2218931C81212398EF9009FAB789789");
        entity.setPatientPseudonymId("HDJK1780ASBC8912");
        entity.setDoctorPseudonymId("8912098GHSAIOJ879");
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
