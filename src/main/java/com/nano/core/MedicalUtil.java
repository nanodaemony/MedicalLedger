package com.nano.core;

import org.bouncycastle.openssl.PEMWriter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringWriter;
import java.security.PrivateKey;

/**
 * Description: Utils
 *
 * @version: 1.0
 * @author: nano
 * @date: 2020/11/24 16:22
 */
public class MedicalUtil {

    public static String getPemStringFromPrivateKey(PrivateKey privateKey) throws IOException {
        StringWriter pemStrWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(pemStrWriter);
        pemWriter.writeObject(privateKey);
        pemWriter.close();
        return pemStrWriter.toString();
    }



    private static void serialize(Object object, String filePath) {
        try {
            ObjectOutputStream oo = new ObjectOutputStream(new FileOutputStream(new File(filePath)));
            oo.writeObject(object);
            System.out.println("Person对象序列化成功！");
            oo.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }



}
