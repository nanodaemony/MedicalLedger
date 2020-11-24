package com.nano.core;

import org.bouncycastle.openssl.PEMWriter;

import java.io.IOException;
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

    static String getPEMStringFromPrivateKey(PrivateKey privateKey) throws IOException {
        StringWriter pemStrWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(pemStrWriter);
        pemWriter.writeObject(privateKey);
        pemWriter.close();
        return pemStrWriter.toString();
    }

}
