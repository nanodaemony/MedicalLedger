package com.nano.core;

/**
 * Description:
 *
 * @version: 1.0
 * @author: nano
 * @date: 2020/11/26 15:28
 */

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * ECC Algorithm Helper.
 *
 * @author nano
 * @see: https://blog.csdn.net/sunhuaqiang1/article/details/103258223
 */
public class EccHelper {
    private static final Logger logger = LoggerFactory.getLogger(EccHelper.class);
    private static final int SIZE = 4096;
    private BCECPublicKey publicKey;
    private BCECPrivateKey privateKey;

    private static KeyFactory keyFactory;

    static {
        Security.addProvider(new BouncyCastleProvider());
        try {
            keyFactory = KeyFactory.getInstance("EC", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    public EccHelper(String publicKey, String privateKey) {
        this(Base64Util.decodeBite(publicKey), Base64Util.decodeBite(privateKey));
    }

    /**
     * Constructor
     *
     * @param publicKey  公钥
     * @param privateKey 私钥
     */
    public EccHelper(byte[] publicKey, byte[] privateKey) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            if (publicKey != null && publicKey.length > 0) {
                this.publicKey = (BCECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKey));
            }
            if (privateKey != null && privateKey.length > 0) {
                this.privateKey = (BCECPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
            }
        } catch (ClassCastException e) {
            throw new RuntimeException("", e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public EccHelper(String publicKey) {
        this(Base64Util.decodeBite(publicKey));
    }

    public EccHelper(byte[] publicKey) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            if (publicKey != null && publicKey.length > 0) {
                this.publicKey = (BCECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKey));
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] encrypt(byte[] plainText) {
        if (publicKey == null) {
            throw new RuntimeException("public key is null.");
        }
        try {
            Cipher cipher = Cipher.getInstance("ECIES", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            int size = SIZE;
            ByteArrayOutputStream baos = new ByteArrayOutputStream((plainText.length + size - 1) / size * (size + 45));
            int left = 0;
            for (int i = 0; i < plainText.length; ) {
                left = plainText.length - i;
                if (left > size) {
                    cipher.update(plainText, i, size);
                    i += size;
                } else {
                    cipher.update(plainText, i, left);
                    i += left;
                }
                baos.write(cipher.doFinal());
            }
            return baos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public static byte[] encrypt(byte[] plainText, byte[] publicKeyBytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            Cipher cipher = Cipher.getInstance("ECIES", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, (BCECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes)));
            int size = SIZE;
            ByteArrayOutputStream baos = new ByteArrayOutputStream((plainText.length + size - 1) / size * (size + 45));
            int left = 0;
            for (int i = 0; i < plainText.length; ) {
                left = plainText.length - i;
                if (left > size) {
                    cipher.update(plainText, i, size);
                    i += size;
                } else {
                    cipher.update(plainText, i, left);
                    i += left;
                }
                baos.write(cipher.doFinal());
            }
            return baos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public byte[] decrypt(byte[] secretText) {
        if (privateKey == null) {
            throw new RuntimeException("private key is null.");
        }
        try {
            Cipher cipher = Cipher.getInstance("ECIES", "BC");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            int size = SIZE + 45;
            ByteArrayOutputStream baos = new ByteArrayOutputStream((secretText.length + size + 44) / (size + 45) * size);
            int left = 0;
            for (int i = 0; i < secretText.length; ) {
                left = secretText.length - i;
                if (left > size) {
                    cipher.update(secretText, i, size);
                    i += size;
                } else {
                    cipher.update(secretText, i, left);
                    i += left;
                }
                baos.write(cipher.doFinal());
            }
            return baos.toByteArray();
        } catch (Exception e) {
            logger.error("ecc decrypt failed.", e);
        }
        return null;
    }


    public static byte[] decrypt(byte[] secretText, byte[] privateKeyByte) {
        try {
            Cipher cipher = Cipher.getInstance("ECIES", "BC");
            cipher.init(Cipher.DECRYPT_MODE, (BCECPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyByte)));
            int size = SIZE + 45;
            ByteArrayOutputStream baos = new ByteArrayOutputStream((secretText.length + size + 44) / (size + 45) * size);
            int left = 0;
            for (int i = 0; i < secretText.length; ) {
                left = secretText.length - i;
                if (left > size) {
                    cipher.update(secretText, i, size);
                    i += size;
                } else {
                    cipher.update(secretText, i, left);
                    i += left;
                }
                baos.write(cipher.doFinal());
            }
            return baos.toByteArray();
        } catch (Exception e) {
            logger.error("ecc decrypt failed.", e);
        }
        return null;
    }

    public byte[] sign(byte[] content) {
        if (privateKey == null) {
            throw new RuntimeException("private key is null.");
        }
        try {
            Signature signature = Signature.getInstance("SHA384withECDSA", "BC");
            signature.initSign(privateKey);
            signature.update(content);
            return signature.sign();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean verifySignature(byte[] sign, byte[] content) {
        if (publicKey == null) {
            throw new RuntimeException("public key is null.");
        }
        try {
            Signature signature = Signature.getInstance("SHA384withECDSA", "BC");
            signature.initVerify(publicKey);
            signature.update(content);
            return signature.verify(sign);
        } catch (Exception e) {
            logger.error("ecc verify failed.", e);
        }
        return false;
    }
}

