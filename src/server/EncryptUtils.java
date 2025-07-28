package server;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.KeySpec;

public class EncryptUtils {

    public static SecretKey deriveKeyFromPassword(char[] password, byte[] salt) throws Exception {
        int iterationCount = 65536;
        int keyLength = 128;

        KeySpec spec = new PBEKeySpec(password, salt, iterationCount, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();

        return new SecretKeySpec(keyBytes, "AES");
    }

    public static byte[] encryptWithPublicKey(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decryptWithPrivateKey(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        
        return cipher.doFinal(encryptedData);
    }

    public static PublicKey loadClientPublicKey(String clientId) throws Exception {
        KeyStore truststore = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream("certificates/truststore.jks");
        truststore.load(fis, "trustpass".toCharArray());
    
        Certificate cert = truststore.getCertificate(clientId);
        return cert.getPublicKey();
    }


    public static PrivateKey loadPrivateKey(String userId, String password) throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream("certificates/" + userId + "_keystore.jks");
        keystore.load(fis, password.toCharArray());

        return (PrivateKey) keystore.getKey(userId, password.toCharArray());
    }

}
