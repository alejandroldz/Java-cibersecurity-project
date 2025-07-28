package client;

import java.io.*;
import java.nio.file.Files;
import java.security.cert.Certificate;

import javax.crypto.Cipher;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class SignatureUtils {

    public static byte[] signFile(File file, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);

        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                signature.update(buffer, 0, bytesRead);
            }
        }

        return signature.sign();
    }

    public static PrivateKey loadPrivateKey(String userId, String password) throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream("certificates/" + userId + "_keystore.jks");
        keystore.load(fis, password.toCharArray());

        return (PrivateKey) keystore.getKey(userId, password.toCharArray());
    }


    public static boolean verifySignature(File originalFile, File signatureFile, PublicKey publicKey) throws Exception {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initVerify(publicKey);

    try (FileInputStream fis = new FileInputStream(originalFile)) {
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            signature.update(buffer, 0, bytesRead);
        }
    }

    byte[] signatureBytes = Files.readAllBytes(signatureFile.toPath());
    return signature.verify(signatureBytes);
    }


    public static PublicKey loadClientPublicKey(String clientId) throws Exception {
        KeyStore truststore = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream("certificates/truststore.jks");
        truststore.load(fis, "trustpass".toCharArray());
    
        Certificate cert = truststore.getCertificate(clientId);
        return cert.getPublicKey();
    }
    public static byte[] decryptWithPrivateKey(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        
        return cipher.doFinal(encryptedData);
    }

}