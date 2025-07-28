package client;

public class CertUtils {
    static void createCert(String username, String password) throws Exception {
        String[] command = {
            "keytool",
            "-genkeypair",
            "-alias",
            username,
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-keystore",
            "certificates/" + username + "_keystore.jks",
            "-storepass",
            password,
            "-keypass",
            password,
            "-dname",
            "\"CN=" + username +"\""
        };
         
        Process process = Runtime.getRuntime().exec(command);
        process.waitFor();
    }

    static void exportCert(String username, String password) throws Exception {
        String[] command ={
            "keytool",
            "-exportcert",
            "-alias",
            username,
            "-keystore",
            "certificates/" + username + "_keystore.jks",
            "-file",
            "certificates/" + username + "_cert.cer",
            "-storepass",
            password
        };
           
            
        Process process = Runtime.getRuntime().exec(command);
        process.waitFor();
    }

    static void addToTruststore(String username, String password) throws Exception {
        String[] command = {
            "keytool",
            "-importcert",
            "-alias",
            username,
            "-file",
            "certificates/" + username + "_cert.cer",
            "-keystore",
            "certificates/truststore.jks",
            "-storepass",
            "trustpass",
            "-noprompt"
        };
            
        Process process = Runtime.getRuntime().exec(command);
        process.waitFor();
    }
    
}
