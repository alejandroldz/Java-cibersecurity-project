package server;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import  java.util.Base64;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

public class MACUtils {
    private static final String ALGORITHM = "HmacSHA256";

    public static String calculateMAC(String filePath, String secretKey) throws Exception {
        byte[] keyBytes = secretKey.getBytes();
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM); 
        Mac mac = Mac.getInstance(ALGORITHM);
        mac.init(keySpec);
        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
        byte[] macBytes = mac.doFinal(fileBytes);
        return Base64.getEncoder().encodeToString(macBytes);
    }

    public static boolean verifyMAC(String filePath, String secretKey, String macPath) throws Exception {
        File macFile = new File(macPath);
        File file = new File(filePath);
        if(macFile.exists()) {
            String fileMAC = new String(Files.readAllBytes(Paths.get(macPath)));
            String calculatedMAC = calculateMAC(filePath, secretKey);
            return fileMAC.equals(calculatedMAC);
        }
        else {
            System.out.println("MAC file does not exist for file: " + filePath + ". Do you want to create it? (y/n)");
            String response = new java.util.Scanner(System.in).nextLine();
            if(response.equals("y")) {
                createMAC(filePath, secretKey);
                return true;
            }
            else {
                return false;
            }
        }
    }

    public static void createMAC(String filePath, String secretKey) throws Exception {
        String calculatedMAC = calculateMAC(filePath, secretKey);
        Files.write(Paths.get(filePath + ".mac"), calculatedMAC.getBytes());
    }

}
