package client;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


// Cliente mySharingClient
public class mySharingClient {

    private static void printMenu() {
        System.out.println(
                "\nWelcome to mySharing! Here are your options:\n" +
                        "CREATE <ws> <password>\n" +
                        "ADD <user1> <ws>\n" +
                        "UP <ws> <file1> ... <filen>\n" +
                        "DW <ws> <file1> ... <filen>\n" +
                        "RM <ws> <file1> ... <filen>\n" +
                        "LW\n" +
                        "LS <ws>\n" + 
                        "EXIT"
        );
    }

     public static String getUserId(String filename) {
        // Expressão regular para capturar a parte "userid"
        Pattern pattern = Pattern.compile(".+\\.signed\\.(.+)$");
        Matcher matcher = pattern.matcher(filename);

        if (matcher.matches()) {
            // O "userid" está no primeiro grupo de captura
            return matcher.group(1);
        } else {
            return null; // Se não corresponder ao padrão
        }
    }

    private static void createCommand(ObjectOutputStream outStream, ObjectInputStream inStream, String[] arg) throws IOException, ClassNotFoundException {
        if(arg.length != 2){
            System.out.println("Error on arguments, try again");
            return;
        }

        outStream.writeObject("CREATE");
        outStream.writeObject(arg[0]);
        outStream.writeObject(arg[1]);
        String response = (String) inStream.readObject();
        if(response.equals("OK")){
            System.out.println("Workspace created successfully!\n");
        }
        else{
            System.out.println("Error creating workspace!\n");
        }
    }

    private static void addCommand(ObjectOutputStream outStream, ObjectInputStream inStream, String[] arg) throws IOException, ClassNotFoundException {
        if(arg.length != 2){
            System.out.println("Error on arguments, try again");
            return;
        }

        outStream.writeObject("ADD");
        outStream.writeObject(arg[0]);
        outStream.writeObject(arg[1]);
        String response = (String) inStream.readObject();
        if(response.equals("OK")){
            System.out.println("User added successfully!\n");
        }
        else if (response.equals("NOWS")){
            System.out.println("Workspace not found!\n");
        }
        else if (response.equals("NOUSER")){
            System.out.println("User not found!\n");
        }
        else if(response.equals("NOPERM")){
            System.out.println("You don't have permission to add users to this workspace!\n");
        }
    }

    private static void upCommand(ObjectOutputStream outStream, ObjectInputStream inStream, String[] arg, String userID, String password) throws Exception {
        if (arg.length < 2) {
            System.out.println("Error on arguments, try again.");
            return;
        }
    
        String workspace = arg[0];
        String[] files = Arrays.copyOfRange(arg, 1, arg.length);
    
        PrivateKey privateKey = SignatureUtils.loadPrivateKey(userID, password);
    
        outStream.writeObject("UP");
        outStream.writeObject(workspace);
    
        String response = (String) inStream.readObject();
        if (response.equals("NOWS")) {
            System.out.println("NOWS");
            return;
        } else if (response.equals("NOPERM")) {
            System.out.println("NOPERM");
            return;
        }
    
        byte[] wskey = (byte[]) inStream.readObject();
        byte[] decryptedWsKey = SignatureUtils.decryptWithPrivateKey(wskey, privateKey);
        SecretKeySpec key = new SecretKeySpec(decryptedWsKey, "AES");
    
        for (String fileName : files) {
            File file = new File(fileName);
            if (!file.exists() || !file.isFile()) {
                System.out.println(fileName + ": Does not exist");
                continue;
            }
    
            outStream.writeObject("FILE");
            outStream.writeObject(file.getName());
    
            String fileResponse = (String) inStream.readObject();
            if (fileResponse.equals("EXISTS")) {
                System.out.println(fileName + ": Already exists");
                continue;
            } else if (!fileResponse.equals("SEND")) {
                System.out.println(fileName + ": Unexpected server response");
                continue;
            }
    
            byte[] p = Files.readAllBytes(file.toPath());
            Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aes.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedFile = aes.doFinal(p);
    
            outStream.writeObject((long) encryptedFile.length);
            outStream.write(encryptedFile);
            outStream.flush();
    
            response = (String) inStream.readObject();
            if (response.equals("OK")) {
                System.out.println(fileName + ": OK");
            } else {
                System.out.println(fileName + ": Error");
                continue;
            }
    
            byte[] signature = SignatureUtils.signFile(file, privateKey);
            String signatureFileName = fileName + ".signed." + userID;
            File signatureFile = new File(signatureFileName);
            try (FileOutputStream sigOut = new FileOutputStream(signatureFile)) {
                sigOut.write(signature);
            }
    
            outStream.writeObject("SIGNATURE");
            outStream.writeObject(signatureFile.getName());
            outStream.writeObject(signatureFile.length());
    
            try (FileInputStream sigInput = new FileInputStream(signatureFile)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = sigInput.read(buffer)) > 0) {
                    outStream.write(buffer, 0, bytesRead);
                }
            }
            outStream.flush();
    
            response = (String) inStream.readObject();
            if (response.equals("OK")) {
                System.out.println("Signature for " + fileName + ": OK");
            } else {
                System.out.println("Signature for " + fileName + ": Error");
            }
    
            signatureFile.delete();
        }
    
        outStream.writeObject("END");
        outStream.flush();
    }

    private static void lwCommand(ObjectOutputStream outStream, ObjectInputStream inStream, String[] arg) throws IOException, ClassNotFoundException {
        if (arg.length != 0) {
            System.out.println("This command does not need arguments.");
        }

        outStream.writeObject("LW");

        String[] workspaces = (String[]) inStream.readObject();

        System.out.print("{ ");

        for (int i = 0; i < workspaces.length; i++) {
            System.out.print(workspaces[i]);
            if (i < workspaces.length - 1) {
                System.out.print(", ");
            }
        }

        System.out.println(" }");
    }

    private static void lsCommand(ObjectOutputStream outStream, ObjectInputStream inStream, String[] arg) throws IOException, ClassNotFoundException {
        if (arg.length != 1) {
            System.out.println("Error on arguments, try again.");
            return;
        }
    
        String workspace = arg[0];
    
        outStream.writeObject("LS");
        outStream.writeObject(workspace);

        String response = (String) inStream.readObject();
        if (response.equals("NOWS")) {
            System.out.println("This workspace does not exist.");
            return;
        } else if (response.equals("NOPERM")) {
            System.out.println("You do not have permission to access this workspace.");
            return;
        } else if (response.equals("NOFILES")) {
            System.out.println("This workspace has no files.");
            return;
        } 

        String[] files = (String[]) inStream.readObject();

        if (files.length == 0) {
            System.out.println("{ }");
        } else {
            System.out.print("{ ");
            for (int i = 0; i < files.length; i++) {
                System.out.print(files[i]);
                if (i < files.length - 1) {
                    System.out.print(", ");
                }
            }
            System.out.println(" }");
        }
    }

    private static void rmCommand(ObjectOutputStream outStream, ObjectInputStream inStream, String[] arg) throws IOException, ClassNotFoundException {
        if (arg.length < 2) {
            System.out.println("Error on arguments, try again.");
            return;
        }
    
        String workspace = arg[0];
        List<String> files = Arrays.asList(Arrays.copyOfRange(arg, 1, arg.length)); 
    
        outStream.writeObject("RM");
        outStream.writeObject(workspace);
        outStream.writeObject(files);
    
        while (true) {
            String response = (String) inStream.readObject();
            if (response.equals("NOWS")) {
                System.out.println("This workspace does not exist.");
                break;
            } else if (response.equals("NOPERM")) {
                System.out.println("You do not have permission to access this workspace.");
                break;
            } else if (response.equals("DONE")) {
                break;
            } else {
                System.out.println(response);
            }
        }
    }

    private static void dwCommand(ObjectOutputStream out, ObjectInputStream in, String[] args, String userID, String password) throws Exception {
        if (args.length < 2) {
            System.out.println("Error on arguments, try again.");
            return;
        }

        String workspace = args[0];
        List<String> filesToDownload = Arrays.asList(Arrays.copyOfRange(args, 1, args.length));

        out.writeObject("DW");
        out.writeObject(workspace);
        out.writeObject(filesToDownload);

        String response = (String) in.readObject();
        if (response.equals("NOWS")) {
            System.out.println("Workspace does not exist.");
            return;
        } else if (response.equals("NOPERM")) {
            System.out.println("You do not have permission to access this workspace.");
            return;
        } else if (response.equals("NOFILES")) {
            System.out.println("Some or all files not found in workspace.");
            return;
        } 

        File downloadFolder = new File(workspace + "_downloads/");
        if (!downloadFolder.exists()) {
            if (!downloadFolder.mkdir()) {
                System.out.println("Failed to create download folder.");
                return;
            }
        }        
        byte[] wskey = (byte[]) in.readObject();
        PrivateKey privKey = SignatureUtils.loadPrivateKey(userID, password);
        byte[] decryptedKey = SignatureUtils.decryptWithPrivateKey(wskey, privKey);
        SecretKeySpec keySpec = new SecretKeySpec(decryptedKey, "AES");
        
        for (String fileName : filesToDownload) {

                response = (String) in.readObject();
                if (!"File".equals(response)) {
                    continue;
                }
                String receivedFileName = (String) in.readObject();
                long fileSize = (Long) in.readObject();
                byte[] encryptedData = (byte[]) in.readObject();
                
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, keySpec);
                byte[] decryptedData = cipher.doFinal(encryptedData);

                File outputFile = new File(downloadFolder, receivedFileName);
                try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputFile))) {
                    bos.write(decryptedData);
                }

                response = (String) in.readObject();
                if (!"Signed".equals(response)) {
                    continue;
                }
                String receivedSignedFileName = (String) in.readObject();
                long signedFileSize = (Long) in.readObject();
                byte[] signedData = (byte[]) in.readObject();
                File signedOutputFile = new File(downloadFolder, receivedSignedFileName);
                try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(signedOutputFile))) {
                    bos.write(signedData);
                }


                System.out.println("Downloaded: " + receivedFileName);
                System.out.println("Downloaded: " + receivedSignedFileName);


                String signedUser = getUserId(receivedSignedFileName);

                PublicKey publicKey = SignatureUtils.loadClientPublicKey(signedUser);
                Boolean isWellSigned = SignatureUtils.verifySignature(outputFile, signedOutputFile,publicKey);

                if (isWellSigned) {
                    System.out.println("Correctly Signed!");
                } else{
                    System.out.println("Incorrectly Signed! The file was not downloaded.");
                }
                

        }
    }
    

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("Error on arguments, try again");
            return;
        }

        String serverAddress = args[0];
        String userId = args[1];
        String password = args[2];

        Scanner scanner = new Scanner(System.in);

        String host;
        int port = 12345; 

        if (serverAddress.contains(":")) {
            String[] parts = serverAddress.split(":");
            host = parts[0];
            try {
                port = Integer.parseInt(parts[1]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port number. Using default port: " + port);
            }
        } else {
            host = serverAddress;
        }
        File file = new File("certificates/" + userId + "_keystore.jks");
        if (!file.exists()) {
            CertUtils.createCert(userId, password);
            CertUtils.exportCert(userId, password);
            CertUtils.addToTruststore(userId, password);
        }
        System.setProperty("javax.net.ssl.keyStore", "certificates/" + userId + "_keystore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", password);
        System.setProperty("javax.net.ssl.trustStore", "certificates/truststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "trustpass");
        SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();

        // Connect to server
        try (
            SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(host, port);
            ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream())) {

            System.out.println("Connected to server " + host + " on port " + port);

            // Send credentials
            outStream.writeObject(userId);
            outStream.writeObject(password);

            //Response from server
            String response = (String) inStream.readObject();

            Boolean authenticated = false;


            switch (response) {
                case "OK-USER":
                    System.out.println("Authentication sucessful!");
                    authenticated = true;
                    break;
                case "WRONG-PWD":
                    System.out.println("Wrong password, try again");
                    break;
                case "OK-NEW-USER":
                    System.out.println("New user registred successfull!");
                    authenticated = true;
                    break;
                default:
                    System.out.println("Wrong response from server.");
                    break;
            }

            if (!authenticated) {
                return;
            }
            while(true) {
                printMenu();
                String input = scanner.nextLine();
                String[] parts = input.split(" ");
                String command = parts[0];
                command = command.toUpperCase();
                String[] arg = new String[parts.length - 1];

                for (int i = 1; i < parts.length; i++) {
                    arg[i - 1] = parts[i];
                }
                switch (command) {
                    case "CREATE":
                        createCommand(outStream, inStream, arg);
                        break;
                    case "ADD":
                        addCommand(outStream, inStream, arg);
                        break;
                    case "UP":
                        upCommand(outStream, inStream, arg, userId, password);
                        break;
                    case "DW":
                        dwCommand(outStream, inStream, arg, userId, password);
                        break;
                    case "RM":
                        rmCommand(outStream, inStream, arg);
                        break;
                    case "LW":
                        lwCommand(outStream, inStream, arg);
                        break;
                    case "LS":
                        lsCommand(outStream, inStream, arg);
                        break;
                    case "EXIT":
                        System.out.println("Exiting...");
                    default:
                        System.out.println("Unknown command.");
                        break;
                }
            }

        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Erro: " + e.getMessage());
            e.printStackTrace();
        }
    }
}