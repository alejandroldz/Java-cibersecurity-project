package server;

/* 
import org.json.*;
*/
import java.io.*;
import java.nio.file.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

import javax.crypto.SecretKey;



public class WorkspaceHandler {
	private static final String WS_FOLDER = "server/ws_folders/";
    private static final String FILE_PATH = "server/workspaces.txt";
    //private static List<JSONObject> workspaces = new ArrayList<>();
    private static List<String> workspaces = new ArrayList<>();
    

    static {
        loadWorkspaces();
    }

    private static void loadWorkspaces() {
       /* try {
            File file = new File(FILE_PATH);
            if (file.exists()) {
                String content = new String(Files.readAllBytes(Paths.get(FILE_PATH)));
                JSONArray jsonArray = new JSONArray(content);
                workspaces.clear();
                for (int i = 0; i < jsonArray.length(); i++) {
                    workspaces.add(jsonArray.getJSONObject(i));
                }
            }
        } catch (IOException | JSONException e) {
            System.err.println("Error loading workspaces: " + e.getMessage());
        }*/

        File file = new File(FILE_PATH);
        if (!file.exists()) {
            return;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                workspaces.add(line); // Add each line directly to the list
            }
        } catch (IOException e) {
            System.err.println("Error loading workspaces: " + e.getMessage());
        }
    }


    private static void saveWorkspaces() {
        /*try (FileWriter file = new FileWriter(FILE_PATH)) {
            JSONArray jsonArray = new JSONArray(workspaces);
            file.write(jsonArray.toString(2));
        } catch (IOException e) {
            System.err.println("Error saving workspaces: " + e.getMessage());
        }*/
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(FILE_PATH))) {
            for (String workspace : workspaces) {
                writer.write(workspace);
                writer.newLine(); // Ensures each workspace is on a new line
            }
        } catch (IOException e) {
            System.err.println("Error saving workspaces: " + e.getMessage());
        }
    }

    public static String createWorkspace(String owner, String password) {
        return createWorkspace(owner,generateNextId(),"placeholder");
    }
    //two createWorkspace functions, one with automatic newId, and the other with a chosen name.
    public static String createWorkspace(String owner, String newId, String password) {
    if (getWorkspace(newId) == null) {
        try {
            File wsDir = new File(WS_FOLDER + newId);
            wsDir.mkdirs();

            String saltString = PasswordUtils.generateSalt();
            byte[] salt = Base64.getDecoder().decode(saltString);


            SecretKey workspaceKey = EncryptUtils.deriveKeyFromPassword(password.toCharArray(), salt);

            PublicKey ownerPublicKey = EncryptUtils.loadClientPublicKey(owner);
            byte[] encryptedKey = EncryptUtils.encryptWithPublicKey(workspaceKey.getEncoded(), ownerPublicKey);

            FileOutputStream keyFile = new FileOutputStream(WS_FOLDER + newId + "/" + newId + ".key." + owner);
            keyFile.write(encryptedKey);
            keyFile.close();

            String workspaceEntry = newId + " | " + owner + " | " +  " " + " | " + " ";
            workspaces.add(workspaceEntry);
            saveWorkspaces();

            return newId;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    return null; // Retornar null se o workspace já existir
}

    

    private static String generateNextId() {
        
        Set<Integer> existingIds = new HashSet<>();

        for (String workspace : workspaces) {
            String[] parts = workspace.split(" \\| "); // Split by " | "
            if (parts.length > 0 && parts[0].matches("\\d+")) {
                existingIds.add(Integer.parseInt(parts[0]));
            }
        }

        int nextId = 1;
        while (existingIds.contains(nextId)) {
            nextId++;
        }

        return String.format("%03d", nextId); // Ensures the ID is always 3 digits (e.g., "001", "002", "003")
    }

    public static boolean addToWorkspace(String id, String user, String pass) throws Exception {
        for (int i = 0; i < workspaces.size(); i++) {
            String workspace = workspaces.get(i);
            String[] parts = workspace.split(" \\| "); // Split by " | "
    
    
            // Check if the ID matches
            if (parts[0].equals(id)) {

                String owner = parts[1];


                byte[] encryptedKey = Files.readAllBytes(Path.of(WS_FOLDER + id + "/" + id + ".key." + owner));
                PrivateKey ownerPrivateKey = EncryptUtils.loadPrivateKey(owner, pass); 


                byte[] desencryptedKey = EncryptUtils.decryptWithPrivateKey(encryptedKey, ownerPrivateKey);

                PublicKey pk = EncryptUtils.loadClientPublicKey(user);

                byte[] newEncryptedKey = EncryptUtils.encryptWithPublicKey(desencryptedKey, pk);
                FileOutputStream keyFile = new FileOutputStream(WS_FOLDER + id + "/" + id + ".key." + user);
                keyFile.write(newEncryptedKey);
                keyFile.close();




                // Extract existing allowed users (split by commas, if any)
                String[] allowedUsers = parts[3].equals(" ") ? new String[0] : parts[3].split(",");
    
                // Add the new user to the allowed list
                Set<String> allowedSet = new HashSet<>(Arrays.asList(allowedUsers));
                allowedSet.add(user);
    
                // Rebuild the workspace string with the updated allowed users
                String updatedWorkspace = parts[0] + " | " + parts[1] + " | " + parts[2] + " | " + String.join(",", allowedSet);
    
                // Update the workspaces list
                workspaces.set(i, updatedWorkspace);
                saveWorkspaces();
                return true; // Successfully added the user
            }
        }
        return false; // ID not found
    }

    public static boolean addFilePath(String id, String filePath) {
        /*for (JSONObject ws : workspaces) {
            if (ws.getString("id").equals(id)) {
                ws.getJSONArray("filepaths").put(filePath);
                saveWorkspaces();
                return true;
            }
        }
        return false;*/
        for (int i = 0; i < workspaces.size(); i++) {
            String workspace = workspaces.get(i);
            String[] parts = workspace.split(" \\| "); // Split by " | "
    
    
            // Check if the ID matches
            if (parts[0].equals(id)) {
                // Extract existing file paths (split by commas, if any)
                String[] filePaths = parts[2].equals(" ") ? new String[0] : parts[2].split(",");
    
                // Add the new file path to the set (to avoid duplicates)
                Set<String> filePathSet = new HashSet<>(Arrays.asList(filePaths));
                filePathSet.add(filePath);
    
                // Rebuild the workspace string with the updated file paths
                String updatedWorkspace = parts[0] + " | " + parts[1] + " | " + String.join(",", filePathSet) + " | " + parts[3];
    
                // Update the workspaces list
                workspaces.set(i, updatedWorkspace);
                saveWorkspaces();
                return true; // Successfully added the file path
            }
        }
        return false; // ID not found
    }

    public static List<String> listFiles(String id) {
       /*  for (JSONObject ws : workspaces) {
            if (ws.getString("id").equals(id)) {
                JSONArray filepaths = ws.getJSONArray("filepaths");
                List<String> files = new ArrayList<>();
                for (int i = 0; i < filepaths.length(); i++) {
                    files.add(filepaths.getString(i));
                }
                return files;
            }
        }
        return Collections.emptyList();*/

        

        for (String workspace : workspaces) {
            String[] parts = workspace.split(" \\| "); // Split by " | "
    
            if (parts[0].equals(id)) {
                // Extract file paths (third part of the string)
                String[] filePaths = parts[2].equals("") ? new String[0] : parts[2].split(",");
                return new ArrayList<>(Arrays.asList(filePaths));
            }
        }
        return Collections.emptyList(); // Return empty list if workspace not found
    }

    public static void printWorkspaces() {
        /*for (JSONObject ws : workspaces) {
            System.out.println(ws.toString(2));
        }*/
        for (String workspace : workspaces) {
            String[] parts = workspace.split(" \\| "); // Split by " | "
    
                // Format the output to print in a structured way
                System.out.println("ID: " + parts[0]);
                System.out.println("Owner: " + parts[1]);
                System.out.println("Filepaths: " + parts[2]);
                System.out.println("Allowed Users: " + parts[3]);
                System.out.println("---------------"); // Separator between workspaces
            }
        }
    
    
    /*public static JSONObject getWorkspace(String id) {
        for (JSONObject ws : workspaces) {
            if (ws.getString("id").equals(id)) {
                return ws;
            }
        }
        return null;
    }*/
    public static String getWorkspace(String id) {
        for (String workspace : workspaces) {
            String[] parts = workspace.split(" \\| "); // Split by " | "
    
            if (parts[0].equals(id)) {
                // Return the whole workspace string if found
                return workspace;
            }
        }
        return null; // Return null if workspace with the given id is not found
    }
    
    public static Boolean isOwner (String id, String user) {
        /*for (JSONObject ws : workspaces) {
            if (ws.getString("id").equals(id) && ws.getString("owner").equals(user)) {
                return true;
            }
        }
        return false;*/
        for (String workspace : workspaces) {
            String[] parts = workspace.split(" \\| "); // Split by " | "
    
            if (parts[0].equals(id) && parts[1].equals(user)) {
                return true;
            }
        }
        return false; // Return false if workspace with the given id and user as owner is not found
    }

    public static Boolean isAllowed(String id, String user) {
        /*for (JSONObject ws : workspaces) {
            if (ws.getString("id").equals(id)) {
                if (ws.getString("owner").equals(user)) { 
                    return true;
                }
                JSONArray allowedUsers = ws.getJSONArray("allowed");
                for (int i = 0; i < allowedUsers.length(); i++) {
                    if (allowedUsers.getString(i).equals(user)) {
                        return true;
                    }
                }
            }
        }
        return false;*/
        for (String workspace : workspaces) {
            String[] parts = workspace.split(" \\| "); // Split by " | "
    
    
            if (parts[0].equals(id)) {
                // Check if the user is the owner
                if (parts[1].equals(user)) { 
                    return true;
                }
    
                // Check if the user is in the allowed users list
                String[] allowedUsers = parts[3].equals(" ") ? new String[0] : parts[3].split(",");
                for (String allowedUser : allowedUsers) {
                    if (allowedUser.equals(user)) {
                        return true;
                    }
                }
            }
        }
        return false; // Return false if not allowed
    }

    public static String[] getUserWorkspaces(String user) {
       /*  List<String> userWorkspaces = new ArrayList<>();
    
        for (JSONObject ws : workspaces) {
            if (ws.getString("owner").equals(user) || ws.getJSONArray("allowed").toList().contains(user)) {
                userWorkspaces.add(ws.getString("id"));
            }
        }
    
        return userWorkspaces.toArray(new String[0]);*/
        List<String> userWorkspaces = new ArrayList<>();
       

        for (String workspace : workspaces) {
            String[] parts = workspace.split(" \\| "); // Split by " | "

          
                // Check if the user is the owner or is in the allowed list
                if (parts[1].equals(user) || Arrays.asList(parts[3].split(",")).contains(user)) {
                    userWorkspaces.add(parts[0]); // Add workspace ID to the list
                }
        }

        return userWorkspaces.toArray(new String[0]);
    }

        
    public static void removeFile(String id, String filePath) {
        /*for (JSONObject ws : workspaces) {
            if (ws.getString("id").equals(id)) {
                JSONArray filepaths = ws.getJSONArray("filepaths");
                for (int i = 0; i < filepaths.length(); i++) {
                    if (filepaths.getString(i).equals(filePath)) {
                        filepaths.remove(i);
                        saveWorkspaces();
                        return;
                    }
                }
            }
        }*/

        for (int i = 0; i < workspaces.size(); i++) {
            String workspace = workspaces.get(i);
            String[] parts = workspace.split(" \\| "); // Split by " | "
    
            if (parts[0].equals(id)) {
                // Extract the file paths (third part of the string)
                String[] files = parts[2].split(",");
    
                // Create a list of files and attempt to remove the file
                List<String> updatedFiles = new ArrayList<>(Arrays.asList(files));
                if (updatedFiles.remove(filePath)) {
                    // Join the updated list of files back into a string
                    String updatedFilePaths = String.join(",", updatedFiles);
    
                    // Rebuild the workspace string with the updated file paths
                    String updatedWorkspace = parts[0] + " | " + parts[1] + " | " + updatedFilePaths + " | " + parts[3];
    
                    // Update the workspace in the list
                    workspaces.set(i, updatedWorkspace);
    
                    // Save the updated workspaces
                    saveWorkspaces();
                    return; // Successfully removed the file, exit the function
                }
            }
        }
    }

}
