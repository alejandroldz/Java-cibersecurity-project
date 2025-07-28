package server;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Pattern;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

/* 
import org.json.JSONArray;
import org.json.JSONObject;
*/


public class mySharingServer{

	private static final String USERS_FILE = "server/users.txt";	
	private static final String WS_FOLDER = "server/ws_folders/";
	private static final String FILE_PATH = "server/workspaces.txt";
	private Map<String, String[]> userDatabase;
	private static String serverKey;
	private static final String SERVER_SALT= "Project2Security";

	public static void main(String[] args) throws Exception {
		int port = 12345;
		if (args.length > 0) {
			try {
				port = Integer.parseInt(args[0]);
			} catch (NumberFormatException e) {
				System.err.println("Invalid port. Using default port: " + port);
			}
		}

		System.out.println("Server initiated on port: " + port);
		Scanner	scanner = new Scanner(System.in);
		System.out.print("Password: ");
		String password = scanner.nextLine();
		serverKey = PasswordUtils.hashPassword(password, SERVER_SALT);
	
		if(!MACUtils.verifyMAC(USERS_FILE, serverKey, "server/users.txt.mac")) {
			System.err.println("Error verifying MAC for users.txt");
			System.exit(1);
		}
		if(!MACUtils.verifyMAC(FILE_PATH, serverKey, "server/workspaces.txt.mac")) {
			System.err.println("Error verifying MAC for workspaces.txt");
			System.exit(1);
		}
		System.out.println("MACs verified successfully");
		mySharingServer server = new mySharingServer();
		server.startServer(port);
	}

	public mySharingServer() throws IOException{
		userDatabase = loadUsers();
	}


	public void startServer (int port) throws IOException{

		System.setProperty("javax.net.ssl.keyStore", "certificates/server_keystore.jks");
		System.setProperty("javax.net.ssl.keyStorePassword", "serverpass");
		System.setProperty("javax.net.ssl.trustStore", "certificates/truststore.jks");
		System.setProperty("javax.net.ssl.trustStorePassword", "trustpass");

		SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port);

		while(true) {
			try {
				Socket inSoc = (SSLSocket) sslServerSocket.accept();
				ServerThread newServerThread = new ServerThread(inSoc);
				newServerThread.start();
			}
			catch (IOException e) {
				e.printStackTrace();
			}

		}
		//sSoc.close();
	}


class ServerThread extends Thread {

	private Socket socket = null;

	ServerThread(Socket inSoc) {
		socket = inSoc;
		System.out.println("New connection received");
	}

	public void run() {
		ObjectOutputStream outStream = null;
		ObjectInputStream inStream = null;

		try {
			outStream = new ObjectOutputStream(socket.getOutputStream());
			inStream = new ObjectInputStream(socket.getInputStream());

			String user = null;
			String passwd = null;

			try {
				user = (String) inStream.readObject();
				passwd = (String) inStream.readObject();
				System.out.println("User and pass received");
			} catch (ClassNotFoundException e1) {
				e1.printStackTrace();
			}

			// Authentication
			String authResponse = authenticateUser(user, passwd);
			outStream.writeObject(authResponse);

			if (authResponse.equals("OK-USER") || authResponse.equals("OK-NEW-USER")) {
				while (true) {
					String command = null;
					try {
						command = (String) inStream.readObject();
						System.out.println("Command received: " + command);

						if (command.equals("EXIT")) {
							System.out.println("Client requested exit.");
							break;
						}

						switch (command) {
							case "CREATE":
								createCommand(outStream, inStream, user);
								break;
							case "ADD":
								addCommand(outStream, inStream, user, passwd);
								break;
							case "UP":
								upCommand(outStream, inStream, user, passwd);
								break;
							case "DW":
								dwCommand(outStream, inStream, user);
								break;
							case "RM":
								rmCommand(outStream, inStream, user);
								break;
							case "LW":
								lwCommand(outStream, inStream, user);
								break;
							case "LS":
								lsCommand(outStream, inStream, user);
								break;
							default:
								System.out.println("Unknown command.");
								break;
						}
					} catch (EOFException | SocketException e) {
						System.out.println("Client disconnected.");
						break;
					} catch (Exception e) {
						System.out.println("Error processing command: " + e.getMessage());
						e.printStackTrace();
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (inStream != null) inStream.close();
				if (outStream != null) outStream.close();
				if (socket != null && !socket.isClosed()) socket.close();
				System.out.println("Connection closed.");
			} catch (IOException e) {
				System.out.println("Error closing resources: " + e.getMessage());
			}
		}
	}
}

	private synchronized Map<String, String[]> loadUsers() throws IOException {
		Map<String, String[]> users = new HashMap<>();
		File file = new File(USERS_FILE);
	
		if (!file.exists()) return users;
	
		try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
			String line;
			while ((line = reader.readLine()) != null) {
				String[] parts = line.split(":");
				if (parts.length == 3) {
					users.put(parts[0], new String[] {parts[1], parts[2]}); // username -> [hash, salt]
				}
			}
		}
		return users;
	}

	private synchronized String authenticateUser(String user, String passwd) throws Exception {
		if (userDatabase.containsKey(user)) {
			String[] stored = userDatabase.get(user);
			String storedHash = stored[0];
			String salt = stored[1];
	
			String hash = PasswordUtils.hashPassword(passwd, salt);
	
			if (storedHash.equals(hash)) {
				return "OK-USER";
			} else {
				return "WRONG-PWD";
			}
		} else {
			String salt = PasswordUtils.generateSalt();
			String hash = PasswordUtils.hashPassword(passwd, salt);
			userDatabase.put(user, new String[]{hash, salt});
			WorkspaceHandler.createWorkspace(user, passwd);
			saveUsers();
			MACUtils.createMAC(USERS_FILE, serverKey);
			MACUtils.createMAC(FILE_PATH, serverKey);
			return "OK-NEW-USER";
		}
	}

	private synchronized void saveUsers() {
		try (BufferedWriter writer = new BufferedWriter(new FileWriter(USERS_FILE))) {
			for (Map.Entry<String, String[]> entry : userDatabase.entrySet()) {
				writer.write(entry.getKey() + ":" + entry.getValue()[0] + ":" + entry.getValue()[1]);
				writer.newLine();
			}
		} catch (IOException e) {
			System.err.println("Error saving users: " + e.getMessage());
		}
	}

	private synchronized void createCommand(ObjectOutputStream outStream, ObjectInputStream inStream, String user) throws Exception{
		String ws = (String)inStream.readObject();
		String password = (String)inStream.readObject();
		System.out.println("Workspace received: " + ws);
		String response = WorkspaceHandler.createWorkspace(user, ws, password);
		if (response != null) {
			outStream.writeObject("OK");
			MACUtils.createMAC(FILE_PATH, serverKey);
		} else {
			outStream.writeObject("NOK");
		}

	}

	private synchronized void addCommand(ObjectOutputStream outStream, ObjectInputStream inStream, String user, String pass) throws Exception{
		String userToAdd = (String)inStream.readObject();
		String ws = (String)inStream.readObject();

		if(userDatabase.containsKey(userToAdd)){
			if(WorkspaceHandler.getWorkspace(ws) != null){
				if(WorkspaceHandler.isOwner(ws, user)){
					WorkspaceHandler.addToWorkspace(ws, userToAdd, pass);
					outStream.writeObject("OK");
					MACUtils.createMAC(FILE_PATH, serverKey);
				}
				else{
					outStream.writeObject("NOPERM");
				}
			}
			else{
				outStream.writeObject("NOWS");
			}
		}
		else{
			outStream.writeObject("NOUSER");
		}
	}

	private synchronized void upCommand(ObjectOutputStream outStream, ObjectInputStream inStream, String user, String pass) throws Exception {
		String workspace = (String) inStream.readObject();
	
		if (WorkspaceHandler.getWorkspace(workspace) == null) {
			outStream.writeObject("NOWS");
			return;
		}
		if (!WorkspaceHandler.isAllowed(workspace, user)) {
			outStream.writeObject("NOPERM");
			return;
		}
	
		File workspaceDir = new File(WS_FOLDER + workspace);
		if (!workspaceDir.exists()) {
			workspaceDir.mkdirs();
		}
		outStream.writeObject("OK");
	
		String keyFile = WS_FOLDER + workspace + File.separator + workspace + ".key." + user;
		byte[] wskey = Files.readAllBytes(Paths.get(keyFile));
		outStream.writeObject(wskey);
	
		while (true) {
			String fileCommand = (String) inStream.readObject();
	
			if ("END".equals(fileCommand)) {
				System.out.println("All files received for workspace: " + workspace);
				break;
			}
	
			if ("FILE".equals(fileCommand)) {
				String fileName = (String) inStream.readObject();
				if (WorkspaceHandler.listFiles(workspace).contains(fileName)) {
					outStream.writeObject("EXISTS");
					continue;
				} else {
					outStream.writeObject("SEND");
				}
	
				long fileSize = (long) inStream.readObject();
				File file = new File(workspaceDir, fileName);
	
				try (FileOutputStream fileOutputStream = new FileOutputStream(file)) {
					byte[] buffer = new byte[4096];
					long remaining = fileSize;
					int bytesRead;
	
					while (remaining > 0 && (bytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, remaining))) > 0) {
						fileOutputStream.write(buffer, 0, bytesRead);
						remaining -= bytesRead;
					}
				}
	
				if (WorkspaceHandler.addFilePath(workspace, file.getName())) {
					outStream.writeObject("OK");
				} else {
					outStream.writeObject("ERROR");
				}
			} else if ("SIGNATURE".equals(fileCommand)) {
				String signatureFileName = (String) inStream.readObject();
				long sigFileSize = (long) inStream.readObject();
	
				File signatureFile = new File(workspaceDir, signatureFileName);
	
				try (FileOutputStream sigOut = new FileOutputStream(signatureFile)) {
					byte[] buffer = new byte[4096];
					long remaining = sigFileSize;
					int bytesRead;
	
					while (remaining > 0 && (bytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, remaining))) > 0) {
						sigOut.write(buffer, 0, bytesRead);
						remaining -= bytesRead;
					}
				}
	
				outStream.writeObject("OK");
			}
		}
	
		MACUtils.createMAC(FILE_PATH, serverKey);
	}
	
	private synchronized void lsCommand(ObjectOutputStream outStream, ObjectInputStream inStream, String user) throws IOException, ClassNotFoundException {
		String workspace = (String) inStream.readObject();
		System.out.println("List files in workspace: " + workspace);

		if (WorkspaceHandler.getWorkspace(workspace) == null) {
			outStream.writeObject("NOWS");
			return;
		}

		if (!WorkspaceHandler.isAllowed(workspace, user)) {
			outStream.writeObject("NOPERM");
			return;
		}

		File workspaceDir = new File(WS_FOLDER + workspace);
		if (!workspaceDir.exists() || !workspaceDir.isDirectory()) {
			outStream.writeObject("NOFILES");  
			return;
		}

		List<String> fileNames = WorkspaceHandler.listFiles(workspace);

		String[] finalFiles = fileNames.toArray(new String[0]);

		outStream.writeObject("OK");
		outStream.writeObject(finalFiles);
	}

	private synchronized void lwCommand(ObjectOutputStream outStream, ObjectInputStream inStream, String user) throws IOException, ClassNotFoundException {
		outStream.writeObject(WorkspaceHandler.getUserWorkspaces(user));
	}

	private synchronized void rmCommand(ObjectOutputStream outStream, ObjectInputStream inStream, String user) throws Exception {
		String workspace = (String) inStream.readObject();
		List<String> filesToRemove = (List<String>) inStream.readObject();
	
		System.out.println("Removing: " + filesToRemove + " from workspace: " + workspace);
	
		if (WorkspaceHandler.getWorkspace(workspace) == null) {
			outStream.writeObject("NOWS");
			return;
		}
	
		if (!WorkspaceHandler.isAllowed(workspace, user)) {
			outStream.writeObject("NOPERM");
			return;
		}
	
		File workspaceDir = new File(WS_FOLDER + File.separator + workspace);
	
		for (String fileName : filesToRemove) {
			File fileToRemove = new File(workspaceDir, fileName);
	
			if (!fileToRemove.exists()) {
				outStream.writeObject(fileName + ": THE FILE DOES NOT EXIST");
				continue;
			}
	
			if (fileToRemove.delete()) {
				WorkspaceHandler.removeFile(workspace, fileName);
				outStream.writeObject(fileName + ": DELETED");
			} else {
				outStream.writeObject(fileName + ": ERROR");
			}
		}
	
		outStream.writeObject("DONE");
	
		MACUtils.createMAC(FILE_PATH, serverKey);
	}

	private synchronized void dwCommand(ObjectOutputStream outStream, ObjectInputStream inStream, String user) throws IOException, ClassNotFoundException {
    	String workspace = (String) inStream.readObject();
    	List<String> filesToDownload = (List<String>) inStream.readObject();

    	System.out.println("Downloading files: " + filesToDownload + " from workspace: " + workspace);

    	if (WorkspaceHandler.getWorkspace(workspace) == null) {
        	outStream.writeObject("NOWS");
        	return;
    	}

    	if (!WorkspaceHandler.isAllowed(workspace, user)) {
        	outStream.writeObject("NOPERM");
        	return;
    	}

    	File workspaceDir = new File(WS_FOLDER + File.separator + workspace);
    	List<String> existingFiles = WorkspaceHandler.listFiles(workspace);

    	boolean foundAll = true;
    	for (String fileName : filesToDownload) {
        	if (!existingFiles.contains(fileName)) {
            	foundAll = false;
            	break;
        	}
    	}

    	if (!foundAll) {
        	outStream.writeObject("NOFILES");
        	return;
   	 	}

    	// Send files
		outStream.writeObject("OK");


		String keyFile = WS_FOLDER + workspace + File.separator + workspace + ".key." + user;
		byte[] wskey = Files.readAllBytes(Paths.get(keyFile));
		outStream.writeObject(wskey);


    	for (String fileName : filesToDownload) {
        	File fileToSend = new File(workspaceDir, fileName);

			File[] matchingSignedFiles = workspaceDir.listFiles((dir, name) -> name.matches(
    			Pattern.quote(fileToSend.getName()) + "\\.signed\\..+"));
				if (matchingSignedFiles == null || matchingSignedFiles.length == 0) {
					System.out.println("Signed file not found: " + fileToSend.getName());
					outStream.writeObject("ERROR");
					continue;
				}
				
				File signedFileToSend = matchingSignedFiles[0]; 
				String signedFileName = signedFileToSend.getName();

        	if (!fileToSend.exists() || !fileToSend.isFile() || !signedFileToSend.exists() || !signedFileToSend.isFile()  ) {
            	outStream.writeObject("ERROR");
            	continue;
        	}

			outStream.writeObject("File");
        	outStream.writeObject(fileName);
			byte[] fileBytes = Files.readAllBytes(fileToSend.toPath());
			outStream.writeObject((long)fileBytes.length);
			outStream.writeObject(fileBytes);

			outStream.writeObject("Signed");
			outStream.writeObject(signedFileName);
			byte[] signedFileBytes = Files.readAllBytes(signedFileToSend.toPath());
			outStream.writeObject((long) signedFileBytes.length);
			outStream.writeObject(signedFileBytes);

        	System.out.println("Sent: " + fileName);
			System.out.println("Sent signed " + fileName);
    	}
	}


	
	
	
	
	
}