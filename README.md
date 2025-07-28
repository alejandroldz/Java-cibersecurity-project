This project aims to familiarize and practise some of the problems involved in programming secure distributed application, namely cryptographic key management, secure digest generation, remote attestation, ciphers and digital signatures, and the use of secure channels. 

The assignment consists of implementing a simplified file storage system, called mySharing, where the user relies on a central server to store and, if desired, share their files.

The mySharingClient is responsible for sending and receiving files to/from the server. This program is executed on each client machine and requires the identification of a unique user (for example, user alan). For a client to send, receive, or delete files from the server, the user must first authenticate with the server.

The mySharingServer implements the concept of a workspace, where each workspace may belong to a single user or be shared by multiple users 

Users can have access to multiple workspaces. Thus, a user with access to a given workspace can access, modify, or delete the files stored there. Each workspace has one, and only one, owner. Only the owner can add other users to that workspace. 

The mySharingClient application aims to enable user interaction with the mySharingServer. It must allow the creation of workspaces, the addition of users to workspaces, file uploading, file downloading, and file deletion on the server. To use all these functionalities, the mySharingClient application must implement a simple command-line interface for user interaction.

The server application mySharingServer is a program that allows simultaneous connections with multiple clients, maintains information about files, workspaces, and registered users, authenticates and identifies users, and enables file collection and sharing among the various clients.



How to compile: 
javac -d out src/server/*.java
javac -d out src/client/*.java


Create the jars:
jar cfm myClient.jar client_manifest.txt -C out .
jar cfm myServer.jar server_manifest.txt -C out .

    
How to execute:
    run on the terminal :
        java -jar myServer.jar [port]
        java -jar myClient.jar <serverAddress> <user-id> <password>



Limitations:

The system data files (users.txt and workspaces.txt) and the workspaces are stored in the server/ folder.

The server reads and updates these files automatically during execution.

To upload a file using the up command from the client, the file must be located in the project root directory 

When downloading a file using the dw command, the file will be saved inside a new folder automatically created in the project root directory.



The password of the current server is admin. If we delete both macs files we can change the password. 




Create server keystore:
keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -validity 365 -keystore certificates/server_keystore.jks -storepass serverpass -keypass serverpass -dname "CN=MySharingServer"

Export server certificate
keytool -exportcert -alias server -keystore certificates/server_keystore.jks -file certificates/server_cert.cer -storepass serverpass

Create the truststore and import the server's certificate
keytool -importcert -alias server -file certificates/server_cert.cer -keystore certificates/truststore.jks -storepass trustpass -noprompt



 # Before creating new user:
 "user" equals the username
 "user_pass" equals the password

 Create keystore
 keytool -genkeypair -alias "user" -keyalg RSA -keysize 2048 -validity 365 -keystore certificates/"user"_keystore.jks -storepass "user_pass" -keypass "user_pass" -dname "CN=user"

Export certificate 
 keytool -exportcert -alias "user" -keystore certificates/"user"_keystore.jks -file certificates/"user"_cert.cer -storepass "user_pass"

Add to truststore
 keytool -importcert -alias "user" -file certificates/"user"_cert.cer -keystore certificates/truststore.jks -storepass trustpass -noprompt




 3 users com keystores e certificado na truststore:
 goncalo 020802
 teresa 562345
 tiago 123456

