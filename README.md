##Projeto SC

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

Criar a truststore e importar o certificado do servidor
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

