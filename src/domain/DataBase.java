package domain;

import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import org.bson.Document;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;

import cryptoLib.CryptoLibrary;
import cryptoLib.CryptoLibrary;
import db.MongoDB;
import domain.entities.Message;
import domain.utils.JsonManipulator;
import domain.utils.KeyReader;
import domain.utils.JsonManipulator;
import domain.utils.KeyReader;

public class DataBase {

	protected static final String KEYSTORES_DIR = "./src/newKeyStores";
	protected static final String DATABASE_KEYSTORE = KEYSTORES_DIR + "/databaseKeyStore";
	protected static final String DATABASE_TRUSTSTORE = KEYSTORES_DIR + "/databaseTrustStore";
	protected static final String SERVER_CERTIFICATE = KEYSTORES_DIR + "/serverRSApub.cer";
	protected static final String TRUSTSTORE_PASS = "123456";
	protected static PrivateKey databaseKey;
	protected static PublicKey serverKey;

    private static final int DATABASE_PORT = 50000;

	
	// mvn exec:java -Dexec.mainClass="domain.DataBase"
	public static void main(String args[]) throws IOException {

		System.setProperty("javax.net.ssl.keyStore", DATABASE_KEYSTORE);
        System.setProperty("javax.net.ssl.keyStorePassword", TRUSTSTORE_PASS);
        System.setProperty("javax.net.ssl.trustStore", DATABASE_TRUSTSTORE);
        System.setProperty("javax.net.ssl.trustStore", DATABASE_TRUSTSTORE);
        System.setProperty("javax.net.ssl.trustStorePassword", TRUSTSTORE_PASS);
//		System.setProperty("javax.net.debug", "ssl");
        try {
			startDatabase(DATABASE_PORT);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
     }
 	
     public static void startDatabase(int port) throws Exception {
 	
         ServerSocketFactory factory = SSLServerSocketFactory.getDefault();
		 databaseKey = KeyReader.readPrivateKey(DATABASE_KEYSTORE, TRUSTSTORE_PASS, "databaseKeys");
		 serverKey = KeyReader.readPublicKey(SERVER_CERTIFICATE);
         
         SSLServerSocket listener = (SSLServerSocket) factory.createServerSocket(port);

		listener.setNeedClientAuth(true);
		listener.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" });
		listener.setEnabledProtocols(new String[] { "TLSv1.3" });
			
		/*MongoDB mongoDB = MongoDB.getInstance();
		mongoDB.mongoClient = mongoDB.connect();
		mongoDB.database = mongoDB.mongoClient.getDatabase("SIRS41DB");
		mongoDB.insertPatient();
		mongoDB.disconnect();*/
		
		System.out.println("Database waiting for connection...");
		
		while (true) {
			try (Socket socket = listener.accept()) {
				
				System.out.println("Server connection Accepted");

				
				ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
				ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
// 		
				System.out.println("Streams created");
				
				Message serverMessage = (Message) inStream.readObject();
				
// 		
				String[] words = serverMessage.getContent().split("\\s+");
				String username;
				String view;
				int firstIndex;
				Path path;
				String response;
				String signature;
				switch (words[0]) {
					case "GET":
						firstIndex = serverMessage.getContent().indexOf(' ');
						firstIndex = serverMessage.getContent().indexOf(' ', firstIndex + 1);
						firstIndex = serverMessage.getContent().indexOf(' ', firstIndex + 1);
						String signed = serverMessage.getContent().substring(0, firstIndex);
						if (!CryptoLibrary.checkDigitalSignature(signed, words[3], serverKey)) {
							throw new SecurityException("Digital Signature was not verified correctly, ignoring message");
						}
						username = words[1];
						view = words[2];
						CryptoLibrary.addSecurityMeasures("./Views/" + username + "/" + view, "./aux.json", databaseKey, "Database");
						FileReader fileReader = new FileReader("./aux.json");
						JsonObject rootJson = new Gson().fromJson(fileReader, JsonObject.class);
						outStream.writeObject(new Message(rootJson.toString()));
						path = Paths.get("./aux.json");
						Files.delete(path);
						break;
					case "STORE":
						username = words[1];
						view = words[2];
						firstIndex = serverMessage.getContent().indexOf(' ');
						firstIndex = serverMessage.getContent().indexOf(' ', firstIndex + 1);
						firstIndex = serverMessage.getContent().indexOf(' ', firstIndex + 1);
						String record = serverMessage.getContent().substring(firstIndex + 1);
						JsonObject receivedJson = JsonParser.parseString(record).getAsJsonObject();
						JsonManipulator.writeJsonToFile(receivedJson, "./receivedFromServer.json");
						Map<String, PublicKey> keys = new HashMap<String, PublicKey>();
						keys.put("Server", serverKey);
						if(!CryptoLibrary.check("./receivedFromServer.json", keys)) {
							throw new SecurityException("Check was not fulfilled!");
						}
						CryptoLibrary.removeSecurityChecks(receivedJson);
						path = Paths.get("./receivedFromServer.json");
						Files.delete(path);
						path = Paths.get("./Views/" + username);
						if (!Files.exists(path)) {
							Files.createDirectory(path);
						}
						switch (view) {
							case "patientView":
								JsonManipulator.writeJsonToFile(receivedJson, "./Views/" + username + "/" + "patientView");
								break;
							case "publicView":
								JsonManipulator.writeJsonToFile(receivedJson, "./Views/" + username + "/" + "publicView");
								break;
							case "emergencyView":
								JsonManipulator.writeJsonToFile(receivedJson, "./Views/" + username + "/" + "emergencyView");
								break;
						}
						response = "SUCCESS";
						signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(response, databaseKey));
						response = signature + " " + response;
						outStream.writeObject(new Message(response));
						break;
					case "DELETE":
						firstIndex = serverMessage.getContent().indexOf(' ');
						firstIndex = serverMessage.getContent().indexOf(' ', firstIndex + 1);
						String toBeSigned = serverMessage.getContent().substring(0, firstIndex);
						if (!CryptoLibrary.checkDigitalSignature(toBeSigned, words[2], serverKey)) {
							throw new SecurityException("Digital Signature was not verified correctly, ignoring message");
						}
						username = words[1];
						path = Paths.get("./Views/" + username + "/" + "emergencyView");
						Files.delete(path);
						path = Paths.get("./Views/" + username + "/" + "patientView");
						Files.delete(path);
						path = Paths.get("./Views/" + username + "/" + "publicView");
						Files.delete(path);
						path = Paths.get("./Views/" + username);
						Files.delete(path);
						response = "SUCCESS";
						signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(response, databaseKey));
						response = signature + " " + response;
						outStream.writeObject(new Message(response));
						break;
					default:
						break;
				}
// 		            
				inStream.close();
				outStream.close();
			// mongoDB.disconnect();
			}
 		
         }
	}
}
