package domain;

import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Map;
import java.util.HashMap;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import cryptoLib.CryptoLibrary;
import java.security.Key;

import db.MongoDB;
import domain.entities.Message;
import domain.utils.JsonManipulator;
import domain.utils.KeyReader;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Server {
	
	protected static final String KEYSTORES_DIR = "./src/newKeyStores";
	protected static final String SERVER_KEYSTORE = KEYSTORES_DIR + "/serverKeyStore";
	protected static final String SERVER_TRUSTSTORE = KEYSTORES_DIR + "/serverTrustStore";
	protected static final String SERVER_CERTIFICATE = KEYSTORES_DIR + "/serverRSApub.cer";
	protected static final String DRSMITH_KEYSTORE = KEYSTORES_DIR + "smithKeyStore";
	protected static final String DRJONES_KEYSTORE = KEYSTORES_DIR + "jonesKeyStore";
	protected static final String PATIENT_CERTIFICATE = KEYSTORES_DIR + "/patientRSApub.cer";
	protected static final String DRJONES_CERTIFICATE = KEYSTORES_DIR + "/jonesRSApub.cer";
	protected static final String DRSMITH_CERTIFICATE = KEYSTORES_DIR + "/smithRSApub.cer";
	protected static final String INSURANCE_KEYSTORE = KEYSTORES_DIR + "/insuranceKeyStore";
	protected static final String INSURANCE_CERTIFICATE = KEYSTORES_DIR + "/insuranceRSApub.cer";
	protected static final String EMERGENCY_KEY = "emergency";
	protected static final String ORTHOPEDY_KEY = "orthopedy";
	protected static final String SPECIALITY_KEYSTORE = KEYSTORES_DIR + "/specialityKeyStore";
	protected static final String DATABASE_CERTIFICATE = KEYSTORES_DIR + "/databaseRSApub.cer";
	protected static final String TRUSTSTORE_PASS = "123456";
	
	private static final int SERVER_PORT = 12345;
    private static final int DATABASE_PORT = 50000;
    
	public static MongoDB mongoDB;


	private static PrivateKey serverPrivate;
	private static PublicKey serverPublic;
	private static PublicKey patientKey;
	private static Key emergencyKey;
	private static Key orthopedyKey;
	private static Map<String, PublicKey> doctorKeys;
	private static PublicKey insuranceKey;
	private static PublicKey databaseKey;
	private static Map<String, Boolean> doctorAuths = new HashMap<String, Boolean>();
	private static Map<String, Boolean> insuranceAuths = new HashMap<String, Boolean>();

	private static String patientUsername;
	private static int maxUsers = 0;

	// mvn exec:java -Dexec.mainClass="domain.Server"
	public static void main(String args[]) throws IOException {
		
		
		Server server = new Server();

		
		System.setProperty("javax.net.ssl.keyStore", SERVER_KEYSTORE);
        System.setProperty("javax.net.ssl.keyStorePassword", TRUSTSTORE_PASS);
        System.setProperty("javax.net.ssl.trustStore", SERVER_TRUSTSTORE);
        System.setProperty("javax.net.ssl.trustStorePassword", TRUSTSTORE_PASS);
        
		try {
			getKeys();
		}
		catch (Exception e) {
			e.printStackTrace();
		}

        ServerSocketFactory factory = SSLServerSocketFactory.getDefault();
        
        SSLServerSocket listener = (SSLServerSocket) factory.createServerSocket(SERVER_PORT);	
        	
		listener.setNeedClientAuth(true);
		listener.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" });
		listener.setEnabledProtocols(new String[] { "TLSv1.3" });	

		server.startServer(listener);
    }

	private static void getKeys() throws Exception {
		serverPrivate = KeyReader.readPrivateKey(SERVER_KEYSTORE, TRUSTSTORE_PASS, "serverKeys");
		serverPublic = KeyReader.readPublicKey(SERVER_CERTIFICATE);
		patientKey = KeyReader.readPublicKey(PATIENT_CERTIFICATE);
		databaseKey = KeyReader.readPublicKey(DATABASE_CERTIFICATE);
		PublicKey smithKey = KeyReader.readPublicKey(DRSMITH_CERTIFICATE);
		PublicKey jonesKey = KeyReader.readPublicKey(DRJONES_CERTIFICATE);
		doctorKeys = new HashMap<String, PublicKey>();
		doctorKeys.put("Dr.Smith", smithKey);
		doctorKeys.put("Dr.Jones", jonesKey);
		insuranceKey = KeyReader.readPublicKey(INSURANCE_CERTIFICATE);
		emergencyKey = KeyReader.readSecretKey(SPECIALITY_KEYSTORE, TRUSTSTORE_PASS, EMERGENCY_KEY);
		orthopedyKey = KeyReader.readSecretKey(SPECIALITY_KEYSTORE, TRUSTSTORE_PASS, ORTHOPEDY_KEY);
		doctorAuths.put("Dr.Smith", false);
		doctorAuths.put("Dr.Jones", false);
		insuranceAuths.put("Freedom", false);
	}

	private static void handlePubKeys(ObjectOutputStream stream) throws Exception {
		String response = "";
		for (String key : doctorKeys.keySet()) {
			response += key;
			response += " ";
			response += Base64.getEncoder().encodeToString(doctorKeys.get(key).getEncoded());
			response += " ";
		}
		String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(response, serverPrivate));
		response = signature + " SUCCESS " + response;
		Message message = new Message(response);
		stream.writeObject(message);
		stream.flush();
	}

	private static void handleClientConsult(ObjectOutputStream stream, DatabaseHandler handler) throws Exception {
        JsonObject rootJson = getRecord(handler, patientUsername, "patientView");

		JsonManipulator.writeJsonToFile(rootJson, "./receivedFromDatabase.json");
		CryptoLibrary.addSecurityMeasures("./receivedFromDatabase.json", "./receivedFromDatabase.json", serverPrivate, "Server");
		FileReader fileReader = new FileReader("./receivedFromDatabase.json");
        JsonObject sendJson = new Gson().fromJson(fileReader, JsonObject.class);
		Message message = new Message(sendJson.toString());
		stream.writeObject(message);
		stream.flush();
		Path path = Paths.get("./receivedFromDatabase.json");
		Files.delete(path);
	}

	private static void handleGrantAccess(ObjectOutputStream stream, String command) throws Exception {
		String[] words = command.split("\\s+");
		String content = "";
		if (words[1].equals("DOCTOR")) {
			if (doctorKeys.containsKey(words[2])) {
				doctorAuths.put(words[2], true);
				content = "SUCCESS";
			}
			else {
				content = "ERROR";
			}
		}
		else {
			if (words[2].equals("Freedom")) {
				insuranceAuths.put(words[2], true);
				content = "SUCCESS";
			}
			else {
				content = "ERROR";
			}
		}

		String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(content, serverPrivate));
		content = signature + " " + content;
		stream.writeObject(new Message(content));
		stream.flush();
	}

	private static void handleCreate(ObjectOutputStream stream, Key decypherKey, DatabaseHandler handler) throws Exception {
		if (maxUsers == 1) {
			String content = "ERROR";
			String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(content, serverPrivate));
			content = signature + " " + content;
			stream.writeObject(new Message(content));
			stream.flush();
			return;
		}


		CryptoLibrary.unprotect("./receivedCreated.json", "./unencrypted.json", 1, 0, 1, decypherKey);
		CryptoLibrary.unprotect("./unencrypted.json", "./unencrypted.json", 0, 1, 1, decypherKey);
		CryptoLibrary.unprotect("./unencrypted.json", "./unencrypted.json", 0, 0, 4, decypherKey);

		JsonObject rootJson = JsonManipulator.getRootJson("./unencrypted.json");
		JsonObject objectJson = rootJson.getAsJsonObject("patient");
		patientUsername = objectJson.get("name").getAsString();
		maxUsers = 1;
		JsonManipulator.writeJsonToFile(rootJson, "./patientView.json");
		JsonManipulator.writeJsonToFile(rootJson, "./publicView.json");
		JsonManipulator.writeJsonToFile(rootJson, "./emergencyView.json");

		CryptoLibrary.protect("./patientView.json", "./patientView.json", 0, 0, patientKey, 0, serverPrivate);
		CryptoLibrary.protect("./patientView.json", "./patientView.json", 1, 0, patientKey, 0, serverPrivate);
		CryptoLibrary.protect("./patientView.json", "./patientView.json", 4, 0, patientKey, 0, serverPrivate);
		CryptoLibrary.addSecurityMeasures("./patientView.json", "./patientView.json", serverPrivate, "Server");
		rootJson = JsonManipulator.getRootJson("./patientView.json");
		storeRecord(handler, patientUsername, "patientView", rootJson);

		CryptoLibrary.protect("./publicView.json", "./publicView.json", 0, 0, patientKey, 0, serverPrivate);
		CryptoLibrary.protect("./publicView.json", "./publicView.json", 1, 0, patientKey, 0, serverPrivate);
		CryptoLibrary.protect("./publicView.json", "./publicView.json", 4, 0, insuranceKey, 0, serverPrivate);
		CryptoLibrary.addSecurityMeasures("./publicView.json", "./publicView.json", serverPrivate, "Server");
		rootJson = JsonManipulator.getRootJson("./publicView.json");
		storeRecord(handler, patientUsername, "publicView", rootJson);

		CryptoLibrary.protect("./emergencyView.json", "./emergencyView.json", 0, 1, emergencyKey, 0, serverPrivate);
		CryptoLibrary.protect("./emergencyView.json", "./emergencyView.json", 1, 1, emergencyKey, 0, serverPrivate);
		CryptoLibrary.protect("./emergencyView.json", "./emergencyView.json", 4, 1, emergencyKey, 0, serverPrivate);
		CryptoLibrary.addSecurityMeasures("./emergencyView.json", "./emergencyView.json", serverPrivate, "Server");
		rootJson = JsonManipulator.getRootJson("./emergencyView.json");
		storeRecord(handler, patientUsername, "emergencyView", rootJson);

		String content = "SUCCESS";
		String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(content, serverPrivate));
		content = signature + " " + content;
		stream.writeObject(new Message(content));
		stream.flush();
		Path path = Paths.get("./receivedCreated.json");
		Files.delete(path);
		path = Paths.get("./unencrypted.json");
		Files.delete(path);
		path = Paths.get("./patientView.json");
		Files.delete(path);
		path = Paths.get("./publicView.json");
		Files.delete(path);
		path = Paths.get("./emergencyView.json");
		Files.delete(path);
	}

	private static void handleDelete(ObjectOutputStream stream, String name, DatabaseHandler handler) throws Exception {
		if (name.equals(patientUsername)) {
			deleteRecord(handler, name);
			String content = "SUCCESS";
			String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(content, serverPrivate));
			content = signature + " " + content;
			stream.writeObject(new Message(content));
			stream.flush();
			patientUsername = "";
			maxUsers = 0;
		}
		else {
			String content = "ERROR";
			String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(content, serverPrivate));
			content = signature + " " + content;
			stream.writeObject(new Message(content));
			stream.flush();
		}
	}

	private static void handleAdd(ObjectOutputStream stream, Key decypherKey, String doctorName, DatabaseHandler handler) throws Exception {
		Key specialityKey;
		if (doctorName.equals("Dr.Smith")) {
			specialityKey = orthopedyKey;
		}
		else {
			specialityKey = emergencyKey;
		}

		CryptoLibrary.unprotect("./receivedAdd.json", "./unencrypted.json", 1, 2, 1, decypherKey);
		CryptoLibrary.unprotect("./unencrypted.json", "./unencrypted.json", 0, 3, 1, decypherKey);
		
		JsonObject rootJson = JsonManipulator.getRootJson("./unencrypted.json");
		CryptoLibrary.removeSecurityChecks(rootJson);
		JsonManipulator.writeJsonToFile(rootJson, "./patientRecord.json");
		JsonManipulator.writeJsonToFile(rootJson, "./publicRecord.json");
		JsonManipulator.writeJsonToFile(rootJson, "./emergencyRecord.json");

		CryptoLibrary.protect("./patientRecord.json", "./patientRecord.json", 2, 0, patientKey, 0, serverPrivate);
		CryptoLibrary.protect("./patientRecord.json", "./patientRecord.json", 3, 0, patientKey, 0, serverPrivate);
		CryptoLibrary.addSecurityMeasures("./patientRecord.json", "./patientRecord.json", serverPrivate, "Server");
		addToRecords("./patientRecord.json", "patientView", handler);

		CryptoLibrary.protect("./publicRecord.json", "./publicRecord.json", 2, 1, specialityKey, 0, serverPrivate);
		CryptoLibrary.protect("./publicRecord.json", "./publicRecord.json", 3, 0, insuranceKey, 0, serverPrivate);
		CryptoLibrary.addSecurityMeasures("./publicRecord.json", "./publicRecord.json", serverPrivate, "Server");
		addToRecords("./publicRecord.json", "publicView", handler);

		CryptoLibrary.protect("./emergencyRecord.json", "./emergencyRecord.json", 2, 1, emergencyKey, 0, serverPrivate);
		CryptoLibrary.protect("./emergencyRecord.json", "./emergencyRecord.json", 3, 1, emergencyKey, 0, serverPrivate);
		CryptoLibrary.addSecurityMeasures("./emergencyRecord.json", "./emergencyRecord.json", serverPrivate, "Server");
		addToRecords("./emergencyRecord.json", "emergencyView", handler);

		String content = "SUCCESS";
		String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(content, serverPrivate));
		content = signature + " " + content;
		stream.writeObject(new Message(content));
		stream.flush();

		Path path = Paths.get("./receivedAdd.json");
		Files.delete(path);
		path = Paths.get("./unencrypted.json");
		Files.delete(path);
	}

	private static void addToRecords (String newRecordPath, String view, DatabaseHandler handler) throws Exception {
		JsonObject newRecord = JsonManipulator.getRootJson(newRecordPath);
		JsonObject newPatient = newRecord.get("patient").getAsJsonObject();
		JsonArray newConsult = newPatient.get("consultationRecords").getAsJsonArray();
		JsonElement toBeAdded = newConsult.get(0);
		JsonObject oldRecord = getRecord(handler, patientUsername, view);
		JsonObject oldPatient = oldRecord.get("patient").getAsJsonObject();
		JsonArray oldConsults = oldPatient.get("consultationRecords").getAsJsonArray();
		oldConsults.add(toBeAdded);
		oldPatient.add("consultationRecords", oldConsults);
		oldRecord.add("patient", oldPatient);
		JsonManipulator.writeJsonToFile(oldRecord, "./toSend.json");
		CryptoLibrary.addSecurityMeasures("./toSend.json", "./toSend.json", serverPrivate, "Server");
		oldRecord = JsonManipulator.getRootJson("./toSend.json");
		storeRecord(handler, patientUsername, view, oldRecord);
		Path path = Paths.get(newRecordPath);
		Files.delete(path);
		path = Paths.get("./toSend.json");
		Files.delete(path);
	} 
    
	private static void handleDoctorPublicConsult(ObjectOutputStream stream, String patientName, String doctorName, DatabaseHandler handler) throws Exception {
        JsonObject rootJson = getRecord(handler, patientName, "publicView");

		JsonManipulator.writeJsonToFile(rootJson, "./receivedFromDatabase.json");
		Key specialityKey;
		if (doctorName.equals("Dr.Smith")) {
			specialityKey = orthopedyKey;
		}
		else {
			specialityKey = emergencyKey;
		}

		CryptoLibrary.unprotect("./receivedFromDatabase.json", "./receivedFromDatabase.json", 0, 2, 1, specialityKey);
		CryptoLibrary.addKey(false, KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "auxSpeciality");
		Key auxKey = KeyReader.readSecretKey(KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "auxSpeciality");

		CryptoLibrary.protect("./receivedFromDatabase.json", "./receivedFromDatabase.json", 2, 1, auxKey, 0, serverPrivate);
		CryptoLibrary.addSecurityMeasures("./receivedFromDatabase.json", "./receivedFromDatabase.json", serverPrivate, "Server");
		FileReader fileReader = new FileReader("./receivedFromDatabase.json");
        JsonObject sendJson = new Gson().fromJson(fileReader, JsonObject.class);
		PublicKey doctorPublic = doctorKeys.get(doctorName);
		String cypheredKey = CryptoLibrary.cypherKey(auxKey, doctorPublic);
		Message message = new Message(cypheredKey + " " + sendJson.toString());
		stream.writeObject(message);
		stream.flush();
		Path path = Paths.get("./receivedFromDatabase.json");
		Files.delete(path);
		CryptoLibrary.removeKey(KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "auxSpeciality");
	}


	private static void handleDoctorAuthConsult(ObjectOutputStream stream, String patientName, String doctorName, DatabaseHandler handler) throws Exception {
        JsonObject emergencyJson = getRecord(handler, patientName, "emergencyView");
        JsonObject publicJson = getRecord(handler, patientName, "publicView");

		if (doctorAuths.get(doctorName) == false) {
			String content = "ERROR";
			String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(content, serverPrivate));
			content += " " + signature;
			stream.writeObject(new Message(content));
			stream.flush();
			return;
		}
		else {
			doctorAuths.put(doctorName, false);   //authorization only lasts one session
		}

		JsonManipulator.writeJsonToFile(emergencyJson, "./toBeExtracted.json");
		JsonManipulator.writeJsonToFile(publicJson, "./toBeSent.json");
		Key specialityKey;
		if (doctorName.equals("Dr.Smith")) {
			specialityKey = orthopedyKey;
		}
		else {
			specialityKey = emergencyKey;
		}

		CryptoLibrary.unprotect("./toBeExtracted.json", "./toBeExtracted.json", 0, 1, 1, emergencyKey);
		FileReader fileReader = new FileReader("./toBeExtracted.json");
        JsonObject toBeExtractedJson = new Gson().fromJson(fileReader, JsonObject.class);
		toBeExtractedJson = toBeExtractedJson.get("patient").getAsJsonObject();
		String emergencyPhoneNumber = toBeExtractedJson.get("emergencyPhoneNumber").getAsString();
		String bloodType = toBeExtractedJson.get("bloodType").getAsString();
		JsonArray knownAllergies = new JsonArray();
		for (JsonElement element : toBeExtractedJson.get("knownAllergies").getAsJsonArray()) {
			knownAllergies.add(element);
		}
		JsonArray knownIllnesses = new JsonArray();
		for (JsonElement element : toBeExtractedJson.get("knownIllnesses").getAsJsonArray()) {
			knownIllnesses.add(element);
		}

		CryptoLibrary.unprotect("./toBeSent.json", "./toBeSent.json", 0, 2, 1, specialityKey);
		CryptoLibrary.addKey(false, KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "auxSpeciality");
		Key auxKey = KeyReader.readSecretKey(KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "auxSpeciality");

		//CryptoLibrary.protect("./toBeSent.json", "./toBeSent.json", 2, 1, auxKey, 0, serverPrivate);
		fileReader = new FileReader("./toBeSent.json");
        publicJson = new Gson().fromJson(fileReader, JsonObject.class);
		JsonObject patientJson = publicJson.get("patient").getAsJsonObject();
		patientJson.addProperty("emergencyPhoneNumber", emergencyPhoneNumber);
		patientJson.addProperty("bloodType", bloodType);
		patientJson.add("knownAllergies", knownAllergies);
		patientJson.add("knownIllnesses", knownIllnesses);
		publicJson.add("patient", patientJson);
		JsonManipulator.writeJsonToFile(publicJson, "./toBeSent.json");
		CryptoLibrary.protect("./toBeSent.json", "./toBeSent.json", 1, 1, auxKey, 0, serverPrivate);
		CryptoLibrary.protect("./toBeSent.json", "./toBeSent.json", 2, 1, auxKey, 0, serverPrivate);

		CryptoLibrary.addSecurityMeasures("./toBeSent.json", "./toBeSent.json", serverPrivate, "Server");
		fileReader = new FileReader("./toBeSent.json");
        JsonObject sendJson = new Gson().fromJson(fileReader, JsonObject.class);
		PublicKey doctorPublic = doctorKeys.get(doctorName);
		String cypheredKey = CryptoLibrary.cypherKey(auxKey, doctorPublic);
		Message message = new Message(cypheredKey + " " + sendJson.toString());
		stream.writeObject(message);
		stream.flush();
		Path path = Paths.get("./toBeSent.json");
		Files.delete(path);
		path = Paths.get("./toBeExtracted.json");
		Files.delete(path);
		CryptoLibrary.removeKey(KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "auxSpeciality");
	}

	private static void handleDoctorERConsult(ObjectOutputStream stream, String patientName, String doctorName, DatabaseHandler handler) throws Exception {
		if (!doctorName.equals("Dr.Jones")) {
			String content = "ERROR";
			String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(content, serverPrivate));
			content += " " + signature;
			stream.writeObject(new Message(content));
			stream.flush();
			return;
		}

        JsonObject rootJson = getRecord(handler, patientName, "emergencyView");

		JsonManipulator.writeJsonToFile(rootJson, "./receivedFromDatabase.json");

		CryptoLibrary.unprotect("./receivedFromDatabase.json", "./receivedFromDatabase.json", 0, 0, 1, emergencyKey);
		CryptoLibrary.unprotect("./receivedFromDatabase.json", "./receivedFromDatabase.json", 0, 1, 1, emergencyKey);
		CryptoLibrary.unprotect("./receivedFromDatabase.json", "./receivedFromDatabase.json", 0, 2, 1, emergencyKey);
		CryptoLibrary.unprotect("./receivedFromDatabase.json", "./receivedFromDatabase.json", 0, 3, 1, emergencyKey);
		CryptoLibrary.unprotect("./receivedFromDatabase.json", "./receivedFromDatabase.json", 0, 4, 1, emergencyKey);
		CryptoLibrary.addKey(false, KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "auxEmergency");
		Key auxKey = KeyReader.readSecretKey(KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "auxEmergency");

		CryptoLibrary.protect("./receivedFromDatabase.json", "./receivedFromDatabase.json", 0, 1, auxKey, 0, serverPrivate);
		CryptoLibrary.protect("./receivedFromDatabase.json", "./receivedFromDatabase.json", 1, 1, auxKey, 0, serverPrivate);
		CryptoLibrary.protect("./receivedFromDatabase.json", "./receivedFromDatabase.json", 2, 1, auxKey, 0, serverPrivate);
		CryptoLibrary.protect("./receivedFromDatabase.json", "./receivedFromDatabase.json", 3, 1, auxKey, 0, serverPrivate);
		CryptoLibrary.protect("./receivedFromDatabase.json", "./receivedFromDatabase.json", 4, 1, auxKey, 0, serverPrivate);
		CryptoLibrary.addSecurityMeasures("./receivedFromDatabase.json", "./receivedFromDatabase.json", serverPrivate, "Server");
		FileReader fileReader = new FileReader("./receivedFromDatabase.json");
        JsonObject sendJson = new Gson().fromJson(fileReader, JsonObject.class);
		PublicKey doctorPublic = doctorKeys.get(doctorName);
		String cypheredKey = CryptoLibrary.cypherKey(auxKey, doctorPublic);
		Message message = new Message(cypheredKey + " " + sendJson.toString());
		stream.writeObject(message);
		stream.flush();
		Path path = Paths.get("./receivedFromDatabase.json");
		Files.delete(path);
		CryptoLibrary.removeKey(KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "auxEmergency");


	}

	public static void handleInsurancePublicConsult(ObjectOutputStream stream, DatabaseHandler handler) throws Exception {
        JsonObject rootJson = getRecord(handler, patientUsername, "publicView");

		JsonManipulator.writeJsonToFile(rootJson, "./receivedFromDatabase.json");

		CryptoLibrary.addSecurityMeasures("./receivedFromDatabase.json", "./receivedFromDatabase.json", serverPrivate, "Server");
		FileReader fileReader = new FileReader("./receivedFromDatabase.json");
        JsonObject sendJson = new Gson().fromJson(fileReader, JsonObject.class);
		Message message = new Message(sendJson.toString());
		stream.writeObject(message);
		stream.flush();
		Path path = Paths.get("./receivedFromDatabase.json");
		Files.delete(path);
	}

	public static void handleInsuranceAuthConsult(ObjectOutputStream stream, DatabaseHandler handler) throws Exception {
        JsonObject emergencyJson = getRecord(handler, patientUsername, "emergencyView");
        JsonObject publicJson = getRecord(handler, patientUsername, "publicView");

		if (insuranceAuths.get("Freedom") == false) {
			String content = "ERROR";
			String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(content, serverPrivate));
			content += " " + signature;
			stream.writeObject(new Message(content));
			stream.flush();
			return;
		}
		else {
			insuranceAuths.put("Freedom", false);   //authorization only lasts one session
		}

		JsonManipulator.writeJsonToFile(emergencyJson, "./toBeExtracted.json");

		CryptoLibrary.unprotect("./toBeExtracted.json", "./toBeExtracted.json", 0, 1, 1, emergencyKey);
		FileReader fileReader = new FileReader("./toBeExtracted.json");
        JsonObject toBeExtractedJson = new Gson().fromJson(fileReader, JsonObject.class);
		toBeExtractedJson = toBeExtractedJson.get("patient").getAsJsonObject();
		String emergencyPhoneNumber = toBeExtractedJson.get("emergencyPhoneNumber").getAsString();
		String bloodType = toBeExtractedJson.get("bloodType").getAsString();
		JsonArray knownAllergies = new JsonArray();
		for (JsonElement element : toBeExtractedJson.get("knownAllergies").getAsJsonArray()) {
			knownAllergies.add(element);
		}
		JsonArray knownIllnesses = new JsonArray();
		for (JsonElement element : toBeExtractedJson.get("knownIllnesses").getAsJsonArray()) {
			knownIllnesses.add(element);
		}

		CryptoLibrary.addKey(false, KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "auxInsurance");
		Key auxKey = KeyReader.readSecretKey(KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "auxInsurance");

		JsonObject patientJson = publicJson.get("patient").getAsJsonObject();
		patientJson.addProperty("emergencyPhoneNumber", emergencyPhoneNumber);
		patientJson.addProperty("bloodType", bloodType);
		patientJson.add("knownAllergies", knownAllergies);
		patientJson.add("knownIllnesses", knownIllnesses);
		publicJson.add("patient", patientJson);
		JsonManipulator.writeJsonToFile(publicJson, "./toBeSent.json");
		CryptoLibrary.protect("./toBeSent.json", "./toBeSent.json", 1, 1, auxKey, 0, serverPrivate);

		CryptoLibrary.addSecurityMeasures("./toBeSent.json", "./toBeSent.json", serverPrivate, "Server");
		fileReader = new FileReader("./toBeSent.json");
        JsonObject sendJson = new Gson().fromJson(fileReader, JsonObject.class);
		String cypheredKey = CryptoLibrary.cypherKey(auxKey, insuranceKey);
		Message message = new Message(cypheredKey + " " + sendJson.toString());
		stream.writeObject(message);
		stream.flush();
		Path path = Paths.get("./toBeSent.json");
		Files.delete(path);
		path = Paths.get("./toBeExtracted.json");
		Files.delete(path);
		CryptoLibrary.removeKey(KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "auxInsurance");
	}
 
    public void startServer(SSLServerSocket sslServerSocket) throws IOException {
    	
    	DatabaseHandler databaseHandler = DatabaseHandler.getInstance(DATABASE_PORT);
    	

    	while (true) {

			try {
				System.out.println("Waiting for client connections...");

				new ClientHandler(sslServerSocket.accept(), databaseHandler).start();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
    }
    	
    class ClientHandler extends Thread {
    	
		private Socket socket = null;
    	private ObjectOutputStream clientOutStream;
		private ObjectInputStream clientInStream;
		private DatabaseHandler databaseHandler;
    	
		ClientHandler(Socket sslServerSocket, DatabaseHandler databaseHandler) {
			socket = sslServerSocket;
			this.databaseHandler = databaseHandler;

			try {
				clientOutStream = new ObjectOutputStream(socket.getOutputStream());
				clientInStream = new ObjectInputStream(socket.getInputStream());
			} catch (IOException e) {
				e.printStackTrace();
				System.out.println("Erro nas streams da socket");
			}
		}
		
		public void run() {
		
			try {
				
				System.out.println("Client connection Accepted");
				
				Message clientMessage = (Message) clientInStream.readObject();
				String messageString = clientMessage.getContent();
				String[] words = messageString.split("\\s+");
				String command = words[0];

				int firstIndex;
				int secondIndex;
				String toBeSigned;

				switch (command) {
					case "PUBKEYS":
						switch(words[1]) {
							case "PATIENT":
								if (!words[2].equals(patientUsername)) {
									clientOutStream.writeObject(new Message("ERROR ERROR"));
									clientOutStream.flush();
									break;
								}
								firstIndex = messageString.indexOf(' ');
								secondIndex = messageString.indexOf(' ', firstIndex + 1);
								firstIndex = messageString.indexOf(' ', secondIndex + 1);
								toBeSigned = messageString.substring(0, firstIndex);
								System.out.println(toBeSigned);
								if (!CryptoLibrary.checkDigitalSignature(toBeSigned, words[3], patientKey)) {
									throw new SecurityException("Digital Signature was not verified correctly, ignoring message");
								}
								handlePubKeys(clientOutStream);
								break;
							case "INSURANCE":
								firstIndex = messageString.indexOf(' ');
								secondIndex = messageString.indexOf(' ', firstIndex + 1);
								toBeSigned = messageString.substring(0, secondIndex);
								System.out.println(toBeSigned);
								if (!CryptoLibrary.checkDigitalSignature(toBeSigned, words[2], insuranceKey)) {
									throw new SecurityException("Digital Signature was not verified correctly, ignoring message");
								}
								handlePubKeys(clientOutStream);
								break;
						}
						break;
					case "CONSULT":
						switch(words[1]) {
							case "PATIENT":
								firstIndex = messageString.indexOf(' ');
								secondIndex = messageString.indexOf(' ', firstIndex + 1);
								toBeSigned = messageString.substring(0, secondIndex);
								System.out.println(toBeSigned);
								if (!CryptoLibrary.checkDigitalSignature(toBeSigned, words[2], patientKey)) {
									throw new SecurityException("Digital Signature was not verified correctly, ignoring message");
								}
								handleClientConsult(clientOutStream, databaseHandler);
								break;
							case "DOCTOR":
								firstIndex = messageString.indexOf(' ');
								secondIndex = messageString.indexOf(' ', firstIndex + 1);
								firstIndex = messageString.indexOf(' ', secondIndex + 1);
								secondIndex = messageString.indexOf(' ', firstIndex + 1);
								firstIndex = messageString.indexOf(' ', secondIndex + 1);
								toBeSigned = messageString.substring(0, firstIndex);
								PublicKey doctKey = doctorKeys.get(words[4]);
								if (!CryptoLibrary.checkDigitalSignature(toBeSigned, words[5], doctKey)) {
									throw new SecurityException("Digital Signature was not verified correctly, ignoring message");
								}
								if (!words[3].equals(patientUsername)) {
									String content = "ERROR";
									String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(content, serverPrivate));
									content += " " + signature;
									clientOutStream.writeObject(new Message(content));
									clientOutStream.flush();
									return;
								}
								switch(words[2]) {
									case "PUBLIC":
										handleDoctorPublicConsult(clientOutStream, words[3], words[4], databaseHandler);
										break;
									case "AUTH":
										handleDoctorAuthConsult(clientOutStream, words[3], words[4], databaseHandler);
										break;
									case "ER":
										handleDoctorERConsult(clientOutStream, words[3], words[4], databaseHandler);
										break;
								}
								break;
							case "INSURANCE":
								firstIndex = messageString.indexOf(' ');
								secondIndex = messageString.indexOf(' ', firstIndex + 1);
								firstIndex = messageString.indexOf(' ', secondIndex + 1);
								secondIndex = messageString.indexOf(' ', firstIndex + 1);
								toBeSigned = messageString.substring(0, secondIndex);
								if (!CryptoLibrary.checkDigitalSignature(toBeSigned, words[4], insuranceKey)) {
									throw new SecurityException("Digital Signature was not verified correctly, ignoring message");
								}
								if (!words[3].equals(patientUsername)) {
									String content = "ERROR";
									String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(content, serverPrivate));
									content += " " + signature;
									clientOutStream.writeObject(new Message(content));
									clientOutStream.flush();
									return;
								}
								switch(words[2]) {
									case "PUBLIC":
										handleInsurancePublicConsult(clientOutStream, databaseHandler);
										break;
									case "AUTH":
										handleInsuranceAuthConsult(clientOutStream, databaseHandler);
										break;
								}
								break;
							default:
								System.out.println("Command not recognized: " + messageString);
								break;
						}
						break;
					case "GRANT":
						firstIndex = messageString.indexOf(' ');
						secondIndex = messageString.indexOf(' ', firstIndex + 1);
						firstIndex = messageString.indexOf(' ', secondIndex + 1);
						toBeSigned = messageString.substring(0, firstIndex);
						if (!CryptoLibrary.checkDigitalSignature(toBeSigned, words[3], patientKey)) {
							throw new SecurityException("Digital Signature was not verified correctly, ignoring message");
						}
						handleGrantAccess(clientOutStream, toBeSigned);
						break;
					case "CREATE":
						firstIndex = messageString.indexOf(' ');
						secondIndex = messageString.indexOf(' ', firstIndex + 1);
						String record = messageString.substring(secondIndex + 1);
						String keyString = words[1];
						Key receivedSecret = CryptoLibrary.decypherKey(keyString, serverPrivate);
						JsonObject rootJson = JsonParser.parseString(record).getAsJsonObject();
						JsonManipulator.writeJsonToFile(rootJson, "./receivedCreated.json");
						if(!CryptoLibrary.check("./receivedCreated.json", doctorKeys)) {
							throw new SecurityException("Check was not fulfilled!");
						}

						handleCreate(clientOutStream, receivedSecret, databaseHandler);
						break;
					case "DELETE":
						firstIndex = messageString.indexOf(' ');
						secondIndex = messageString.indexOf(' ', firstIndex + 1);
						firstIndex = messageString.indexOf(' ', secondIndex + 1);
						toBeSigned = messageString.substring(0, firstIndex);
						PublicKey verificationKey = doctorKeys.get(words[1]);
						if (!CryptoLibrary.checkDigitalSignature(toBeSigned, words[3], verificationKey)) {
							throw new SecurityException("Digital Signature was not verified correctly, ignoring message");
						}
						handleDelete(clientOutStream, words[2], databaseHandler);
						break;
					case "ADD":
						firstIndex = messageString.indexOf(' ');
						secondIndex = messageString.indexOf(' ', firstIndex + 1);
						String consult = messageString.substring(secondIndex + 1);
						String keyStr = words[1];
						Key receivedKey = CryptoLibrary.decypherKey(keyStr, serverPrivate);
						JsonObject newJson = JsonParser.parseString(consult).getAsJsonObject();
						String name = newJson.get("patient").getAsJsonObject().get("name").getAsString();
						if (!name.equals(patientUsername)) {
							String content = "ERROR";
							String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(content, serverPrivate));
							content = signature + " " + content;
							clientOutStream.writeObject(new Message(content));
							clientOutStream.flush();
						}
						JsonManipulator.writeJsonToFile(newJson, "./receivedAdd.json");
						if(!CryptoLibrary.check("./receivedAdd.json", doctorKeys)) {
							throw new SecurityException("Check was not fulfilled!");
						}

						String docName = newJson.get("integritySigner").getAsString();
						handleAdd(clientOutStream, receivedKey, docName, databaseHandler);
						break;
					default:
						System.out.println("Command not recognized: " + messageString);
						break;
				}

				clientInStream.close();
				clientOutStream.close();
                
			} catch (Exception e) {
				e.printStackTrace();
			}
			
		}
    }


	private static JsonObject getRecord(DatabaseHandler handler, String patientname, String view) throws Exception{
		handler.connect();
		String command = "GET " + patientname + " " + view;
		String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(command, serverPrivate));
		command = command + " " + signature;
		handler.sendMessage(command);
		String message = handler.receiveMessage().getContent();
		
		JsonObject rootJson = JsonParser.parseString(message).getAsJsonObject();
		JsonManipulator.writeJsonToFile(rootJson, "./receivedFromDB.json");
		Map<String, PublicKey> keys = new HashMap<String, PublicKey>();
		keys.put("Database", databaseKey);
		if(!CryptoLibrary.check("./receivedFromDB.json", keys)) {
			throw new SecurityException("Check was not fulfilled!");
		}
		CryptoLibrary.removeSecurityChecks(rootJson);
		handler.closeConnection();
		Path path = Paths.get("./receivedFromDB.json");
		Files.delete(path);
		return rootJson;
	}

	private static void storeRecord(DatabaseHandler handler, String patientname, String view, JsonObject record) throws Exception{
		handler.connect();
		String command = "STORE " + patientname + " " + view + " " + record;
		handler.sendMessage(command);
		String message = handler.receiveMessage().getContent();
		String[] words = message.split("\\s+");
		String verificationSig = words[0];
		String toBeVerified = words[1];
		if (!CryptoLibrary.checkDigitalSignature(toBeVerified, verificationSig, databaseKey)) {
			throw new SecurityException("Digital Signature was not verified correctly, ignoring message");
		}
		if (words[1].equals("SUCCESS")) {
			System.out.println("Document successfuly created");
		}
		else {
			System.out.println("Something went wrong");
		}
		handler.closeConnection();
	}

	private static void deleteRecord(DatabaseHandler handler, String patientUsername) throws Exception {
		handler.connect();
		String command = "DELETE " + patientUsername;
		String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(command, serverPrivate));
		command = command + " " + signature;
		handler.sendMessage(command);
		String message = handler.receiveMessage().getContent();
		String[] words = message.split("\\s+");
		String verificationSig = words[0];
		String toBeVerified = words[1];
		if (!CryptoLibrary.checkDigitalSignature(toBeVerified, verificationSig, databaseKey)) {
			throw new SecurityException("Digital Signature was not verified correctly, ignoring message");
		}
		if (words[1].equals("SUCCESS")) {
			System.out.println("Document successfuly erased");
		}
		else {
			System.out.println("Something went wrong");
		}
		handler.closeConnection();
	}

    
    static class DatabaseHandler {
    	
    	private static DatabaseHandler INSTANCE;
    	private ObjectOutputStream outStream;
		private ObjectInputStream inStream;
	    private SSLSocket databaseSocket;
    	private int port;
    	
    	private DatabaseHandler(int port) {
    		this.port = port;
    	}
    	
    	public static DatabaseHandler getInstance(int port) {
    		if (INSTANCE == null)
    			return INSTANCE = new DatabaseHandler(port);

    		return INSTANCE;
    	}
    	
    	public void connect() {
    		SocketFactory fact = SSLSocketFactory.getDefault();
        	try {
        		
        		this.databaseSocket = (SSLSocket) fact.createSocket("192.168.1.1", this.port);
        		databaseSocket.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" });
        		databaseSocket.setEnabledProtocols(new String[] { "TLSv1.3" });

				outStream = new ObjectOutputStream(this.databaseSocket.getOutputStream());
				inStream = new ObjectInputStream(this.databaseSocket.getInputStream());

        		
        		System.out.println("Connected to Database");
        	} catch (Exception e) {
        		e.printStackTrace();
        	}
    	}
    	
    	public void sendMessage(String message) {
			try {
				Message messageToSend = new Message(message);
	            this.outStream.writeObject(messageToSend);
			} catch (Exception e) {
				e.printStackTrace();
			}
    	}
    	
    	public Message receiveMessage() {
    		Message message = null;
			try {
				message = (Message) inStream.readObject();
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			return message;
    	}
    	
    	public void closeConnection() {
    		try {
				this.outStream.close();
				this.inStream.close();
				this.databaseSocket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
    	}
    	
    	
    	
    }
   
}
