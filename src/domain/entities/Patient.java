package domain.entities;

import java.util.Scanner;
import java.util.Map;
import java.util.HashMap;
import java.util.Base64;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.FileReader;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.net.ssl.SSLSocket;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;

import domain.Client;
import domain.utils.JsonManipulator;
import domain.utils.KeyReader;


import cryptoLib.CryptoLibrary;

public class Patient {

	private String username;
	private PrivateKey patientPrivate;
	private PublicKey patientPublic;
	private PublicKey serverPublic;
	private Map<String, PublicKey> systemPublicKeys;
	protected static final String KEYSTORES_DIR = "./src/newKeyStores";
	protected static final String PATIENT_KEYSTORE = KEYSTORES_DIR + "/patientKeyStore";
	protected static final String PATIENT_TRUSTSTORE = KEYSTORES_DIR + "/patientTrustStore";
	protected static final String PATIENT_CERTIFICATE = KEYSTORES_DIR + "/patientRSApub.cer";
	protected static final String SERVER_KEYSTORE = KEYSTORES_DIR + "/serverKeyStore";
	protected static final String SERVER_CERTIFICATE = KEYSTORES_DIR + "/serverRSApub.cer";
	protected static final String TRUSTSTORE_PASS = "123456";

	public Patient(String username, PrivateKey privateKey, PublicKey publicKey, PublicKey serverPublic) {
		this.username = username;
		this.patientPrivate = privateKey;
		this.patientPublic = publicKey;
		this.serverPublic = serverPublic;
	}

	// mvn exec:java -Dexec.mainClass="domain.Patient"
	public static void main(String argv[]) {
		System.out.println("\nWelcome to MediTrack, a medical records management system tailored for your convenience!");
		System.out.println("As a patient in our network, you will be able to see and grant access permissions to your medical record.");
		System.out.println("Don't worry, we guarantee absolute confidentiality of your record, as well as proper authentication of your doctor's appointments");

		Scanner scanner = new Scanner(System.in);

		System.out.print("Enter username: ");
		String username = scanner.nextLine(); 

		Patient patient;
		try {
			PrivateKey patientPrivate = getPatientPrivate();
			PublicKey patientPublic = getPatientPublic();
			PublicKey serverPublic = getServerPublic();

			patient = new Patient(username, patientPrivate, patientPublic, serverPublic);
			patient.getOtherPublics();
		}
		catch (Exception e) {
			e.printStackTrace();
			return;
		}

		while (true) {
			System.out.println("Enter a number to choose the desired operation:"); 
			System.out.println("1. See record");
			System.out.println("2. Grant Access\n");
			System.out.print(">>> ");
			String choice = scanner.nextLine();
			try {
				switch(choice) {
					case "1":
						patient.getAndPrintRecord();
						break;
					case "2":
						System.out.println("What type of user do you want to grant access?");
						System.out.println("1. Doctor?");
						System.out.println("2. Insurance Company?");
						System.out.print(">>> ");
						String type = scanner.nextLine();
						if (type.equals("1")) {
							System.out.print("Enter doctor name: ");
							String name = scanner.nextLine();
							patient.grantAccess(0, name);
						}
						else if (type.equals("2")) {
							System.out.print("Enter insurance company name: ");
							String name = scanner.nextLine();
							patient.grantAccess(1, name);
						}
						else {
							System.out.println("Wrong input received");
						}
						break;
					default:
						System.out.println("Wrong input received");
				}
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	public static PublicKey getPatientPublic() throws Exception {
        return KeyReader.readPublicKey(PATIENT_CERTIFICATE);
	}

	public static PrivateKey getPatientPrivate() throws Exception {
		return KeyReader.readPrivateKey(PATIENT_KEYSTORE, TRUSTSTORE_PASS, "patientKeys");
	}

	public static PublicKey getServerPublic() throws Exception {
		return KeyReader.readPublicKey(SERVER_CERTIFICATE);
	}

	private void setSystemKeys(Map<String, PublicKey> systemKeys) {
		this.systemPublicKeys = systemKeys;
	}

	private void getOtherPublics() throws Exception {
		String command = "PUBKEYS PATIENT ";
		command += username;
		String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(command, patientPrivate));
		System.out.println(command);
		command = command + " " + signature;

		SSLSocket socket = Client.startPatient();
		Client.sendMessage(command, socket);
		String received = Client.receiveMessage(socket);
		socket.close();
		String[] words = received.split("\\s+");
		if (words[1].equals("ERROR")) {
			System.out.println("User non existent in our system, closing app");
			System.exit(0);
		}

		int spaceIndex = received.indexOf(' ');
		spaceIndex = received.indexOf(' ', spaceIndex + 1);
		String message = received.substring(spaceIndex + 1);
		String returnedSignature = words[0];
		if (!CryptoLibrary.checkDigitalSignature(message, returnedSignature, serverPublic)) {
			throw new SecurityException("Digital Signature was not verified correctly, ignoring message");
		}
		
		Map<String, PublicKey> keys = new HashMap<String, PublicKey>();
		for (int i = 2; i < words.length; i+=2) {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(words[i+1]));
        	PublicKey docPub = keyFactory.generatePublic(publicKeySpec);
			keys.put(words[i], docPub);
		}
		keys.put("Server", serverPublic);
		setSystemKeys(keys);
	}

	private void getAndPrintRecord() throws Exception {
		String command = "CONSULT PATIENT";
		String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(command, patientPrivate));
		command = command + " " + signature;
		
		SSLSocket socket = Client.startPatient();
		Client.sendMessage(command, socket);
		String received = Client.receiveMessage(socket);
		socket.close();

		JsonObject rootJson = JsonParser.parseString(received).getAsJsonObject();
		JsonManipulator.writeJsonToFile(rootJson, "./received.json");
		if(!CryptoLibrary.check("./received.json", systemPublicKeys)) {
			throw new SecurityException("Check was not fulfilled!");
		}

		CryptoLibrary.unprotect("./received.json", "./unprotected.json", 1, 0, 0, patientPrivate);
		CryptoLibrary.unprotect("./unprotected.json", "./unprotected.json", 0, 1, 0, patientPrivate);
		CryptoLibrary.unprotect("./unprotected.json", "./unprotected.json", 0, 2, 0, patientPrivate);
		CryptoLibrary.unprotect("./unprotected.json", "./unprotected.json", 0, 3, 0, patientPrivate);
		CryptoLibrary.unprotect("./unprotected.json", "./unprotected.json", 0, 4, 0, patientPrivate);

		if (!CryptoLibrary.checkAuthenticity("./unprotected.json", systemPublicKeys)) {
			throw new SecurityException("Doctor signatures could not be verified!");
		}

		FileReader fileReader = new FileReader("./unprotected.json");
        JsonObject readJson = new Gson().fromJson(fileReader, JsonObject.class);
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		String formattedJson = gson.toJson(readJson);
		
		System.out.println("Here is your record");
		System.out.println("-------------------------------------------------------------------------------------\n");
		System.out.println(formattedJson);
		System.out.println("\n-------------------------------------------------------------------------------------");

		Path path = Paths.get("./received.json");
		Files.delete(path);
		path = Paths.get("./unprotected.json");
		Files.delete(path);
	}

	private void grantAccess(int type, String name) throws Exception {
		String command = "GRANT";
		if (type == 0) {     // Doctor
			command += " DOCTOR " + name;
		}
		else {   // Insurance
			command += " INSURANCE " + name;
		}

		String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(command, patientPrivate));
		command = command + " " + signature;

		SSLSocket socket = Client.startPatient();
		Client.sendMessage(command, socket);
		String received = Client.receiveMessage(socket);
		socket.close();

		int spaceIndex = received.indexOf(' ');
		String message = received.substring(spaceIndex + 1);
		String[] words = received.split("\\s+");
		String returnedSignature = words[0];
		if (!CryptoLibrary.checkDigitalSignature(message, returnedSignature, serverPublic)) {
			throw new SecurityException("Digital Signature was not verified correctly, message isn't trusted");
		}

		if (words[1].equals("SUCCESS")) {
			System.out.println("Authorization granted!\n");
		}
		else {
			System.out.println("Error during operation, try again please\n");
		}
	}

}
