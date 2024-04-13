package domain.entities;

import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.net.ssl.SSLSocket;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import cryptoLib.CryptoLibrary;
import domain.Client;
import domain.utils.JsonManipulator;
import domain.utils.KeyReader;

public class Doctor {


	private String username;
	private PrivateKey doctorPrivate;
	private PublicKey doctorPublic;
	private PublicKey serverPublic;
	private String speciality;
	private String doctorKeyStore;
	private String doctorTrustStore;
	protected static final String KEYSTORES_DIR = "./src/newKeyStores";
	protected static final String SMITH_KEYSTORE = KEYSTORES_DIR + "/smithKeyStore";
	protected static final String SMITH_CERTIFICATE = KEYSTORES_DIR + "/smithRSApub.cer";
	protected static final String SMITH_TRUSTSTORE = KEYSTORES_DIR + "/smithTrustStore";
	protected static final String JONES_KEYSTORE = KEYSTORES_DIR + "/jonesKeyStore";
	protected static final String JONES_CERTIFICATE = KEYSTORES_DIR + "/jonesRSApub.cer";
	protected static final String JONES_TRUSTSTORE = KEYSTORES_DIR + "/jonesTrustStore";
	protected static final String SERVER_KEYSTORE = KEYSTORES_DIR + "/serverKeyStore";
	protected static final String SERVER_CERTIFICATE = KEYSTORES_DIR + "/serverRSApub.cer";
	protected static final String TRUSTSTORE_PASS = "123456";
	private static Scanner scanner;

	public Doctor() {}
	public Doctor(String username, PrivateKey privateKey, PublicKey publicKey, PublicKey serverPublic, String speciality) {
		this.username = username;
		this.doctorPrivate = privateKey;
		this.doctorPublic = publicKey;
		this.serverPublic = serverPublic;
		this.speciality = speciality;
		if (username.equals("Dr.Smith")) {
			doctorKeyStore = SMITH_KEYSTORE;
			doctorTrustStore = SMITH_TRUSTSTORE;
		}
		else {
			doctorKeyStore = JONES_KEYSTORE;
			doctorTrustStore = JONES_TRUSTSTORE;
		}
	}
	
	//mvn exec:java -Dexec.mainClass="domain.Doctor"
	public static void main(String argv[]) {
		System.out.println("\nWelcome to MediTrack, a medical records management system tailored for your convenience!");
		System.out.println("As a doctor in our network, you will be able to see, create and remove records, as well as add consultation records.");
		System.out.println("We guarentee the secure handling of your patient's data everywhere");
		System.out.print("\n");

		scanner = new Scanner(System.in);

		Boolean correctUser = false;
		Doctor doctor = new Doctor();
		while (!correctUser) {
			System.out.println("Choose your profile: ");
			System.out.println("1. Dr.Smith, Orthopedy");
			System.out.println("2. Dr.Jones, Emergency");
			System.out.print("\n>>>");
			String doctorChoice = scanner.nextLine();
			if (!doctorChoice.equals("1") && !doctorChoice.equals("2")) {
				System.out.println("Incorrect profile, try again\n");
			}
			else {
				try {
					PrivateKey doctorPrivateKey;
					PublicKey doctorPublicKey;
					PublicKey serverPublic = getServerPublic();
					if (doctorChoice.equals("1")) {
						System.out.println("Welcome Dr. Smith!");
						doctorPrivateKey = getDoctorPrivate("Dr.Smith");
						doctorPublicKey = getDoctorPublic("Dr.Smith");
						doctor = new Doctor("Dr.Smith", doctorPrivateKey, doctorPublicKey, serverPublic, "Orthopedy");
					}
					else {
						System.out.println("Welcome Dr. Jones!");
						doctorPrivateKey = getDoctorPrivate("Dr.Jones");
						doctorPublicKey = getDoctorPublic("Dr.Jones");
						doctor = new Doctor("Dr.Jones", doctorPrivateKey, doctorPublicKey, serverPublic, "Emergency");
					}
					correctUser = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					return;
				}
			}
		}

		while (true) {
			System.out.println("Enter a number to choose the desired operation:"); 
			System.out.println("1. Search Record");
			System.out.println("2. Create Record");
			System.out.println("3. Remove Record");
			System.out.println("4. Add Consultation Record\n");
			System.out.print(">>> ");
			String choice = scanner.nextLine();
			try {
				switch(choice) {
					case "1":
						System.out.print("Enter patient's username: ");
						String patientChoice = scanner.nextLine();
						System.out.println("\nIn what way do you want to see the record:");
						System.out.println("1. Public View");
						System.out.println("2. Authorized View");
						System.out.println("3. Emergency View");
						System.out.print(">>> ");
						String viewChoice = scanner.nextLine();
						switch(viewChoice) {
							case "1":
								doctor.publicConsult(patientChoice);
								break;
							case "2":
								doctor.authorizedConsult(patientChoice);
								break;
							case "3":
								doctor.emergencyConsult(patientChoice);
								break;
						}
						break;
					case "2":
						JsonObject record = doctor.createRecordJson();
						doctor.handleCreateRecord(record);
						break;
					case "3":
						System.out.print("Enter patient's username: ");
						String name = scanner.nextLine();
						doctor.deleteRecord(name);
						break;
					case "4":
						System.out.print("Enter patient's username: ");
						String patientName = scanner.nextLine();
						JsonObject consult = doctor.createConsultJson(patientName);
						Gson gson = new GsonBuilder().setPrettyPrinting().create();
						String formattedJson = gson.toJson(consult);
						System.out.println("\n" + formattedJson);
						doctor.addConsult(consult);
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

	public static PublicKey getDoctorPublic(String name) throws Exception {
		PublicKey doctorPub;
		if (name.equals("Dr.Smith")) {
			doctorPub = KeyReader.readPublicKey(SMITH_CERTIFICATE);
		}
		else {
			doctorPub = KeyReader.readPublicKey(JONES_CERTIFICATE);
		}

        return doctorPub;
	}

	public static PrivateKey getDoctorPrivate(String name) throws Exception {
		PrivateKey doctorPri;
		if (name.equals("Dr.Smith")) {
			doctorPri = KeyReader.readPrivateKey(SMITH_KEYSTORE, TRUSTSTORE_PASS, "doctorKeys");
		}
		else {
			doctorPri = KeyReader.readPrivateKey(JONES_KEYSTORE, TRUSTSTORE_PASS, "doctorKeys");
		}
		
        return doctorPri;
	}

	public static PublicKey getServerPublic() throws Exception {
		return KeyReader.readPublicKey(SERVER_CERTIFICATE);
	}

	private JsonObject createRecordJson() {
		JsonObject record = new JsonObject();
		JsonObject patientData = new JsonObject();
		String input;
		List<String> fields = Arrays.asList("name", "sex", "dateOfBirth", "C.C.", "NIF", "insuranceCompany", "address", "phoneNumber", "e-mail", "emergencyPhoneNumber", "bloodType");
		List<String> printFields = Arrays.asList("name", "sex", "date of birth", "C.C.", "NIF", "insurance Company", "address", "phone number", "e-mail", "emergency phone number", "blood type");
		for (int i = 0; i < fields.size(); i++) {
			System.out.print("\nInsert patient's " + printFields.get(i) + ": ");
			input = scanner.nextLine();
			patientData.addProperty(fields.get(i), input);
		}
		fields = Arrays.asList("knownAllergies", "knownIllnesses");
		printFields = Arrays.asList("known allergies", "known illnesses");
		for (int i = 0; i < fields.size(); i++) {
			System.out.print("\nInsert patient's " + printFields.get(i) + " (put spaces in between each): ");
			input = scanner.nextLine();
			String[] words = input.split("\\s+");
			JsonArray jsonArray = new JsonArray();
			for (String element : words) {
				jsonArray.add(new JsonPrimitive(element));
			}
			patientData.add(fields.get(i), jsonArray);
		}
		patientData.add("consultationRecords", new JsonArray());
		record.add("patient", patientData);
		return record;
	}

	private void handleCreateRecord(JsonObject record) throws Exception {
		String command = "CREATE ";
		JsonManipulator.writeJsonToFile(record, "./created.json");
		CryptoLibrary.addKey(false, KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "aux");
		Key auxKey = KeyReader.readSecretKey(KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "aux");
		String cypheredKey = CryptoLibrary.cypherKey(auxKey, serverPublic);
		command += cypheredKey;
		CryptoLibrary.removeKey(KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "aux");

		CryptoLibrary.protect("./created.json", "./created.json", 0, 1, auxKey, 0, doctorPrivate);
		CryptoLibrary.protect("./created.json", "./created.json", 1, 1, auxKey, 0, doctorPrivate);
		CryptoLibrary.protect("./created.json", "./created.json", 0, 4, auxKey, 0, doctorPrivate);
		CryptoLibrary.addSecurityMeasures("./created.json", "./created.json", doctorPrivate, username);
		FileReader fileReader = new FileReader("./created.json");
        JsonObject readJson = new Gson().fromJson(fileReader, JsonObject.class);

		command = command + " " + readJson.toString();
		SSLSocket socket = Client.startDoctor(doctorKeyStore, doctorTrustStore);
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
			System.out.println("Record created successfully!\n");
		}
		else {
			System.out.println("Error during operation, max user limit may have been reached\n");
		}

		Path path = Paths.get("./created.json");
		Files.delete(path);
	}

	private void deleteRecord(String name) throws Exception {
		String command = "DELETE " + username + " " + name;
		String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(command, doctorPrivate));
		command = command + " " + signature;

		SSLSocket socket = Client.startDoctor(doctorKeyStore, doctorTrustStore);
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
			System.out.println("Record successfully erased!\n");
		}
		else {
			System.out.println("Error during operation, patient username may not exist yet\n");
		}
	}

	private JsonObject createConsultJson(String patientName) throws Exception {
		JsonObject record = new JsonObject();
		JsonObject patient = new JsonObject();
		JsonObject consult = new JsonObject();
		consult.addProperty("doctorName", username);
		consult.addProperty("medicalSpeciality", speciality);
		String input;
		List<String> fields = Arrays.asList("date", "practice", "treatmentSummary", "treatmentCost", "paymentDestination");
		List<String> printFields = Arrays.asList("date", "practice facility", "treatment summary", "treatment cost", "payment destination");
		for (int i = 0; i < fields.size(); i++) {
			System.out.print("\nInsert consult's " + printFields.get(i) + ": ");
			input = scanner.nextLine();
			consult.addProperty(fields.get(i), input);
		}
		
		patient.addProperty("name", patientName);
		JsonArray consultArray = new JsonArray();
		consultArray.add(consult);
		patient.add("consultationRecords", consultArray);
		record.add("patient", patient);
		return record;
	}

	private void addConsult(JsonObject consult) throws Exception {
		String command = "ADD ";
		JsonManipulator.writeJsonToFile(consult, "./created.json");
		CryptoLibrary.addKey(false, KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "aux");
		Key auxKey = KeyReader.readSecretKey(KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "aux");
		String cypheredKey = CryptoLibrary.cypherKey(auxKey, serverPublic);
		command += cypheredKey;
		CryptoLibrary.removeKey(KEYSTORES_DIR + "/auxKeys", TRUSTSTORE_PASS, "aux");

		CryptoLibrary.protect("./created.json", "./created.json", 2, 1, auxKey, 1, doctorPrivate);
		CryptoLibrary.protect("./created.json", "./created.json", 3, 1, auxKey, 0, doctorPrivate);
		CryptoLibrary.addSecurityMeasures("./created.json", "./created.json", doctorPrivate, username);
		FileReader fileReader = new FileReader("./created.json");
        JsonObject readJson = new Gson().fromJson(fileReader, JsonObject.class);

		command = command + " " + readJson.toString();
		SSLSocket socket = Client.startDoctor(doctorKeyStore, doctorTrustStore);
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
			System.out.println("Consult record added successfully!\n");
		}
		else {
			System.out.println("Error during operation, patient may not be yet in the system\n");
		}

		Path path = Paths.get("./created.json");
		Files.delete(path);
	}

	private void publicConsult(String patientName) throws Exception {
		String command = "CONSULT DOCTOR PUBLIC " + patientName + " " + username;
		String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(command, doctorPrivate));
		command = command + " " + signature;
		
		SSLSocket socket = Client.startPatient();
		Client.sendMessage(command, socket);
		String received = Client.receiveMessage(socket);
		socket.close();

		String[] words = received.split("\\s+");
		if (words[0].equals("ERROR")) {
			if (!CryptoLibrary.checkDigitalSignature(words[0], words[1], serverPublic)) {
				throw new SecurityException("Digital Signature was not verified correctly, message isn't trusted");
			}
			else {
				System.out.println("Error during operation, patient username may not exist yet in the system");
				return;
			}
		}

		String keyString = words[0];
		Key receivedSecret = CryptoLibrary.decypherKey(keyString, doctorPrivate);
		int firstIndex = received.indexOf(' ');
		String record = received.substring(firstIndex + 1);
		JsonObject rootJson = JsonParser.parseString(record).getAsJsonObject();
		JsonManipulator.writeJsonToFile(rootJson, "./received.json");
		Map<String, PublicKey> systemPublicKeys = new HashMap<String, PublicKey>();
		systemPublicKeys.put("Server", serverPublic);
		if(!CryptoLibrary.check("./received.json", systemPublicKeys)) {
			throw new SecurityException("Check was not fulfilled!");
		}

		CryptoLibrary.unprotect("./received.json", "./unprotected.json", 1, 2, 1, receivedSecret);

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

	private void authorizedConsult(String patientName) throws Exception {
		String command = "CONSULT DOCTOR AUTH " + patientName + " " + username;
		String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(command, doctorPrivate));
		command = command + " " + signature;
		
		SSLSocket socket = Client.startPatient();
		Client.sendMessage(command, socket);
		String received = Client.receiveMessage(socket);
		socket.close();

		String[] words = received.split("\\s+");
		if (words[0].equals("ERROR")) {
			if (!CryptoLibrary.checkDigitalSignature(words[0], words[1], serverPublic)) {
				throw new SecurityException("Digital Signature was not verified correctly, message isn't trusted");
			}
			else {
				System.out.println("Error during operation, doctor may not have authorization to see patient's record");
				return;
			}
		}

		String keyString = words[0];
		Key receivedSecret = CryptoLibrary.decypherKey(keyString, doctorPrivate);
		int firstIndex = received.indexOf(' ');
		String record = received.substring(firstIndex + 1);
		JsonObject rootJson = JsonParser.parseString(record).getAsJsonObject();
		JsonManipulator.writeJsonToFile(rootJson, "./received.json");
		Map<String, PublicKey> systemPublicKeys = new HashMap<String, PublicKey>();
		systemPublicKeys.put("Server", serverPublic);
		if(!CryptoLibrary.check("./received.json", systemPublicKeys)) {
			throw new SecurityException("Check was not fulfilled!");
		}

		CryptoLibrary.unprotect("./received.json", "./unprotected.json", 1, 1, 1, receivedSecret);
		CryptoLibrary.unprotect("./unprotected.json", "./unprotected.json", 0, 2, 1, receivedSecret);

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

	private void emergencyConsult(String patientName) throws Exception {
		String command = "CONSULT DOCTOR ER " + patientName + " " + username;
		String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(command, doctorPrivate));
		command = command + " " + signature;
		
		SSLSocket socket = Client.startPatient();
		Client.sendMessage(command, socket);
		String received = Client.receiveMessage(socket);
		socket.close();

		String[] words = received.split("\\s+");
		if (words[0].equals("ERROR")) {
			if (!CryptoLibrary.checkDigitalSignature(words[0], words[1], serverPublic)) {
				throw new SecurityException("Digital Signature was not verified correctly, message isn't trusted");
			}
			else {
				System.out.println("Error during operation, doctor may not have emergency authorization");
				return;
			}
		}

		String keyString = words[0];
		Key receivedSecret = CryptoLibrary.decypherKey(keyString, doctorPrivate);
		int firstIndex = received.indexOf(' ');
		String record = received.substring(firstIndex + 1);
		JsonObject rootJson = JsonParser.parseString(record).getAsJsonObject();
		JsonManipulator.writeJsonToFile(rootJson, "./received.json");
		Map<String, PublicKey> systemPublicKeys = new HashMap<String, PublicKey>();
		systemPublicKeys.put("Server", serverPublic);
		if(!CryptoLibrary.check("./received.json", systemPublicKeys)) {
			throw new SecurityException("Check was not fulfilled!");
		}

		CryptoLibrary.unprotect("./received.json", "./unprotected.json", 1, 0, 1, receivedSecret);
		CryptoLibrary.unprotect("./unprotected.json", "./unprotected.json", 0, 1, 1, receivedSecret);
		CryptoLibrary.unprotect("./unprotected.json", "./unprotected.json", 0, 2, 1, receivedSecret);
		CryptoLibrary.unprotect("./unprotected.json", "./unprotected.json", 0, 3, 1, receivedSecret);
		CryptoLibrary.unprotect("./unprotected.json", "./unprotected.json", 0, 4, 1, receivedSecret);

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

}
