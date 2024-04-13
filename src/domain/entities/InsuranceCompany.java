package domain.entities;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.net.ssl.SSLSocket;

import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import domain.utils.KeyReader;
import java.security.Key;
import java.security.KeyFactory;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import cryptoLib.CryptoLibrary;
import domain.Client;
import domain.utils.JsonManipulator;

public class InsuranceCompany {

	private String username;
	private PrivateKey insurancePrivate;
	private PublicKey insurancePublic;
	private PublicKey serverPublic;
	private Map<String, PublicKey> systemPublicKeys;
	protected static final String KEYSTORES_DIR = "./src/newKeyStores";
	protected static final String INSURANCE_KEYSTORE = KEYSTORES_DIR + "/insuranceKeyStore";
	protected static final String INSURANCE_TRUSTSTORE = KEYSTORES_DIR + "/insuranceTrustStore";
	protected static final String INSURANCE_CERTIFICATE = KEYSTORES_DIR + "/insuranceRSApub.cer";
	protected static final String SERVER_KEYSTORE = KEYSTORES_DIR + "/serverKeyStore";
	protected static final String SERVER_CERTIFICATE = KEYSTORES_DIR + "/serverRSApub.cer";
	protected static final String TRUSTSTORE_PASS = "123456";

	public InsuranceCompany(String username, PrivateKey privateKey, PublicKey publicKey, PublicKey serverPublic) {
		this.username = username;
		this.insurancePrivate = privateKey;
		this.insurancePublic = publicKey;
		this.serverPublic = serverPublic;
	}
	
	//mvn exec:java -Dexec.mainClass="domain.InsuranceCompany"
	public static void main(String argv[]) {
		System.out.println("\nWelcome to MediTrack, a medical records management system tailored for your convenience!");
		System.out.println("As an insurance company in our network, you will be able to see the medical records of your clients.");
		System.out.println("We guarantee confidentiality and authenticity of all information handled");

		Scanner scanner = new Scanner(System.in);

		Boolean correctUser = false;
		while (!correctUser) {
			System.out.println("Choose your profile: ");
			System.out.println("1. Freedom");
			System.out.print("\n>>>");
			String doctorChoice = scanner.nextLine();
			if (!doctorChoice.equals("1")) {
				System.out.println("Incorrect profile, try again\n");
			}
			else {
				correctUser = true;
			}
		} 

		InsuranceCompany insuranceCompany;
		try {
			PrivateKey insurancePrivate = getInsurancePrivate();
			PublicKey insurancePublic = getInsurancePublic();
			PublicKey serverPublic = getServerPublic();

			insuranceCompany = new InsuranceCompany("Freedom", insurancePrivate, insurancePublic, serverPublic);
			insuranceCompany.getOtherPublics();
		}
		catch (Exception e) {
			e.printStackTrace();
			return;
		}

		while (true) {
			System.out.println("Enter a number to choose the desired operation:"); 
			System.out.println("1. See record");
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
						System.out.print(">>> ");
						String viewChoice = scanner.nextLine();
						switch(viewChoice) {
							case "1":
								insuranceCompany.publicConsult(patientChoice);
								break;
							case "2":
								insuranceCompany.authorizedConsult(patientChoice);
								break;
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

	public static PublicKey getInsurancePublic() throws Exception {
        return KeyReader.readPublicKey(INSURANCE_CERTIFICATE);
	}

	public static PrivateKey getInsurancePrivate() throws Exception {
		return KeyReader.readPrivateKey(INSURANCE_KEYSTORE, TRUSTSTORE_PASS, "insuranceKeys");
	}

	public static PublicKey getServerPublic() throws Exception {
		return KeyReader.readPublicKey(SERVER_CERTIFICATE);
	}

	private void setSystemKeys(Map<String, PublicKey> systemKeys) {
		this.systemPublicKeys = systemKeys;
	}

	private void getOtherPublics() throws Exception {
		String command = "PUBKEYS INSURANCE";
		String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(command, insurancePrivate));
		System.out.println(command);
		command = command + " " + signature;

		SSLSocket socket = Client.startInsurance();
		Client.sendMessage(command, socket);
		String received = Client.receiveMessage(socket);
		socket.close();
		String[] words = received.split("\\s+");

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

	private void publicConsult(String patientName) throws Exception {

		String command = "CONSULT INSURANCE PUBLIC " + patientName;
		String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(command, insurancePrivate));
		command = command + " " + signature;
		
		SSLSocket socket = Client.startInsurance();
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

		JsonObject rootJson = JsonParser.parseString(received).getAsJsonObject();
		JsonManipulator.writeJsonToFile(rootJson, "./received.json");
		if(!CryptoLibrary.check("./received.json", systemPublicKeys)) {
			throw new SecurityException("Check was not fulfilled!");
		}

		CryptoLibrary.unprotect("./received.json", "./unprotected.json", 1, 3, 0, insurancePrivate);
		CryptoLibrary.unprotect("./unprotected.json", "./unprotected.json", 0, 4, 0, insurancePrivate);

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

	private void authorizedConsult(String patientName) throws Exception{
		String command = "CONSULT INSURANCE AUTH " + patientName;
		String signature = Base64.getEncoder().encodeToString(CryptoLibrary.generateDigitalSignature(command, insurancePrivate));
		command = command + " " + signature;
		
		SSLSocket socket = Client.startInsurance();
		Client.sendMessage(command, socket);
		String received = Client.receiveMessage(socket);
		socket.close();

		String[] words = received.split("\\s+");
		if (words[0].equals("ERROR")) {
			if (!CryptoLibrary.checkDigitalSignature(words[0], words[1], serverPublic)) {
				throw new SecurityException("Digital Signature was not verified correctly, message isn't trusted");
			}
			else {
				System.out.println("Error during operation, insurance company may not have permission to access patient's information");
				return;
			}
		}

		String keyString = words[0];
		Key receivedSecret = CryptoLibrary.decypherKey(keyString, insurancePrivate);
		int firstIndex = received.indexOf(' ');
		String record = received.substring(firstIndex + 1);
		JsonObject rootJson = JsonParser.parseString(record).getAsJsonObject();
		JsonManipulator.writeJsonToFile(rootJson, "./received.json");
		if(!CryptoLibrary.check("./received.json", systemPublicKeys)) {
			throw new SecurityException("Check was not fulfilled!");
		}

		CryptoLibrary.unprotect("./received.json", "./unprotected.json", 1, 1, 1, receivedSecret);
		CryptoLibrary.unprotect("./unprotected.json", "./unprotected.json", 0, 3, 0, insurancePrivate);
		CryptoLibrary.unprotect("./unprotected.json", "./unprotected.json", 0, 4, 0, insurancePrivate);

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