package cryptoLib;

import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.JsonObject;
import domain.utils.Encryption;
import domain.utils.JsonManipulator;
import domain.utils.KeyReader;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonPrimitive;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class CryptoLibrary {

    private static List<String> arrayFields = List.of("knownAllergies", "knownIllnesses");
    private static Long maxTimeDifference = (long) 500000;    // 50 segundos
    private static Map<Long, Long> nonceMap = new HashMap<Long, Long>();
    private static Map<String, PublicKey> demoMap = new HashMap<String, PublicKey>();
    private static PrivateKey patientPrivate;
    private static PublicKey patientPublic;
    private static PrivateKey doctorPrivate;
    private static PublicKey doctorPublic;
    private static PrivateKey insurancePrivate;
    private static PublicKey insurancePublic;
    private static Key orthopedyKey;
    private static Key urgencyKey;
    private static Key dermathologyKey;

    // mvn exec:java -Dexec.mainClass="cryptoLib.CryptoLib"
    public static void main(String argv[]) {
        try {
            loadDemoKeys();
            System.out.println("Welcome to CryptoLib, a cryptography library meant for MediTrack's record management system!");
            printHelp();

            Scanner scanner = new Scanner(System.in);

            while (true) {
                System.out.print(">>> ");
                String userInput = scanner.nextLine();

                String[] words = userInput.split("\\s+");

                if (words[0].equals("CryptoLib")) {
                    if (words[1].equals("help")) {
                        interpretHelp(words);
                    }
                    else if (words[1].equals("protect")) {
                        interpretProtect(words);
                    }
                    else if (words[1].equals("check")) {
                        interpretCheck(words);
                    }
                    else if (words[1].equals("unprotect")) {
                        interpretUnprotect(words);
                    }
                    else if (words[1].equals("addSecurity")) {
                        interpretAddSecurity(words);
                    }
                    else if (words[1].equals("exit")) {
                        break;
                    }
                    else {
                        System.out.println("Error: command not found");
                        printHelp();
                    }
                }
                else {
                    System.out.println("Error: first word of command should always be CryptoLib");
                    printHelp();
                }
            }
            System.out.println("\nSee you next time!");
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void loadDemoKeys() throws Exception {
        String demo_pass = "demokeys";
	    String demo_path = "./src/newKeyStores/demoTrustStore";
        String cert_path = "./src/newKeyStores/demoCertificates";

        patientPrivate = KeyReader.readPrivateKey(demo_path, demo_pass, "patientKeys");
        patientPublic = KeyReader.readPublicKey(cert_path + "/patientRSApub.cer");

        doctorPrivate = KeyReader.readPrivateKey(demo_path, demo_pass, "doctorKeys");
        doctorPublic = KeyReader.readPublicKey(cert_path + "/doctorRSApub.cer");

        insurancePrivate = KeyReader.readPrivateKey(demo_path, demo_pass, "insuranceKeys");
        insurancePublic = KeyReader.readPublicKey(cert_path + "/insuranceRSApub.cer");

        orthopedyKey = KeyReader.readSecretKey(demo_path, demo_pass, "orthopedicKey");
        urgencyKey = KeyReader.readSecretKey(demo_path, demo_pass, "urgencyKey");
        dermathologyKey = KeyReader.readSecretKey(demo_path, demo_pass, "dermathologyKey");

        demoMap.put("Dr.Smith", doctorPublic);
    }

    private static void printHelp() {
        System.out.println("--- CriptoLib Usage ---");
        System.out.println("CryptoLib help [command name] -> Shows tool and command usage");
        System.out.println("CryptoLib protect <input-file> <output-file> <fields> <cypher-type> <cypher-key> <sign> <signature-key> - Add security to a document."); 
        System.out.println("CryptoLib check <input-file> - Verifies security of a document.");
        System.out.println("CryptoLib unprotect <input-file> <output-file> <remove-checks> <fields> <cypher-type> <decypher-key> - Removes security from a document.");
        System.out.println("CryptoLib addSecurity <input-file> <output-file> <signature-key> <signer-name> - Adds integrity and freshness mechanisms to the file");
        System.out.println("CryptoLib exit - exits the program\n");
    }

    private static void interpretHelp(String[] words) {

        if (words.length == 2) {
            printHelp();
        }
        else if (words.length == 3) {
            if (words[2].equals("protect")) {
                printProtectHelp();
            }
            else if (words[2].equals("check")) {
                printCheckHelp();
            }
            else if (words[2].equals("unprotect")) {
                printUnprotectHelp();
            }
            else if (words[2].equals("addSecurity")) {
                printAddSecurityHelp();
            }
            else {
                System.out.println("Error: command given doesn't exist or does not need further explanation");
                printHelp();
            }
        }
        else {
            System.out.println("Error: wrong arguments for help");
            printHelp();
        }
    }

    private static void interpretCheck(String[] words) throws Exception {
        if (words.length == 3) {
            Path path = Paths.get(words[2]);
            if (!Files.exists(path)) {
                System.out.println("Error: file does not exist");
                return;
            }
            else {
                check(words[2], demoMap);
            }

        }
        else {
            System.out.println("Error: wrong arguments for check");
            printCheckHelp();
        }
    }

    private static void interpretProtect(String[] words) throws Exception {
        if (checkProtectArgs(words)) {
            int fields = interpretFields(words[4]);
            int method = interpretMethod(words[5]);
            Key key = interpretKey(words[6]);
            int sign = interpretSign(words[7]);
            PrivateKey signKey = (PrivateKey) interpretKey(words[8]);

            protect(words[2], words[3], fields, method, key, sign, signKey);
        }
    }

    private static void interpretUnprotect(String[] words) throws Exception {
        if (checkUnprotectArgs(words)) {
            int remove = interpretRemove(words[4]);
            int fields = interpretFields(words[5]);
            int method = interpretMethod(words[6]);
            Key key = interpretKey(words[7]);
            unprotect(words[2], words[3], remove, fields, method, key);
        }
    }

    private static void interpretAddSecurity(String[] words) throws Exception {
        if (checkAddSecurityArgs(words)) {
            PrivateKey signKey = (PrivateKey) interpretKey(words[4]);
            addSecurityMeasures(words[2], words[3], signKey, words[5]);
        }
    }

    private static int interpretRemove(String remove) {
        if (remove.equals("remove")) {
            return 1;
        }
        else {
            return 0;
        }
    }

    private static int interpretFields(String fields) {
        if (fields.equals("personal")) {
            return 0;
        }
        else if (fields.equals("urgent")) {
            return 1;
        }
        else if (fields.equals("record")) {
            return 2;
        }
        else if (fields.equals("financialRecords")){
            return 3;
        }
        else {
            return 4;
        }
    }

    private static int interpretMethod(String method) {
        if (method.equals("a")) {
            return 0;
        }
        else {
            return 1;
        }
    }

    private static int interpretSign(String sign) {
        if (sign.equals("yes")) {
            return 1;
        }
        else {
            return 0;
        }
    }

    private static Key interpretKey(String key) {
        if (key.equals("ppublic")) {
            return patientPublic;
        }
        else if (key.equals("pprivate")) {
            return patientPrivate;
        }
        else if (key.equals("dpublic")) {
            return doctorPublic;
        }
        else if (key.equals("dprivate")) {
            return doctorPrivate;
        }
        else if (key.equals("ipublic")) {
            return insurancePublic;
        }
        else if (key.equals("iprivate")) {
            return insurancePrivate;
        }
        else if (key.equals("esym")) {
            return urgencyKey;
        }
        else if (key.equals("osym")) {
            return orthopedyKey;
        }
        else {
            return dermathologyKey;
        }
    }

    private static Boolean checkProtectArgs(String[] words) {
        if (words.length == 9) {
            Path path1 = Paths.get(words[2]);
            Path path2 = Paths.get(words[3]);
            if (!Files.exists(path1)) {
                System.out.println("Error: file does not exist");
                return false;
            }

            if (!words[4].equals("personal") && !words[4].equals("urgent") && !words[4].equals("record") && !words[4].equals("financialRecords") && !words[4].equals("financial")) {
                System.out.println("Error: wrong arguments for protect");
                printProtectHelp();
                return false;
            }
            
            if (words[5].equals("a")) {
                if (!words[6].equals("ppublic") && !words[6].equals("dpublic") && !words[6].equals("ipublic")) {
                    System.out.println("Error: wrong arguments for protect");
                    printProtectHelp();
                    return false;
                }
            }
            else if (words[5].equals("s")) {
                if (!words[6].equals("esym") && !words[6].equals("osym") && !words[6].equals("dsym")) {
                    System.out.println("Error: wrong arguments for protect");
                    printProtectHelp();
                    return false;
                }
            }
            else {
                System.out.println("Error: wrong arguments for protect");
                printProtectHelp();
                return false;
            }

            if (!words[7].equals("yes") && !words[7].equals("no")) {
                System.out.println("Error: wrong arguments for protect");
                printProtectHelp();
                return false;
            }

            if (!words[8].equals("pprivate") && !words[8].equals("dprivate") && !words[8].equals("iprivate")) {
                System.out.println("Error: wrong arguments for protect");
                printProtectHelp();
                return false;
            }

            return true;

        }
        else {
            System.out.println("Error: wrong arguments for protect");
            printProtectHelp();
            return false;
        }
    }

    private static Boolean checkUnprotectArgs(String[] words) {
        if (words.length == 8) {
            Path path1 = Paths.get(words[2]);
            Path path2 = Paths.get(words[3]);
            if (!Files.exists(path1)) {
                System.out.println("Error: file does not exist");
                return false;
            }

            if (!words[4].equals("remove") && !words[4].equals("keep")) {
                System.out.println("Error: wrong arguments for unprotect");
                printUnprotectHelp();
                return false;
            }

            if (!words[5].equals("personal") && !words[5].equals("urgent") && !words[5].equals("record") && !words[5].equals("financialRecords") && !words[5].equals("financial")) {
                System.out.println("Error: wrong arguments for unprotect");
                printUnprotectHelp();
                return false;
            }
            
            if (words[6].equals("a")) {
                if (!words[7].equals("pprivate") && !words[7].equals("dprivate") && !words[7].equals("iprivate")) {
                    System.out.println("Error: wrong arguments for protect");
                    printUnprotectHelp();
                    return false;
                }
            }
            else if (words[6].equals("s")) {
                if (!words[7].equals("esym") && !words[7].equals("osym") && !words[7].equals("dsym")) {
                    System.out.println("Error: wrong arguments for protect");
                    printUnprotectHelp();
                    return false;
                }
            }
            else {
                System.out.println("Error: wrong arguments for protect");
                printUnprotectHelp();
                return false;
            }

            return true;

        }
        else {
            System.out.println("Error: wrong arguments for protect");
            printProtectHelp();
            return false;
        }
    }

    private static Boolean checkAddSecurityArgs(String[] words) {
        if (words.length == 6) {
            Path path1 = Paths.get(words[2]);
            Path path2 = Paths.get(words[3]);
            if (!Files.exists(path1)) {
                System.out.println("Error: file does not exist");
                return false;
            }

            if (!words[4].equals("pprivate") && !words[4].equals("dprivate") && !words[4].equals("iprivate")) {
                System.out.println("Error: wrong arguments for addSecurity");
                printAddSecurityHelp();
                return false;
            }

            return true;
        }
        else {
            System.out.println("Error: wrong arguments for addSecurity");
            printAddSecurityHelp();
            return false;
        }
    }

    private static void printProtectHelp() {
        System.out.println("--- Protect Command ---");
        System.out.println("Protects a part of the document, based on fields and cypher chosen, and adds authentication measures");
        System.out.println("CryptoLib protect <input-file> <output-file> <fields> <cypher-type> <cypher-key> <sign> <signature-key>\n");
        System.out.println("<fields> --> can be \"personal\", \"urgent\", \"record\", \"financial\" or \"financialRecords\". Each corresponds to the respective sector in the document");
        System.out.println("<cypher-type> --> can be \"a\" for assymetric or \"s\" for symetric");
        System.out.println("<cypher-key> --> key to cypher the document, can be public or symetric keys");
        System.out.println("<sign> --> can be \"yes\" or \"no\". Adds authentication signature to document");
        System.out.println("<signature-key> --> key to use for digital signature, can only be private keys");
        System.out.println("The keys available in the demo are:");
        System.out.println("    Patient Public and Private keys --> \"ppublic\" and \"pprivate\";");
        System.out.println("    Doctor Public and Private keys --> \"dpublic\" and \"dprivate\";");
        System.out.println("    Insurance Public and Private keys --> \"ipublic\" and \"iprivate\";");
        System.out.println("    Medical Speciality Symetric keys (Emergency, Orthopedy and Dermatology) --> \"esym\", \"osym\" and \"dsym\";\n");
    }

    private static void printCheckHelp() {
        System.out.println("--- Check Command ---");
        System.out.println("Checks if availability (nonce and timestamp) and integrity (document digital signature) is valid for a document");
        System.out.println("CryptoLib check <input-file>\n");
    }

    private static void printUnprotectHelp() {
        System.out.println("--- Unprotect Command ---"); 
        System.out.println("Decyphers a part of the document, based on fields and cypher chosen. Can remove security measures added in protect");
        System.out.println("CryptoLib unprotect <input-file> <output-file> <remove-checks> <fields> <cypher-type> <decypher-key>\n");
        System.out.println("<remove-checks> --> can be \"remove\" or \"keep\". Removes all integrity/autheticity/availability checks present in the document");
        System.out.println("<fields> --> can be \"personal\", \"urgent\", \"record\", \"financial\" or \"financialRecords\". Each corresponds to the respective sector in the document");
        System.out.println("<cypher-type> --> can be \"a\" for assymetric or \"s\" for symetric");
        System.out.println("<decypher-key> --> key to cypher the document, can be private or symetric keys");
        System.out.println("The keys available in the demo are:");
        System.out.println("    Patient Public and Private keys --> \"ppublic\" and \"pprivate\";");
        System.out.println("    Doctor Public and Private keys --> \"dpublic\" and \"dprivate\";");
        System.out.println("    Insurance Public and Private keys --> \"ipublic\" and \"iprivate\";");
        System.out.println("    Medical Speciality Symetric keys (Emergency, Orthopedy and Dermatology) --> \"esym\", \"osym\" and \"dsym\";\n");
    }

    private static void printAddSecurityHelp() {
        System.out.println("--- Add Security Command ---");
        System.out.println("Adds freshness (nonce and timestamp) and integrity (digital signature over entire document) to document\n");
        System.out.println("CryptoLib addSecurity <input-file> <output-file> <signature-key> <signer-name>");
        System.out.println("<signature-key> --> key to use for digital signature, can only be private keys");
        System.out.println("The keys available in the demo are:");
        System.out.println("    Patient Public and Private keys --> \"ppublic\" and \"pprivate\";");
        System.out.println("    Doctor Public and Private keys --> \"dpublic\" and \"dprivate\";");
        System.out.println("    Insurance Public and Private keys --> \"ipublic\" and \"iprivate\";");
        System.out.println("    Medical Speciality Symetric keys (Emergency, Orthopedy and Dermatology) --> \"esym\", \"osym\" and \"dsym\";\n");
    }
	
    /* Encrypts chosenFields in input file onto output file, based on method and key provided */
	public static void protect(String inputFilename, String outputFilename, int chosenFields, int method, Key key, int sign, PrivateKey signatureKey) throws Exception {
        JsonObject rootJson = JsonManipulator.getRootJson(inputFilename);
        JsonObject objectJson = rootJson.getAsJsonObject("patient");

        switch(chosenFields) {
            case 0: {
                if (method == 0) {
                    encryptInfoA(objectJson, (PublicKey) key, getPersonalInfo());
                }
                else {
                    encryptInfoS(objectJson, key, getPersonalInfo());
                }

                break;
            }
            case 1: {
                if (method == 0) {
                    encryptInfoA(objectJson, (PublicKey) key, getUrgentInfo());
                }
                else {
                    encryptInfoS(objectJson, key, getUrgentInfo());
                }

                break;
            }
            case 2: {
                JsonArray consultationRecords = objectJson.getAsJsonArray("consultationRecords");
                for (JsonElement record : consultationRecords) {
                    if (sign == 1) {
                        String signature = generateAuthSignature(record.getAsJsonObject(), getRecordsInfo(), signatureKey);
                        record.getAsJsonObject().addProperty("doctorSignature", signature);
                    }
                    if (method == 0) {
                        encryptInfoA(record.getAsJsonObject(), (PublicKey) key, getRecordsInfo());
                    }
                    else {
                        encryptInfoS(record.getAsJsonObject(), key, getRecordsInfo());
                    }
                }

                break;
            }
            case 3: {
                JsonArray consultationRecords = objectJson.getAsJsonArray("consultationRecords");
                for (JsonElement record : consultationRecords) {
                    if (method == 0) {
                        encryptInfoA(record.getAsJsonObject(), (PublicKey) key, getRecordsFinancialInfo());
                    }
                    else {
                        encryptInfoS(record.getAsJsonObject(), key, getRecordsFinancialInfo());
                    }
                }

                break;
            }
            case 4:
                if (method == 0) {
                    encryptInfoA(objectJson, (PublicKey) key, getFinancialInfo());
                }
                else {
                    encryptInfoS(objectJson, key, getFinancialInfo());
                }

                break;
            default: {
                System.out.println("Argument for chosen Fields must be between 0 and 4");
                return;
            }
        }

        JsonManipulator.writeJsonToFile(rootJson, outputFilename);
		System.out.println("Document protected");

    }


    public static void addSecurityMeasures(String inputFilename, String outputFilename, PrivateKey signatureKey, String signer) throws Exception {
        JsonObject rootJson = JsonManipulator.getRootJson(inputFilename);

        Long randomNumber = Encryption.generateRandomNumber();
		rootJson.addProperty("timestamp", System.currentTimeMillis());
		rootJson.addProperty("randomNumber", randomNumber);

        rootJson.addProperty("integritySigner", signer);
        String fileToString = rootJson.toString();
        byte[] signature = generateDigitalSignature(fileToString, signatureKey);
        String signatureField = Base64.getEncoder().encodeToString(signature);
        rootJson.addProperty("integritySignature", signatureField);

        JsonManipulator.writeJsonToFile(rootJson, outputFilename);
		System.out.println("Added integrity and freshness mechanisms");
    }

    private static String generateAuthSignature(JsonObject objectJson, List<String> fields, PrivateKey signatureKey) throws Exception {
        String toBeHashed = getAllFieldValues(objectJson, fields);
        byte[] signature = generateDigitalSignature(toBeHashed, signatureKey);
        String signatureField = Base64.getEncoder().encodeToString(signature);
        return signatureField;
    }

    public static void addKey(Boolean assymetric, String keyStorePath, String keyStorePass, String keyAlias) {
        try {
            // Run keytool command to generate a key
            ProcessBuilder processBuilder;
            if (assymetric) {
                processBuilder = new ProcessBuilder(
                        "keytool",
                        "-genkeypair",
                        "-keyalg", "RSA",
                        "-keysize", "2048",
                        "-alias", keyAlias,
                        "-keystore", keyStorePath,
                        "-storepass", keyStorePass,
                        "-storetype", "pkcs12",
                        "-validity", "365",
                        "-dname", "CN=My Certificate, OU=My Org, O=My Company, L=My City, ST=My State, C=US"
                );
            }
            else {
                processBuilder = new ProcessBuilder(
                        "keytool",
                        "-genseckey",
                        "-keyalg", "AES",
                        "-keysize", "128",
                        "-alias", keyAlias,
                        "-keystore", keyStorePath,
                        "-storepass", keyStorePass,
                        "-storetype", "pkcs12"
                );
            }

            Process process = processBuilder.start();
            int exitCode = process.waitFor();

            if (exitCode == 0) {
                System.out.println("Key generated successfully.");
            } else {
                System.err.println("Error generating key.");
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static void removeKey(String keyStorePath, String keyStorePass, String keyAlias) {
        try {
            // Run keytool command to generate a key
            ProcessBuilder processBuilder;
            processBuilder = new ProcessBuilder(
                    "keytool",
                    "-delete",
                    "-alias", keyAlias,
                    "-keystore", keyStorePath,
                    "-storepass", keyStorePass
            );

            Process process = processBuilder.start();
            int exitCode = process.waitFor();

            if (exitCode == 0) {
                System.out.println("Key generated successfully.");
            } else {
                System.err.println("Error generating key.");
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static String cypherKey(Key key, PublicKey publicKey) throws Exception {
        byte[] keyBytes = key.getEncoded();
        byte[] encryptedField = Encryption.encryptWithRSA(keyBytes, publicKey);
        String cypheredKey = Base64.getEncoder().encodeToString(encryptedField);
        return cypheredKey;
    }

    public static Key decypherKey(String keyString, PrivateKey privateKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyString);
        byte[] decypheredKey = Encryption.decryptWithRSA(keyBytes, privateKey);
        SecretKey secretKey = new SecretKeySpec(decypheredKey, "AES");
        return secretKey;
    }

	/*
	 * removes security from a document
    */
	public static void unprotect(String inputFilename, String outputFilename, int removeChecks,  int chosenFields, int method, Key key) throws Exception {
        JsonObject rootJson = JsonManipulator.getRootJson(inputFilename);
        if (removeChecks == 1) {
            removeSecurityChecks(rootJson);
        }
        JsonObject patientJson = rootJson.getAsJsonObject("patient");
        switch (chosenFields) {
            case 0: {
                if (method == 0) {
                    decryptInfoA(patientJson, (PrivateKey) key, getPersonalInfo());
                }
                else {
                    decryptInfoS(patientJson, key, getPersonalInfo());
                }
                break;
            }
            case 1: {
                if (method == 0) {
                    decryptInfoA(patientJson, (PrivateKey) key, getUrgentInfo());
                }
                else {
                    decryptInfoS(patientJson, key, getUrgentInfo());
                }
                break;
            }
            case 2: {
                JsonArray consultationRecords = patientJson.getAsJsonArray("consultationRecords");
                for (JsonElement record : consultationRecords) {
                    if (method == 0) {
                        decryptInfoA(record.getAsJsonObject(), (PrivateKey) key, getRecordsInfo());
                    }
                    else {
                        try {
                            decryptInfoS(record.getAsJsonObject(), key, getRecordsInfo());
                        }
                        catch (Exception e) {
                            // ignore
                        }
                    }
                }
                break;
            }
            case 3: {
                JsonArray consultationRecords = patientJson.getAsJsonArray("consultationRecords");
                for (JsonElement record : consultationRecords) {
                    if (method == 0) {
                        decryptInfoA(record.getAsJsonObject(), (PrivateKey) key, getRecordsFinancialInfo());
                    }
                    else {
                        decryptInfoS(record.getAsJsonObject(), key, getRecordsFinancialInfo());
                    }
                }

                break;
            }
            case 4: {
                if (method == 0) {
                    decryptInfoA(patientJson, (PrivateKey) key, getFinancialInfo());
                }
                else {
                    decryptInfoS(patientJson, key, getFinancialInfo());
                }
                break;
            }
            default: 
                System.out.println("Error in unprotect");
                break;
        }
        JsonManipulator.writeJsonToFile(rootJson, outputFilename);
        System.out.println("Document unprotected");
    }


    // checks for integrity and authenticity
	public static Boolean check(String inputFilename, Map<String, PublicKey> verificationKeys) throws Exception {
		JsonObject rootJson = JsonManipulator.getRootJson(inputFilename);

        if (rootJson.getAsJsonPrimitive("randomNumber") == null) {
            System.out.println("Integrity and freshness mechanisms were not added to the file");
            return false;
        }

        long randomNumber = rootJson.getAsJsonPrimitive("randomNumber").getAsLong();
        long timestamp = rootJson.getAsJsonPrimitive("timestamp").getAsLong(); 
        long currentTime = System.currentTimeMillis();
        
        if (Math.abs(currentTime - timestamp) > maxTimeDifference) {
            System.out.println("Document is not fresh. Possible replay attack.");
            return false;
        }

        if (nonceMap.containsKey(randomNumber)) {
            long conflictTimestamp = nonceMap.get(randomNumber);
            currentTime = System.currentTimeMillis();
            if (Math.abs(currentTime - conflictTimestamp) < maxTimeDifference) {
                System.out.println("Nonce matches previously seen nonce. Possible replay attack.");
                return false;
            }
            else {
                nonceMap.replace(randomNumber, timestamp);
            }
        }
        else {
            nonceMap.put(randomNumber, timestamp);
        }

        String integrityString = rootJson.getAsJsonPrimitive("integritySignature").getAsString();
        byte[] integritySignature = Base64.getDecoder().decode(integrityString);
        rootJson.remove("integritySignature");
        String message = rootJson.toString();

        String integritySigner = rootJson.get("integritySigner").getAsString();
        PublicKey pubKey = verificationKeys.get(integritySigner);
        if (pubKey == null) {
            System.out.println("Signer's identity is unknown");
            return false;
        }
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(pubKey);
        sig.update(message.getBytes());

        if (!sig.verify(integritySignature)) {
            System.out.println("Integrity has been compromised");
            return false;
        }

        rootJson.addProperty("integritySignature", integrityString);
        
        System.out.println("Document is secure");
        return true;
	}

    public static Boolean checkAuthenticity(String inputFilename, Map<String, PublicKey> verificationKeys) throws Exception {
        JsonObject rootJson = JsonManipulator.getRootJson(inputFilename);
        JsonObject patientObj = rootJson.getAsJsonObject("patient");
        JsonArray consultationRecords = patientObj.getAsJsonArray("consultationRecords");
        Signature sig = Signature.getInstance("SHA256withRSA");
        String message = rootJson.toString();
        for (JsonElement record : consultationRecords) {
            if (record.getAsJsonObject().get("doctorSignature") == null) {
                System.out.println("Doctor signature missing");
                return false;
            }
            PublicKey verificationKey = verificationKeys.get(record.getAsJsonObject().get("doctorName").getAsString());
            if (verificationKey == null) {
                System.out.println("Signer's identity is unknown");
                return false;
            }
            sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(verificationKey);
            message = getAllFieldValues(record.getAsJsonObject(), getRecordsInfo());
            sig.update(message.getBytes());
            byte[] doctorSignature = Base64.getDecoder().decode(record.getAsJsonObject().get("doctorSignature").getAsString());
            if (!sig.verify(doctorSignature)) {
                System.out.println("Authenticity can't be assured");
                return false;
            }
        }
        System.out.println("Document is authentic");
        return true;
    }


    /* Digital Signature Functions */
    public static byte[] generateDigitalSignature(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());

        // Generate the digital signature
        return signature.sign();
    }

    public static Boolean checkDigitalSignature(String message, String signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(message.getBytes());
        byte[] byteSignature = Base64.getDecoder().decode(signature);
        if (sig.verify(byteSignature)) {
            return true;
        }
        else {
            return false;
        }
    }

    public static void removeSecurityChecks(JsonObject rootJson) {
        rootJson.remove("timestamp");
		rootJson.remove("randomNumber");
		rootJson.remove("integritySignature");
        rootJson.remove("integritySigner");
    }
	
	
    /*
     * Encript patient info functions
     * */
    protected static void encryptInfoA(JsonObject rootJson, PublicKey publicKey, List<String> infoList) throws Exception {
    	for (String info: infoList) {
            encryptFieldAndAddToJsonA(rootJson, info, publicKey);
    	}
    }
    
    protected static void decryptInfoA(JsonObject rootJson, PrivateKey publicKey, List<String> infoList) throws Exception {
    	for (String info: infoList) {
    		decryptFieldAndAddToJsonA(rootJson, info, publicKey);
    	}
    }
    
    protected static void encryptInfoS(JsonObject rootJson, Key publicKey, List<String> infoList) throws Exception {
    	for (String info: infoList) {
            encryptFieldAndAddToJsonS(rootJson, info, publicKey);
    	}
    }
    
    protected static void decryptInfoS(JsonObject rootJson,  Key publicKey, List<String> infoList) throws Exception {
    	for (String info: infoList) {
    		decryptFieldAndAddToJsonS(rootJson, info, publicKey);
    	}
    }
    
	protected static void encryptInfoA_S(JsonObject consultationRecord, PublicKey publicKey, Key key, List<String> infoList) throws Exception {
    	for (String info: infoList) {
    		encryptFieldAndAddToJsonA_S(consultationRecord, info, publicKey, key);
    	}
	}

    protected static void decryptInfoA_S(JsonObject consultationRecord, PrivateKey privateKey, Key key, List<String> infoList) throws Exception {
    	for (String info: infoList) {
    		decryptFieldAndAddToJsonA_S(consultationRecord, info, privateKey, key);
    	}
    }
   
    /*
     * Encrypt Specific Field Functions
     * */

	protected static void encryptFieldAndAddToJsonA(JsonObject file, String field, PublicKey publicKey) throws Exception {
        if (arrayFields.contains(field)) {
            JsonArray arrayField = file.getAsJsonArray(field);
            for (int i = 0; i < arrayField.size(); i++) {
                JsonElement element = arrayField.get(i);
                String data = element.getAsString();
		        byte[] assymetricEncryptedField = Encryption.encryptWithRSA(data.getBytes(), publicKey);
                String encryptedField = Base64.getEncoder().encodeToString(assymetricEncryptedField);
                arrayField.set(i, new JsonPrimitive(encryptedField));
            }
            file.add(field, arrayField);
        }
        else {
    		String data = file.get(field).getAsString();
		    byte[] assymetricEncryptedField = Encryption.encryptWithRSA(data.getBytes(), publicKey);
            String encryptedField = Base64.getEncoder().encodeToString(assymetricEncryptedField);
            file.addProperty(field, encryptedField);
        }
	}

    protected static void decryptFieldAndAddToJsonA(JsonObject file, String field, PrivateKey privateKey) throws Exception {
        if (arrayFields.contains(field)) {
            JsonArray arrayField = file.getAsJsonArray(field);
            for (int i = 0; i < arrayField.size(); i++) {
                JsonElement element = arrayField.get(i);
                String data = element.getAsString();
                byte[] byteArray = Base64.getDecoder().decode(data);
                String decryptedField = new String(Encryption.decryptWithRSA(byteArray, privateKey), StandardCharsets.UTF_8);
                arrayField.set(i, new JsonPrimitive(decryptedField));
            }
            file.add(field, arrayField);
        }
        else {
            String data = file.get(field).getAsString();
            byte[] byteArray = Base64.getDecoder().decode(data);
            String decryptedField = new String(Encryption.decryptWithRSA(byteArray, privateKey), StandardCharsets.UTF_8);
            file.addProperty(field, decryptedField);
        }
    }
    
	protected static void encryptFieldAndAddToJsonS(JsonObject file, String field, Key key) throws Exception {
        if (arrayFields.contains(field)) {
            JsonArray arrayField = file.getAsJsonArray(field);
            for (int i = 0; i < arrayField.size(); i++) {
                JsonElement element = arrayField.get(i);
                String data = element.getAsString();
		        byte[] symetricEncryptedField = Encryption.encryptWithSecret(data.getBytes(), key);
                String encryptedField = Base64.getEncoder().encodeToString(symetricEncryptedField);
                arrayField.set(i, new JsonPrimitive(encryptedField));
            }
            file.add(field, arrayField);
        }
        else {
    		String data = file.get(field).getAsString();
		    byte[] symetricEncryptedField = Encryption.encryptWithSecret(data.getBytes(), key);
            String encryptedField = Base64.getEncoder().encodeToString(symetricEncryptedField);
            file.addProperty(field, encryptedField);
        }
	}

    protected static void decryptFieldAndAddToJsonS(JsonObject file, String field, Key secretKey) throws Exception {
        if (arrayFields.contains(field)) {
            JsonArray arrayField = file.getAsJsonArray(field);
            for (int i = 0; i < arrayField.size(); i++) {
                JsonElement element = arrayField.get(i);
                String data = element.getAsString();
                byte[] byteArray = Base64.getDecoder().decode(data);
                String decryptedField = new String(Encryption.decryptWithSecret(byteArray, secretKey), StandardCharsets.UTF_8);
                arrayField.set(i, new JsonPrimitive(decryptedField));
            }
            file.add(field, arrayField);
        }
        else {
            String data = file.get(field).getAsString();
            byte[] byteArray = Base64.getDecoder().decode(data);
            String decryptedField = new String(Encryption.decryptWithSecret(byteArray, secretKey), StandardCharsets.UTF_8);
            file.addProperty(field, decryptedField);
        }
    }
    
   	
	protected static void encryptFieldAndAddToJsonA_S(JsonObject fatherOfField, String field, PublicKey publicKey, Key key) throws Exception {
		String data = fatherOfField.get(field).getAsString();
		byte[] symmetricEncryptedField = Encryption.encryptWithSecret(data.getBytes(), key);
		byte[] encryptedField = Encryption.encryptWithRSA(symmetricEncryptedField, publicKey);
		fatherOfField.addProperty(field, Base64.getEncoder().encodeToString(encryptedField));
	}

	protected static void decryptFieldAndAddToJsonA_S(JsonObject fatherOfField, String field, PrivateKey privateKey, Key secretKey) throws Exception {
        String encryptedField = fatherOfField.get(field).getAsString();
        byte[] symmetricEncryptedField = Encryption.decryptWithRSA(Base64.getDecoder().decode(encryptedField), privateKey);
        String decryptedField = new String(Encryption.decryptWithSecret(symmetricEncryptedField, secretKey));
        fatherOfField.addProperty(field, decryptedField);
    }

	/*
	 * functions to get fields to encrypt/decrypt
	 * */

    protected static List<String> getPersonalInfo() {
		List<String> res = new ArrayList<>();
		res.add("C.C.");
		res.add("address");
		res.add("phoneNumber");
		res.add("e-mail");
		return res;
	}

    protected static List<String> getRecordsInfo() {
    	List<String> res = new ArrayList<>();
		res.add("date");
		res.add("practice");
		res.add("treatmentSummary");
		return res;
    }

    protected static List<String> getAllRecordsInfo() {
    	List<String> res = new ArrayList<>();
		res.add("date");
        res.add("medicalSpeciality");
        res.add("doctorName");
		res.add("practice");
		res.add("treatmentSummary");
        res.add("treatmentCost");
        res.add("paymentDestination");
		return res;
    }

    protected static List<String> getUrgentInfo() {
		List<String> res = new ArrayList<>();
		res.add("emergencyPhoneNumber");
		res.add("bloodType");
		res.add("knownAllergies");
		res.add("knownIllnesses");
		return res;
	}
	
    protected static List<String> getRecordsFinancialInfo() {
		List<String> res = new ArrayList<>();
        res.add("treatmentCost");
		res.add("paymentDestination");
		return res;
	}

	protected static List<String> getFinancialInfo() {
		List<String> res = new ArrayList<>();
		res.add("NIF");
		return res;
	}

    protected static String getAllFieldValues(JsonObject objectJson, List<String> fields) {
        String joinedFields = "";
        for (int i = 0; i < fields.size(); i++) {
            joinedFields += objectJson.get(fields.get(i)).getAsString();
        }
        return joinedFields;
    }
    
}
