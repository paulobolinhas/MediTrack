package domain;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import domain.entities.Message;


public class Client {
	
	protected static final String KEYSTORES_DIR = "./src/newKeyStores";
	protected static final String PATIENT_KEYSTORE = KEYSTORES_DIR + "/patientKeyStore";
	protected static final String PATIENT_TRUSTSTORE = KEYSTORES_DIR + "/patientTrustStore";
	protected static final String INSURANCE_KEYSTORE = KEYSTORES_DIR + "/insuranceKeyStore";
	protected static final String INSURANCE_TRUSTSTORE = KEYSTORES_DIR + "/insuranceTrustStore";
	protected static final String TRUSTSTORE_PASS = "123456";
	
	private static final int SERVER_PORT = 12345;
	
	public static SSLSocket startPatient() throws Exception {		

		System.setProperty("javax.net.ssl.keyStore", PATIENT_KEYSTORE);
        System.setProperty("javax.net.ssl.keyStorePassword", TRUSTSTORE_PASS);
        System.setProperty("javax.net.ssl.trustStore", PATIENT_TRUSTSTORE);
        System.setProperty("javax.net.ssl.trustStorePassword", TRUSTSTORE_PASS);
	
		SocketFactory factory = SSLSocketFactory.getDefault();		
		
		try  {
			
			SSLSocket socket = (SSLSocket) factory.createSocket("192.168.0.10", SERVER_PORT);
			socket.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" });
			socket.setEnabledProtocols(new String[] { "TLSv1.3" });
			
			System.out.println("Socket created");
			return socket;

		} catch (Exception e) {
			throw e;
		}
	
	}

	public static SSLSocket startDoctor(String doctorKeyStore, String doctorTrustStore) throws Exception {
		System.setProperty("javax.net.ssl.keyStore", doctorKeyStore);
        System.setProperty("javax.net.ssl.keyStorePassword", TRUSTSTORE_PASS);
        System.setProperty("javax.net.ssl.trustStore", doctorTrustStore);
        System.setProperty("javax.net.ssl.trustStorePassword", TRUSTSTORE_PASS);
	
		SocketFactory factory = SSLSocketFactory.getDefault();		
		
		try  {
			
			SSLSocket socket = (SSLSocket) factory.createSocket("192.168.0.10", SERVER_PORT);
			socket.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" });
			socket.setEnabledProtocols(new String[] { "TLSv1.3" });
			
			System.out.println("Socket created");
			return socket;

		} catch (Exception e) {
			throw e;
		}
	}

	public static SSLSocket startInsurance() throws Exception {
		System.setProperty("javax.net.ssl.keyStore", INSURANCE_KEYSTORE);
        System.setProperty("javax.net.ssl.keyStorePassword", TRUSTSTORE_PASS);
        System.setProperty("javax.net.ssl.trustStore", INSURANCE_TRUSTSTORE);
        System.setProperty("javax.net.ssl.trustStorePassword", TRUSTSTORE_PASS);
	
		SocketFactory factory = SSLSocketFactory.getDefault();		
		
		try  {
			
			SSLSocket socket = (SSLSocket) factory.createSocket("192.168.0.10", SERVER_PORT);
			socket.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" });
			socket.setEnabledProtocols(new String[] { "TLSv1.3" });
			
			System.out.println("Socket created");
			return socket;

		} catch (Exception e) {
			throw e;
		}
	}

	public static void sendMessage(String message, SSLSocket socket) {
		Message sentMessage = new Message(message);

		try {
			ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
			outputStream.writeObject(sentMessage);
			outputStream.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("Message sent to server");
	}

	public static String receiveMessage(SSLSocket socket) {
		try {
			ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());
			Message receivedMessage = (Message) inputStream.readObject();
			return receivedMessage.getContent();
		}
		catch (Exception e) {
			e.printStackTrace();
			return "ERROR";
		}
	}

}
