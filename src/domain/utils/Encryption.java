package domain.utils;

import java.io.Serializable;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignedObject;

import javax.crypto.Cipher;

public class Encryption {

	public static byte[] encryptWithRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

	public static byte[] decryptWithRSA(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }
   
	public static byte[] encryptWithSecret(byte[] plainBytes, Key key) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

		return cipherBytes;
    }

	public static byte[] decryptWithSecret(byte[] encryptedData, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

	public static long generateRandomNumber() {
        SecureRandom secureRandom = new SecureRandom();
        return secureRandom.nextLong();
    }
    
	public static SignedObject createDigitalSignature(Serializable rootJson, PrivateKey privateKey) throws Exception {	
		Signature signingEngine = Signature.getInstance("SHA256withRSA");
		return new SignedObject(rootJson, privateKey, signingEngine);
	}
	
}
