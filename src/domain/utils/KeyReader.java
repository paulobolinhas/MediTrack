package domain.utils;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class KeyReader {

	public static PublicKey readPublicKey(String publicKeyPath) throws Exception {
        try {
            Path path = Paths.get(publicKeyPath);
            byte[] publicKeyBytes = Files.readAllBytes(path);

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(publicKeyBytes));
            
            return certificate.getPublicKey();
        } catch (Exception e) {
            throw new Exception("Error reading public key", e);
        }
    }
	
	public static PrivateKey readPrivateKey(String trustStorePath, String trustStorePassword, String keysAlias) throws Exception {
		KeyStore trustStore = KeyStore.getInstance("pkcs12");
		trustStore.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());
		return (PrivateKey) trustStore.getKey(keysAlias, trustStorePassword.toCharArray());
	}
	
	public static Key readSecretKey(String trustStorePath, String trustStorePassword, String keysAlias) throws Exception {
		KeyStore trustStore = KeyStore.getInstance("pkcs12");
		trustStore.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());
		return (Key) trustStore.getKey(keysAlias, trustStorePassword.toCharArray());
	}
	
    public static X509Certificate getCertificate(String publicKeyPath) throws Exception {
        try {
            Path path = Paths.get(publicKeyPath);
            byte[] publicKeyBytes = Files.readAllBytes(path);

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(publicKeyBytes));
            
            return certificate;
        } catch (Exception e) {
            throw new Exception("Error getting Certificate", e);
        }
    }
    
    private static byte[] readFile(String path) throws FileNotFoundException, IOException {
        FileInputStream fis = new FileInputStream(path);
        byte[] content = new byte[fis.available()];
        fis.read(content);
        fis.close();
        return content;
    }
	
}
