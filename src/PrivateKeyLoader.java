import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;

public class PrivateKeyLoader {
    public static PrivateKey loadPrivateKey(String keystoreFilename, char[] keystorePassword, String alias, char[] keyPassword) {
        // Load private key from the keystore file using provided details
        try {
            // Create a KeyStore instance for handling keys
            KeyStore keystore = KeyStore.getInstance("JCEKS"); // "Java Cryptography Extension KeyStore."
            FileInputStream fis = new FileInputStream(keystoreFilename);
            keystore.load(fis, keystorePassword);
            fis.close();

            // Load the private key from the keystore using provided alias and key password
            Key key = keystore.getKey(alias, keyPassword);
            if (key instanceof PrivateKey) { // checks if the object referred to by the variable key is an instance of the PrivateKey
                return (PrivateKey) key; // Return the loaded private key
            } else {
                System.err.println("Key is not a private key");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
