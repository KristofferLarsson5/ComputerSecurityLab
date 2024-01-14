import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws IOException {
        try {
            // Lab 1
            // Load the private key using PrivateKeyLoader class
            String keystoreFilename = "src/Ciphertext and Keys in a Zip file for you to download/lab1Store";
            char[] keystorePassword = "lab1StorePass".toCharArray();
            String alias = "lab1EncKeys";
            char[] keyPassword = "lab1KeyPass".toCharArray();
            // Load the private key for decryption from the keystore
            PrivateKey privateKey = PrivateKeyLoader.loadPrivateKey(keystoreFilename, keystorePassword, alias, keyPassword);

            // Read the ciphertext from the file
            byte[] ciphertext = Files.readAllBytes(Paths.get("src/Ciphertext and Keys in a Zip file for you to download/ciphertext.enc"));
            // Split the ciphertext into different parts based on byte ranges
            byte[] encryptedSymmetricKey = Arrays.copyOfRange(ciphertext, 0, 128);
            byte[] encryptedIV = Arrays.copyOfRange(ciphertext, 128, 256);
            byte[] encryptedHmacKey = Arrays.copyOfRange(ciphertext, 256, 384);
            byte[] encryptedData = Arrays.copyOfRange(ciphertext, 384, ciphertext.length);

            // Decrypt the RSA-encrypted components using the private key
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] decryptedSymmetricKey = rsaCipher.doFinal(encryptedSymmetricKey);
            byte[] decryptedIV = rsaCipher.doFinal(encryptedIV);
            byte[] decryptedHmacKey = rsaCipher.doFinal(encryptedHmacKey);

            // Decrypt the AES-encrypted data using the decrypted keys
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec aesKey = new SecretKeySpec(decryptedSymmetricKey, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(decryptedIV);
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivParameterSpec);

            // Decrypt the actual data using the decrypted keys
            byte[] decryptedData = aesCipher.doFinal(encryptedData);

            // Process or save the decrypted data as needed
            String decryptedText = new String(decryptedData, StandardCharsets.UTF_8);
            System.out.println("Decrypted Text: " + decryptedText);

            // LAB 2 Task 3: Calculate and compare MACs
            MACProcessor macProcessor = new MACProcessor();

            // Calculate MAC using decryptedHmacKey and decryptedData
            String calculatedMAC = macProcessor.calculateMAC(decryptedHmacKey, decryptedData);

            // Compare calculatedMAC with provided MACs
            String providedMAC1 = "src/Ciphertext and Keys in a Zip file for you to download/ciphertext.mac1.txt";
            String providedMAC2 = "src/Ciphertext and Keys in a Zip file for you to download/ciphertext.mac2.txt";

            // Read provided MACs from files
            String contentMAC1 = new String(Files.readAllBytes(Paths.get(providedMAC1)), StandardCharsets.UTF_8).trim();
            String contentMAC2 = new String(Files.readAllBytes(Paths.get(providedMAC2)), StandardCharsets.UTF_8).trim();

            if (calculatedMAC.equals(contentMAC1)) {
                System.out.println("The calculated MAC matches provided MAC1");
            } else if (calculatedMAC.equals(contentMAC2)) {
                System.out.println("The calculated MAC matches provided MAC2");
            } else {
                System.out.println("No match found for calculated MAC");
            }


            // Lab 2 Task 4
            // Load the public key from the certificate file
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            FileInputStream fis = new FileInputStream("src/Ciphertext and Keys in a Zip file for you to download/lab1Sign.cert");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(fis);
            PublicKey senderPublicKey = certificate.getPublicKey();
            fis.close();

            // Initialize a Signature instance for signature verification using the SHA1withRSA algorithm
            // By using Public key we can verify that the signature is valid
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(senderPublicKey);
            // Read the signature content from ciphertext.sig1 and verify it
            byte[] signatureContent1 = Files.readAllBytes(Paths.get("src/Ciphertext and Keys in a Zip file for you to download/ciphertext.enc.sig1"));
            signature.update(decryptedData);
            boolean isSignatureValid1 = signature.verify(signatureContent1);
            // Check if the first signature is valid
            if (isSignatureValid1) {
                System.out.println("Signature 1 is valid");
            } else {
                System.out.println("Signature 1 is invalid");
            }

            // Initialize another Signature instance for signature verification using the SHA1withRSA algorithm
            Signature signature2 = Signature.getInstance("SHA1withRSA");
            signature2.initVerify(senderPublicKey);
            // Read the signature content from ciphertext.sig2 and verify it
            byte[] signatureContent2 = Files.readAllBytes(Paths.get("src/Ciphertext and Keys in a Zip file for you to download/ciphertext.enc.sig2"));
            signature2.update(decryptedData);
            boolean isSignatureValid2 = signature2.verify(signatureContent2);
            // Check if the second signature is valid
            if (isSignatureValid2) {
                System.out.println("Signature 2 is valid");
            } else {
                System.out.println("Signature 2 is invalid");
            }

        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}
