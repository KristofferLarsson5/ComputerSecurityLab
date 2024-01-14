import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class MACProcessor {
    private Mac mac;
    public MACProcessor() {
        try {
            mac = Mac.getInstance("HmacMD5");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Problem initializing MAC");
            e.printStackTrace();
        }
    }
    public String calculateMAC(byte[] key, byte[] data) {
        byte[] macVal = null;
        try {
            Mac mac = Mac.getInstance("HmacMD5");
            SecretKeySpec secretKey = new SecretKeySpec(key, "HmacMD5");
            mac.init(secretKey);
            mac.update(data);
            macVal = mac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return bytesToHex(macVal); // Convert byte array to hex string
    }
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
