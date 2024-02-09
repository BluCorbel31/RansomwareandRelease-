import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class Encrypt {
    public static String encrypt(String plainText, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        String key = "YourSecretKeyHere";
        String message = "Hello, world!";
        String encryptedMessage = encrypt(message, key);
        System.out.println("Encrypted message: " + encryptedMessage);
    }
}