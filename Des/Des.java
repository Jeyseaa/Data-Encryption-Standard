import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.util.Scanner;
import java.util.Base64;

public class Des {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            int choice = getChoice(scanner);
            if (choice == 1) {
                String key = getKey(scanner);
                String plainText = getPlainText(scanner);
                String encryptedText = encrypt(plainText, key);

                System.out.println("Encrypted text: " + encryptedText);
            } else if (choice == 2) {
                String key = getKey(scanner);
                String cipherText = getCipherText(scanner);
                
                System.out.println("Decrypted text: " + decrypt(cipherText, key));
            } else if (choice == 3) {
                break;
            } else {
                System.out.println("Invalid choice!");
            }
        }

        scanner.close();
    }

    static int getChoice(Scanner scanner) {
        System.out.println("\nMenu:");
        System.out.println("1. Encrypt");
        System.out.println("2. Decrypt");
        System.out.println("3. Exit");
        System.out.print("Enter your choice: ");
        return scanner.nextInt();
    }

    static String getKey(Scanner scanner) {
        System.out.print("Enter the key as text: ");
        return scanner.next();
    }

    static String getPlainText(Scanner scanner) {
        System.out.print("Enter plain text: ");
        return scanner.next();
    }

    static String getCipherText(Scanner scanner) {
        System.out.print("Enter the ciphertext (in hexadecimal format): ");
        return scanner.next();
    }

    static String encrypt(String input, String key) {
        try {
            byte[] keyBytes = key.getBytes();
            DESKeySpec desKeySpec = new DESKeySpec(keyBytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(input.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            System.out.println("Encryption failed: " + e.getMessage());
            return null;
        }
    }

    static String decrypt(String input, String key) {
        try {
            byte[] keyBytes = key.getBytes();
            DESKeySpec desKeySpec = new DESKeySpec(keyBytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] encryptedBytes = Base64.getDecoder().decode(input);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            System.out.println("Decryption failed: " + e.getMessage());
            return null;
        }
    }
}
