import com.google.gson.Gson;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Objects;



public class Encryptionapp {


    private static Cipher cipher;

    static {
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException(e);
        }
    }

    public Encryptionapp() {
        System.out.println("CIPHER_PING: " + System.getProperty("CIPHER_PING", "CIPHER PINGER"));
    }

    public static void main(String[] args) {
        Payload payload = new Payload(
                "20240131234",
                "09/07/2024",
                "0501115310",
                "0500592358",
                "NGN",
                "1000",
                "Testing",
                "Samuel"
        );

        EncryptionHelper encryptionHelper = new EncryptionHelper();
        String payloadJson = new Gson().toJson(payload);

        // Encrypting the payload
        String encryptedPayload = encryptionHelper.encryptRequest(payloadJson);
        System.out.println("Encrypted Payload: " + encryptedPayload);

        // Decrypting the encrypted payload (just for demonstration)
        String decryptedPayload = encryptionHelper.decryptResponse(encryptedPayload);
        System.out.println("Decrypted Payload: " + decryptedPayload);

        String decryptedResult = encryptionHelper.decryptResponse("EsxChzwQOeLJOU5xcECjtkGN0jOcdnyJbSk3r3IHYPZAraueHzgwMEV6y5R5ufW20/z8vk+cYYsxpJeZNMMaxJXXVSAYQQ45oFA8Rf5r4txu81Exz20INedMHPEj7iTrhh80eEkA0xl1GAnu/BW20EXkSMFrY8winXg8t1T4CNU=");
        System.out.println("Decrypted Result: " + decryptedResult);
    }

    public static class Payload {
        private String transRef;
        private String transactionDate;
        private String debitAccount;
        private String creditAccount;
        private String currency;
        private String amount;
        private String narration;
        private String beneficiaryName;

        public Payload(String transRef, String transactionDate, String debitAccount, String creditAccount,
                       String currency, String amount, String narration, String beneficiaryName) {
            this.transRef = transRef;
            this.transactionDate = transactionDate;
            this.debitAccount = debitAccount;
            this.creditAccount = creditAccount;
            this.currency = currency;
            this.amount = amount;
            this.narration = narration;
            this.beneficiaryName = beneficiaryName;
        }
    }


    // ... (Payload class remains the same)

    public static class EncryptionHelper {
        private static final String PASS_PHRASE = "Av2345fgbnhes78@#dn";
        private static final String SALT_VALUE = "Dfcvb542*&sdcf87r";
        private static final String INIT_VECTOR = "Mked098lasn34mg6";
        //private static final byte[] INIT_VECTOR = new byte[]{0x4D, 0x6B, 0x65, 0x64, 0x30, 0x39, 0x38, 0x6C, 0x61, 0x73, 0x6E, 0x33, 0x34, 0x6D, 0x67, 0x36};

        static final int PASSWORD_ITERATIONS = 2;
        private static final int BLOCK_SIZE = 256;
        private static final int ENCRYPT_MODE = Cipher.ENCRYPT_MODE;
        private static final int DECRYPT_MODE = Cipher.DECRYPT_MODE;

        public String encryptRequest(String clearText) {
            if (Objects.isNull(clearText)) {
                return null;
            }
            try {
                SecretKey key = generateKey(SALT_VALUE, PASS_PHRASE);
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(INIT_VECTOR.getBytes(StandardCharsets.UTF_8)));
                byte[] encrypted = cipher.doFinal(clearText.getBytes("UTF-8"));
                return Base64.getEncoder().encodeToString(encrypted);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                     InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException |
                     UnsupportedEncodingException e) {
                throw new IllegalStateException(e);
            }
        }

        private static SecretKey generateKey(String salt, String passphrase) {
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt.getBytes("UTF-8"), PASSWORD_ITERATIONS, BLOCK_SIZE);
                SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
                return key;
            } catch (NoSuchAlgorithmException | InvalidKeySpecException | UnsupportedEncodingException e) {
                throw new IllegalStateException(e);
            }
        }

        private static byte[] hex(String str) {
            try {
                // Remove any non-Base64 characters from the input string
                str = str.replaceAll("[^A-Za-z0-9+/=]", "");

                // Check if the input string has an odd number of characters
                if (str.length() % 4 != 0) {
                    // Add the required padding characters
                    str = String.format("%s%s", str, "==".substring(0, (4 - str.length() % 4)));
                }
                byte[] decodedBytes = Base64.getDecoder().decode(str);
                return decodedBytes;
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }


        public String decryptResponse(String encryptedText) {
            try {
                byte[] saltValueBytes = EncryptionHelper.SALT_VALUE.getBytes(StandardCharsets.UTF_8);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                KeySpec spec = new PBEKeySpec(PASS_PHRASE.toCharArray(), saltValueBytes, EncryptionHelper.PASSWORD_ITERATIONS, EncryptionHelper.BLOCK_SIZE);
                SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR.getBytes(StandardCharsets.UTF_8));
                cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

                byte[] decoded = Base64.getDecoder().decode(encryptedText);
                byte[] decrypted = cipher.doFinal(decoded);

                return new String(decrypted, StandardCharsets.UTF_8);
            } catch (Exception ex) {
                ex.printStackTrace();
                return null;
            }
        }
    }

}

