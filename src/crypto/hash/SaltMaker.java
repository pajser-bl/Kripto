package crypto.hash;

import java.security.SecureRandom;
import java.util.Base64;

public class SaltMaker {

    public static byte[] generateSalt(int length) {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[length];
        random.nextBytes(salt);
        return Base64.getEncoder().encode(salt);
    }

}
