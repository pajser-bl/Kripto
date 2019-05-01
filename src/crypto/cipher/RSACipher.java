package crypto.cipher;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSACipher {

    private final Cipher cipher;
    private final String algorythm = "RSA";

    public RSACipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.cipher = Cipher.getInstance(algorythm);
    }

    public String getAlgorythm() {
        return this.algorythm;
    }

    public byte[] encrypt(PublicKey publicKey, byte base64ByteArray[]) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        this.cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return this.cipher.doFinal(Base64.getEncoder().encode(base64ByteArray));
    }

    public byte[] decrypt(PrivateKey key, byte byteCipherArray[]) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        this.cipher.init(Cipher.DECRYPT_MODE, key);
        return Base64.getDecoder().decode(this.cipher.doFinal(byteCipherArray));
    }

    public static PrivateKey readPrivateKey(String privateKeyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get(privateKeyPath));
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(privateKeySpec);
    }

    public static void main(String args[]) {
        try {
            System.out.println(RSACipher.readPrivateKey("/home/pajser/Desktop/PrG/KIRZ_projekat/certificate_manager/private/private1.der").getFormat());
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(RSACipher.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
