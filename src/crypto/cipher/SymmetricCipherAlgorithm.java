package crypto.cipher;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SymmetricCipherAlgorithm {

    /**
     * Available ciphers:
     * 1. AES
     * 2. DES
     * 3. RC2
     * 4. RC4
     * 5. RC5
     * 6. BLOWFISH
     *
     * @return 
     */
    public static String[] getCiphers(){
        return new String[]{"AES","DES","RC2","RC4","RC5","BLOWFISH"};
    }
    
    
    private final Cipher cipher;

    public SymmetricCipherAlgorithm(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        Security.addProvider(new BouncyCastleProvider());
        this.cipher = Cipher.getInstance(algorithm);
    }

    public String getAlgorithm() {
        return this.cipher.getAlgorithm();
    }

    public byte[] encrypt(SecretKey key, byte base64ByteArray[]) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        this.cipher.init(Cipher.ENCRYPT_MODE, key);
        return this.cipher.doFinal(Base64.getEncoder().encode(base64ByteArray));
    }

    public byte[] decrypt(SecretKey key, byte byteCipherArray[]) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        this.cipher.init(Cipher.DECRYPT_MODE, key);
        return Base64.getDecoder().decode(this.cipher.doFinal(byteCipherArray));
    }

    public SecretKey generateKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator keyGen = KeyGenerator.getInstance(this.cipher.getAlgorithm());
        return keyGen.generateKey();
    }

    public static void getAlgorythms() {
        for (Provider provider : Security.getProviders()) {
            System.out.println(provider.getName());
            for (Provider.Service s : provider.getServices()) {
                if (s.getType().equals("Cipher")) {
                    System.out.println("\t" + s.getType() + " " + s.getAlgorithm());
                }
            }
        }
    }

    //    public static void main(String args[]) {
//        try {
//            System.out.println("Cypher test");
//
//            String alg = "AES";
//            CipherAlgorithm cA = new CipherAlgorithm(alg);
//            System.out.println(cA.getAlgorithm());
//            SecretKey key = cA.generateKey();
//            String text = "\'[]][]]{./,.//n/!@#$%^&*()_+>><<>??.,";
//            try {
//                byte[] base64 = Base64.getEncoder().encode(text.getBytes());
//                byte enc[] = cA.encrypt(key, base64);
//                System.out.println(text);
//                System.out.println(enc);
//                byte[] dec = cA.decrypt(key, enc);
//                System.out.println(new String(Base64.getDecoder().decode(dec)));
//            } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
//                Logger.getLogger(CipherAlgorithm.class.getName()).log(Level.SEVERE, null, ex);
//            }
//        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
//            System.out.println("Cypher test fail");
//            Logger.getLogger(CipherAlgorithm.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (NoSuchPaddingException ex) {
//            Logger.getLogger(CipherAlgorithm.class.getName()).log(Level.SEVERE, null, ex);
//        }
//    }
}
