package crypto.hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class HashAlgorithm {

    /**
     * Available hash algorithms:
     * 1. MD4
     * 2. MD5
     * 3. SHA1
     * 4. SHA-256
     * 5. SHA-512
     * 
     * @return 
     */
    public static String[] getHashes(){
        return new String[]{"MD4","MD5","SHA1","SHA-256","SHA-512"};
    }
    
    private String algorithm = "";
    private MessageDigest messageDigest = null;

    public HashAlgorithm(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        this.algorithm = algorithm;
        Security.addProvider(new BouncyCastleProvider());
        this.messageDigest = MessageDigest.getInstance(this.algorithm, BouncyCastleProvider.PROVIDER_NAME);
    }

    public String getAlgorithm() {
        return this.algorithm;
    }

    public byte[] hash(byte byteArray[]) {
        return this.messageDigest.digest(byteArray);
    }

    public String hash(String toHash) {
        return new String(hash(toHash.getBytes()));
    }

    public static boolean verify(String string1, String string2) {
        return MessageDigest.isEqual(string1.getBytes(), string2.getBytes());
    }

}
