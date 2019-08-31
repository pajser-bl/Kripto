package communication;

import access.User;
import crypto.cipher.RSACipher;
import crypto.cipher.SymmetricCipherAlgorithm;
import crypto.hash.HashAlgorithm;
import crypto.hash.SaltMaker;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Message {

    /**
     * Message file:
     * -----BEGIN HEADER-----
     * receiverUsername:senderUsername:timestamp:sourceFileName
     * -----END HEADER-----
     * -----BEGIN HIDDEN-----
     * hashAlgorithm:symmetricCipherAlgorithm:byteKey
     * -----END HIDDEN-----
     * -----BEGIN ENCRYPTED-----
     * encrypted source code
     * -----END ENCRYPTED-----
     * -----BEGIN SALT-----
     * sourceSalt
     * -----END SALT-----
     * -----BEGIN HASH-----
     * hashed source code
     * -----END HASH-----
     *
     *
     * @param sender
     * @param receiver
     * @param hashAlgorithm
     * @param symmetricCipherAlgorithm
     * @param saltLength
     * @param source
     * @return
     */
    public static boolean send(User sender, User receiver, String hashAlgorithm, String symmetricCipherAlgorithm, int saltLength, File source) {
        try {
            //declarations (message info)
            String senderUsername = sender.getUsername();
            String receiverUsername = receiver.getUsername();
            LocalDateTime time = LocalDateTime.now();
            String sourceFileName = source.getName();

            //cipher, key, salt and hash
            SymmetricCipherAlgorithm cipher = new SymmetricCipherAlgorithm(symmetricCipherAlgorithm);
            SecretKey key = cipher.generateKey();
            byte[] byteKeyBase64 = Base64.getEncoder().encode(key.getEncoded());
            byte[] messageSalt = SaltMaker.generateSalt(256);
            byte[] sourceSalt = SaltMaker.generateSalt(saltLength);
            HashAlgorithm hasher = new HashAlgorithm(hashAlgorithm);

            //generate message hash
            String messageInfo = senderUsername + receiverUsername + time.toInstant(ZoneOffset.UTC).toEpochMilli();
            byte[] messageInfoInBytesBase64 = Base64.getEncoder().encode(messageInfo.getBytes());
            byte[] messageHash = hasher.hash(messageInfoInBytesBase64);

            //encrypt hidden
            FileInputStream receiverCertificateStream = new FileInputStream(receiver.getCertificatePath());
            X509Certificate receiverCertificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(receiverCertificateStream);
            PublicKey receiverPublicKey = receiverCertificate.getPublicKey();
            RSACipher rsaCipher = new RSACipher();
            String hidden = hashAlgorithm + ":" + symmetricCipherAlgorithm + ":" + new String(byteKeyBase64);
            byte[] hiddenBase64 = Base64.getEncoder().encode(hidden.getBytes());
            byte[] encryptedHidden = rsaCipher.encrypt(receiverPublicKey, hiddenBase64);

            //read source code
            byte[] sourceInBytes = Files.readAllBytes(source.toPath());
            byte[] sourceInBytesBase64 = Base64.getEncoder().encode(sourceInBytes);
            byte[] sourceInBytesBase64Salted = new byte[sourceInBytesBase64.length + sourceSalt.length];
            System.arraycopy(sourceInBytesBase64, 0, sourceInBytesBase64Salted, 0, sourceInBytesBase64.length);
            System.arraycopy(sourceSalt, 0, sourceInBytesBase64Salted, sourceInBytesBase64.length, sourceSalt.length);

            //generate source hash
            byte[] sourceHash = hasher.hash(sourceInBytesBase64);

            //encrypt source
            byte[] encrypted = cipher.encrypt(key, sourceInBytesBase64Salted);

            //save to file
            String fileName = receiver.getFolderPath() + File.separator + DateTimeFormatter.ofPattern("yyyyMMddHHmmssSSS").format(time) + ".message";
            PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(fileName, true)));

            writer.println("-----BEGIN HEADER-----");
            writer.println(receiverUsername + ";" + senderUsername + ";" + DateTimeFormatter.ofPattern("dd.MM.yyyy.[HH:mm:ss:SSS]").format(time) + ";" + sourceFileName + ";" + new String(messageSalt));
            writer.println("-----END HEADER-----");
            writer.println("-----BEGIN HIDDEN-----");
//            writer.println(hashAlgorithm + ":" + symmetricCipherAlgorithm + ":" + new String(byteKeyBase64));
            writer.println(Base64.getEncoder().encodeToString(encryptedHidden));
            writer.println("-----END HIDDEN-----");
            writer.println("-----BEGIN ENCRYPTED-----");
//            writer.println(new String(encrypted));
            writer.println(Base64.getEncoder().encodeToString(encrypted));
            writer.println("-----END ENCRYPTED-----");
            writer.println("-----BEGIN SALT-----");
            writer.println(Base64.getEncoder().encodeToString(sourceSalt));
            writer.println("-----END SALT-----");
            writer.println("-----BEGIN HASH-----");
            writer.println(Base64.getEncoder().encodeToString(sourceHash));
            writer.println("-----END HASH-----");

            writer.close();
            return true;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException | CertificateException ex) {
            Logger.getLogger(Message.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    /**
     * Used to read encrypted file found in users folder
     *
     * @param file
     * @param user
     * @return
     */
    public static String read(File file, User user) {
        // 1:sender:time:cipher:hash OK
        // 0:sender:time:cipher:hash bad hash
        // -1 bad private key
        // -2 bad format
        // -3 exceptions
        // -4 user is not receiver
        try {
            ArrayList<String> lines = (ArrayList<String>) Files.readAllLines(Paths.get(file.getPath()));
            //format check
            if (!lines.get(0).equals("-----BEGIN HEADER-----")
                    || !lines.get(2).equals("-----END HEADER-----")
                    || !lines.get(3).equals("-----BEGIN HIDDEN-----")
                    || !lines.get(5).equals("-----END HIDDEN-----")
                    || !lines.get(6).equals("-----BEGIN ENCRYPTED-----")
                    || !lines.get(8).equals("-----END ENCRYPTED-----")
                    || !lines.get(9).equals("-----BEGIN SALT-----")
                    || !lines.get(11).equals("-----END SALT-----")
                    || !lines.get(12).equals("-----BEGIN HASH-----")
                    || !lines.get(14).equals("-----END HASH-----")) {
                return "-2";//bad format
            }
            //read message info
            String[] messageInfo = lines.get(1).split(";");
            String receiver = messageInfo[0];
            String sender = messageInfo[1];
            String time = messageInfo[2];
            String sourceFileName = user.getFolderPath() + File.separator + messageInfo[3];

            if (!receiver.equals(user.getUsername())) {
                return "-4";//user is not receiver
            }            //read hidden
            byte[] encryptedHidden = Base64.getDecoder().decode(lines.get(4));
            RSACipher rsaCipher = new RSACipher();
            PrivateKey privateKey = RSACipher.readPrivateKey(user.getPrivateKeyPath());
            byte[] decryptedHidden = rsaCipher.decrypt(privateKey, encryptedHidden);
            String[] hidden = new String(Base64.getDecoder().decode(decryptedHidden)).split(":");
            String hashAlgorithm = hidden[0];
            String symmetricCipherAlgorithm = hidden[1];
            byte[] keyBytes = Base64.getDecoder().decode(hidden[2].getBytes());
            SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, symmetricCipherAlgorithm);

            HashAlgorithm hasher = new HashAlgorithm(hashAlgorithm);
            SymmetricCipherAlgorithm cipher = new SymmetricCipherAlgorithm((symmetricCipherAlgorithm));

            //salt
            byte[] salt = Base64.getDecoder().decode(lines.get(10).getBytes());

            //encrypted source code
            byte[] encrypted = Base64.getDecoder().decode(lines.get(7).getBytes());
            byte[] decryptedBytes64 = cipher.decrypt(key, encrypted);
            byte[] desalted = new byte[decryptedBytes64.length - salt.length];
            System.arraycopy(decryptedBytes64, 0, desalted, 0, desalted.length);
            byte[] decrypted = Base64.getDecoder().decode(desalted);

            //hash
            String hash = lines.get(13);
            String newHash = Base64.getEncoder().encodeToString(hasher.hash(desalted));
            if (!HashAlgorithm.verify(hash, newHash)) {
                return "0;" + sender + ";" + time + ";" + cipher.getAlgorithm() + ";" + hashAlgorithm;//bad hash
            }//            System.out.println("To: " + receiver);
//            System.out.println("From: " + sender);
//            System.out.println("At: " + time);
//
//            System.out.println("Hash: " + hashAlgorithm);
//            System.out.println("Enc: " + symmetricCipherAlgorithm);
//            System.out.println("HASH VERIFY: " + HashAlgorithm.verify(hash, newHash));
//            System.out.println("Source:" + new String(decrypted));
            Files.write(new File(sourceFileName).toPath(), new String(decrypted).getBytes(), StandardOpenOption.CREATE);
            return "1;" + sender + ";" + time + ";" + cipher.getAlgorithm() + ";" + hashAlgorithm + ";" + sourceFileName;//all good
        } catch (FileNotFoundException ex) {
//            Logger.getLogger(Message.class.getName()).log(Level.SEVERE, null, ex);
            return "-3";//file problem
        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeySpecException | IllegalBlockSizeException |IllegalArgumentException ex) {
//            Logger.getLogger(Message.class.getName()).log(Level.SEVERE, null, ex);
            return "-3";//file problem
        } catch (InvalidKeyException | BadPaddingException ex) {
//            Logger.getLogger(Message.class.getName()).log(Level.SEVERE, null, ex);
            return "-1";//bad private key
        }
    }

    public static void main(String args[]) {

//        File source = new File("/home/pajser/Desktop/ree.java");
//        User u1 = new User(1, "test1", "test", "", "user_folders/korisnik1", "/home/pajser/Desktop/PrG/KIRZ_projekat/certificate_manager/newcerts/cert1.crt", "/home/pajser/Desktop/PrG/KIRZ_projekat/certificate_manager/private/private1.key");
//        User u2 = new User(2, "test2", "test", "", "user_folders/korisnik1", "/home/pajser/Desktop/PrG/KIRZ_projekat/certificate_manager/newcerts/cert1.crt", "/home/pajser/Desktop/PrG/KIRZ_projekat/certificate_manager/private/private1.der");
//        System.out.println(Message.send(u1, u2, "SHA256", "RC4", 256, source));
        //File out=new File("/home/pajser/NetBeansProjects/Kripto/20190408121910625");
//        System.out.println(Message.read(out, u2));
    }

}
