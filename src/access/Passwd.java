package access;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import crypto.hash.HashAlgorithm;
import crypto.hash.SaltMaker;
import java.io.FileNotFoundException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.util.Base64;
import java.security.cert.X509Certificate;

/**
 * File passwd contains user data.
 * It is modeled after /etc/passwd.
 * Format:
 * user_id:username:hashed_password:salt:users_folder_path:users:certificate_path
 *
 *
 *
 */
public class Passwd {

    private File passwd;
    private ArrayList<User> users;
    private HashAlgorithm sha256;

    public Passwd() {
        try {
            this.users = new ArrayList<>();
            this.sha256 = new HashAlgorithm("SHA256");
            this.passwd = new File("passwd");
            if (!this.passwd.exists()) {
                this.passwd.createNewFile();
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(passwd)));
            String line = "";
            User user;
            while ((line = reader.readLine()) != null) {
                String[] sLine = line.split(":");
                // id,username,hash,salt,folderPath,certificatePath,privateKey
                user = new User(Integer.parseInt(sLine[0]), sLine[1], sLine[2], sLine[3], sLine[4], sLine[5], sLine[6]);
                this.users.add(user);
            }
            reader.close();
        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException ex) {
            Logger.getLogger(Passwd.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public User getUser(int id) {
        for (User user : this.users) {
            if (user.getId() == id) {
                return user;
            }
        }
        return null;
    }

    public User getUser(String username) {
        for (User user : this.users) {
            if (user.getUsername().equals(username)) {
                return user;
            }
        }
        return null;
    }

    public ArrayList<User> getUsers() {
        return this.users;
    }

    public int login(String username, String password) {
        //-1 nepostoji acc
        //-2 koruptovan user
        //-3 istekao certifikat
        //-4 nije jos vazeci certifikat
        //-5 opozvan certifikat
        // 0 los pass
        // 1 ok
        User user = null;
        if ((user = getUser(username)) == null) {
            return -1;
        }
        String hash = this.sha256.hash(password.concat(user.getSalt()));
        if (!HashAlgorithm.verify(Base64.getEncoder().encodeToString(hash.getBytes()), user.getHash())) {
            if (!new File(user.getCertificatePath()).exists() || !new File(user.getFolderPath()).exists() || !new File(user.getPrivateKeyPath()).exists()) {
                return -2;
            }
            try{
                FileInputStream fIS=new FileInputStream(user.getCertificatePath());
                X509Certificate cert=  (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fIS);
                cert.checkValidity();
                fIS.close();
            }catch(CertificateExpiredException ex){
                return -3;
            } catch (CertificateNotYetValidException ex) {
                return -4;
            } catch (FileNotFoundException ex) {
                return -2;
            } catch (java.security.cert.CertificateException | IOException ex) {
                Logger.getLogger(Passwd.class.getName()).log(Level.SEVERE, null, ex);
            }
            if(false){return -5;}
            return 0;
        }
        return 1;
    }

    public boolean checkUniqueUsername(String username) {
        return getUser(username) == null;
    }

    public boolean addUser(User user) {
        PrintWriter writer = null;
        String toWrite = "";
        try {
            writer = new PrintWriter(new BufferedWriter(new FileWriter(passwd, true)));
            // id,username,hash,salt,folderPath,certificatePath,privateKey
            toWrite = this.users.size() + ":";
            toWrite += user.getUsername() + ":";
            toWrite += user.getHash() + ":";
            toWrite += user.getSalt() + ":";
            toWrite += user.getFolderPath() + ":";
            toWrite += user.getCertificatePath() + ":";
            toWrite += user.getPrivateKeyPath();
            writer.println(toWrite);
            return true;
        } catch (IOException ex) {
            Logger.getLogger(Passwd.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        } finally {
            writer.close();
        }
    }

    public static void main(String args[]) {
        try {
            Passwd passwd = new Passwd();
            HashAlgorithm sha256 = new HashAlgorithm("SHA256");
            for (int i = 1; i <= 5; i++) {
                String salt = new String(SaltMaker.generateSalt(64));
                String pass = "" + i + i + i + i;
                String hash = Base64.getEncoder().encodeToString(sha256.hash(pass.concat(salt)).getBytes());
                User user = new User(i - 1, "korisnik" + i, hash, salt, "/folder", "/cert", "/private1.der");
                System.out.println(passwd.addUser(user));
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Logger.getLogger(Passwd.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
