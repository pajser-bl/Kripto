package crypto.certificate;

import access.User;
import crypto.hash.HashAlgorithm;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import org.bouncycastle.util.encoders.Base64;

public class CertHelp {

    X509Certificate certificate;
    PublicKey publicKey;
    PrivateKey privateKey;

    public CertHelp(User user) throws FileNotFoundException, CertificateException {
        
//        File certificateFile=new File(user.getCertificatePath());
//        File privateKeyFile=new File();
//        FileInputStream certificateFIS = new FileInputStream(certificateFile);
//        this.certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certificateFIS);
//        this.publicKey=this.certificate.getPublicKey();
//        this.privateKey=user.getPrivateKeyPath()
    }

    public boolean isValid() {
        try {
            this.certificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException ex) {
            return false;
        }
        return true;
    }
    public PublicKey getPublicKey(){
        return this.certificate.getPublicKey();
    }

    public static void main(String args[]){
        try {
            X509Certificate cert =(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream("C:/Users/pajse/Documents/NetBeansProjects/Kripto/user_folders/korisnik5/cert/cert5.crt"));
//            List<Rdn> r=new LdapName(cert.getSubjectX500Principal().getName()).getRdns();
            HashAlgorithm hash=new HashAlgorithm("SHA1");
            System.out.println(Base64.toBase64String(hash.hash(cert.getEncoded())));
        } catch (CertificateException | FileNotFoundException | NoSuchAlgorithmException | NoSuchProviderException ex) {
            Logger.getLogger(CertHelp.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
