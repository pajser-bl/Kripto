package crypto.certificate;

import access.User;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
            X509Certificate cert =(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream("/home/pajser/Desktop/PrG/KIRZ_projekat/certificate_manager/newcerts/cert1.crt"));
            List<Rdn> r=new LdapName(cert.getSubjectX500Principal().getName()).getRdns();
            System.out.println();
        } catch (CertificateException | FileNotFoundException | InvalidNameException ex) {
            Logger.getLogger(CertHelp.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
