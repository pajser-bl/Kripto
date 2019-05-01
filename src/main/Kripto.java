package main;


import access.Passwd;
import access.User;
import java.security.cert.X509Certificate;
import view.login.LoginJFrame;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author pajser
 */
public class Kripto {
    
    public static User user;
    public static X509Certificate userCertificate;
    public static final Passwd passwd=new Passwd();
    
    public static void main(String args[]){
        LoginJFrame loginFrame=new LoginJFrame();
        loginFrame.setVisible(true);
    }
}
