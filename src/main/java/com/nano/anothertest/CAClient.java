package com.nano.anothertest;

import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;

import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Description:
 *
 * @version: 1.0
 * @author: nano
 * @date: 2020/11/20 16:59
 */
public class CAClient {
    String caname;
    String caUrl;
    Properties caProperties;

    HFCAClient instance;

    UserContext adminContext;

    public UserContext getAdminUserContext() {
        return adminContext;
    }

    public void setAdminUserContext(UserContext userContext) {
        this.adminContext = userContext;
    }

    public CAClient(String caname ,String caUrl, Properties caProperties) throws MalformedURLException, IllegalAccessException, InstantiationException, ClassNotFoundException, CryptoException, InvalidArgumentException, NoSuchMethodException, InvocationTargetException {
        this.caname=caname;

        this.caUrl = caUrl;
        this.caProperties = caProperties;
        init();
    }

    public CAClient(String caUrl, Properties caProperties) throws MalformedURLException, IllegalAccessException, InstantiationException, ClassNotFoundException, CryptoException, InvalidArgumentException, NoSuchMethodException, InvocationTargetException {
        this.caUrl = caUrl;
        this.caProperties = caProperties;
        initTLS();
    }

    public void init() {
        try {
            CryptoSuite cryptoSuite = CryptoSuite.Factory.getCryptoSuite();
            instance = HFCAClient.createNewInstance(caUrl, caProperties);
            instance.setCryptoSuite(cryptoSuite);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public void initTLS() {
        try {
            CryptoSuite cryptoSuite = CryptoSuite.Factory.getCryptoSuite();
            instance = HFCAClient.createNewInstance(caname, caUrl, caProperties);
            instance.setCryptoSuite(cryptoSuite);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public HFCAClient getInstance() {
        return instance;
    }

    public UserContext enrollAdminUser(String username, String password) throws Exception {
        UserContext userContext = Util.readUserContext(adminContext.getAffiliation(), username);
        if (userContext != null) {
            Logger.getLogger(CAClient.class.getName()).log(Level.WARNING, "CA -" + caUrl + " admin is already enrolled.");
            return userContext;
        }
        Enrollment adminEnrollment = instance.enroll(username, password);
        adminContext.setEnrollment(adminEnrollment);
        Logger.getLogger(CAClient.class.getName()).log(Level.INFO, "CA -" + caUrl + " Enrolled Admin.");
        Util.writeUserContext(adminContext);
        return adminContext;
    }


    public UserContext enrollAdminUserTLS(String username, String password) throws Exception {

        UserContext userContext = Util.readUserContext(adminContext.getAffiliation(), username);
        if (userContext != null) {
            Logger.getLogger(CAClient.class.getName()).log(Level.WARNING, "CA -" + caUrl + " admin is already enrolled.");
            return userContext;
        }
        instance.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        EnrollmentRequest enrollmentRequestTLS  = new EnrollmentRequest();
        enrollmentRequestTLS.addHost(Config.CA_ORG1_URL);
        enrollmentRequestTLS.setProfile("tls");
        Enrollment adminenroll = instance.enroll(username, password, enrollmentRequestTLS);
        adminContext.setEnrollment(adminenroll);
        Logger.getLogger(CAClient.class.getName()).log(Level.INFO, "CA -" + caUrl + " Enrolled Admin.");
        Util.writeUserContext(adminContext);
        return adminContext;
    }

    public String registerUser(String username, String organization) throws Exception {
        UserContext userContext = Util.readUserContext(adminContext.getAffiliation(), username);
        if (userContext != null) {
            Logger.getLogger(CAClient.class.getName()).log(Level.WARNING, "CA -" + caUrl +" User " + username+ " is already registered.");
            return null;
        }
        RegistrationRequest rr = new RegistrationRequest(username, organization);
        String enrollmentSecret = instance.register(rr, adminContext);
        Logger.getLogger(CAClient.class.getName()).log(Level.INFO, "CA -" + caUrl + " Registered User - " + username);
        return enrollmentSecret;
    }
    public UserContext enrollUser(UserContext user, String secret) throws Exception {
        UserContext userContext = Util.readUserContext(adminContext.getAffiliation(), user.getName());
        if (userContext != null) {
            Logger.getLogger(CAClient.class.getName()).log(Level.WARNING, "CA -" + caUrl + " User " + user.getName()+" is already enrolled");
            return userContext;
        }
        Enrollment enrollment = instance.enroll(user.getName(), secret);
        user.setEnrollment(enrollment);
        Util.writeUserContext(user);
        Logger.getLogger(CAClient.class.getName()).log(Level.INFO, "CA -" + caUrl +" Enrolled User - " + user.getName());
        return user;
    }
}
