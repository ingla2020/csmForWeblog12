package com.demo;

import org.apache.axis.client.Call;
import org.apache.axis.client.Service;
import org.apache.axis.encoding.Base64;
import org.apache.axis.encoding.XMLType;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;


import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.rpc.ParameterMode;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.TimeZone;


public class LoginCsm {

    public void lg(){
        org.apache.log4j.Logger.getRootLogger().setLevel(org.apache.log4j.Level.OFF);

        String endpoint = "xx";
        String service = "xx";
        String dstDN = "xx";
        String p12file = "xx";
        String signer = "xx";
        String p12pass = "Xx";


        PrivateKey pKey = null;
        X509Certificate pCertificate = null;
        byte[] asn1_cms = null;
        CertStore cstore = null;
        String LoginTicketRequest_xml;
        String SignerDN = null;

        //
        // Manage Keys & Certificates
        //
        try {
            ClassLoader loader = LoginCsm.class.getClassLoader();
            InputStream inst = loader.getResourceAsStream(p12file);
            //InputStream reso = Thread.currentThread().getContextClassLoader().getResourceAsStream(p12file);

            // Create a keystore using keys from the pkcs#12 p12file
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(inst, p12pass.toCharArray());
            inst.close();

            // Get Certificate & Private key from KeyStore
            pKey = (PrivateKey) ks.getKey(signer, p12pass.toCharArray());

            pCertificate = (X509Certificate) ks.getCertificate(signer);

            SignerDN = pCertificate.getSubjectDN().toString();

            // Create a list of Certificates to include in the final CMS
            ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();
            certList.add(pCertificate);

            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }

            cstore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }



        /*siguiente paso crea el ticket*/

        int year = 2024;
        int month = 5;
        int day = 25;
        int hour = 12;
        int minute = 0;
        int second = 0;

        int yearexp = 2024;
        int monthexp = 5;
        int dayexp = 25;
        int hourexp = 12;
        int minuteexp = 0;
        int secondexp = 0;

        GregorianCalendar gentime = new GregorianCalendar(year, month, day, hour, minute, second);
        gentime.setTimeZone(TimeZone.getTimeZone("America/Argentina/Buenos_Aires"));

        GregorianCalendar exptime = new GregorianCalendar(yearexp, monthexp, dayexp, hourexp, minuteexp, secondexp);
        exptime.setTimeZone(TimeZone.getTimeZone("America/Argentina/Buenos_Aires"));

        String UniqueId = String. valueOf(gentime.getTime().getTime() / 1000);

        XMLGregorianCalendar XMLGenTime = null;
        try {
            XMLGenTime = DatatypeFactory.newInstance()
                    .newXMLGregorianCalendar(gentime);
        } catch (DatatypeConfigurationException e) {
            System.out.println(e.getMessage());
        } //


        XMLGregorianCalendar XMLExpTime = null;
        try {
            XMLExpTime = DatatypeFactory.newInstance()
                    .newXMLGregorianCalendar(exptime);
        } catch (DatatypeConfigurationException e) {
            System.out.println(e.getMessage());
        } //


        LoginTicketRequest_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                + "<loginTicketRequest version=\"1.0\">" + "<header>" + "<source>" + SignerDN + "</source>"
                + "<destination>" + dstDN + "</destination>" + "<uniqueId>" + UniqueId + "</uniqueId>"
                + "<generationTime>" + XMLGenTime + "</generationTime>" + "<expirationTime>" + XMLExpTime
                + "</expirationTime>" + "</header>" + "<service>" + service + "</service>" + "</loginTicketRequest>";

        System.out.println(LoginTicketRequest_xml);


        /*crea cms*/
        try {
            // Create a new empty CMS Message
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

            List<X509Certificate> certList = new ArrayList<X509Certificate>();
            certList.add(pCertificate);

            Store certStore = new JcaCertStore(certList);
            ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(pKey);
            gen.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                            .build(sha1Signer, pCertificate));

            gen.addCertificates(certStore);

            CMSTypedData data2 = new CMSProcessableByteArray(LoginTicketRequest_xml.getBytes("UTF-8"));

            CMSSignedData sigData = gen.generate(data2, true);
            asn1_cms = sigData.getEncoded();

        } catch (Exception e) {
            System.out.println("Error Create a new empty CMS Message  leo");
            System.out.println(e.getMessage());
        }

        System.out.println("succes Create a new empty CMS Message  leo");



        String LoginTicketResponse = null;


        Integer timeout = 250000;
        try {
            // activa el TLSv1.2

            Service serviceE = new Service();
            Call call = (Call)serviceE.createCall();

            call.setTargetEndpointAddress(new java.net.URL(endpoint));
            call.setOperationName("loginCms");
            call.addParameter("request", XMLType.XSD_STRING, ParameterMode.IN);
//			call.addParameter(paramName, paramq, parameterMode);
            call.setReturnType(XMLType.XSD_STRING);
            call.setTimeout(timeout);
            LoginTicketResponse = (String) call.invoke(new Object[] { Base64.encode(asn1_cms) });

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        System.out.println(LoginTicketResponse);


    }
}
