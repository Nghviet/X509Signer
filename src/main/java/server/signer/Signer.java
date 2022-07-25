package server.signer;

import sun.security.pkcs10.PKCS10;
import sun.security.provider.X509Factory;
import sun.security.tools.keytool.*;
import sun.security.util.DerValue;
import sun.security.x509.*;

import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.Data;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Random;
import java.io.*;


public class Signer {

    private String private_key_path = "signer.key";
    private String ca_path = "CA.crt";

    private static Signer instance = null;
    private X509Certificate caFile;
    private PrivateKey privateKey;
    private X500Name name;

    public static Signer getInstance() throws Exception {
        if(instance == null) instance = new Signer();
        return instance;
    }

    private void load() throws Exception{
        BufferedReader reader = null;
        String buf_line = null;

        StringBuilder private_key_encoded = new StringBuilder();
        reader = new BufferedReader(new InputStreamReader(new FileInputStream(private_key_path)));
        do {
            buf_line = reader.readLine();
            if(buf_line == null) break;

            private_key_encoded.append(buf_line);
        }
        while(true);

        if(private_key_encoded.toString().equals("")) throw new RuntimeException("Invalid private key");

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(private_key_encoded.toString()));
        privateKey = keyFactory.generatePrivate(keySpec);

        reader = new BufferedReader(new InputStreamReader(new FileInputStream(ca_path)));
        StringBuilder CA_encoded = new StringBuilder();

        do {
            buf_line = reader.readLine();
            if(buf_line == null) break;

            CA_encoded.append(buf_line);
        }
        while(true);

        if(CA_encoded.toString().equals("")) throw new RuntimeException("Invalid CA file");
        caFile = new X509CertImpl(Base64.getMimeDecoder().decode(CA_encoded.toString()));

        X500Principal pricipal = new X500Principal("OU = home, O = iot, L = HN, S = HN, C = VN, CN = 112.137.129.202");
        name = new X500Name(pricipal.getEncoded());
    }

    private Signer() throws Exception {
        try {
            load();
        } catch(Exception ex) {
            System.out.println("Init");
            CertAndKeyGen keypair = new CertAndKeyGen("RSA", "SHA256WithRSA", null);
            X500Principal pricipal = new X500Principal("OU = home, O = iot, L = HN, S = HN, C = VN, CN = 112.137.129.202");
            name = new X500Name(pricipal.getEncoded());
            keypair.generate(2048);

            CertificateExtensions ext = new CertificateExtensions();


            privateKey = keypair.getPrivateKey();

            BasicConstraintsExtension bce = new BasicConstraintsExtension(true, true, -1);
            ext.set(BasicConstraintsExtension.NAME, bce);
            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = keypair.getSelfCertificate(name, new Date(),(long) 1 * 365 * 24 * 60 * 60, ext);
            caFile = chain[0];

            File private_key = new File(private_key_path);
            private_key.createNewFile();
            FileWriter fileWriter = new FileWriter(private_key);
            fileWriter.write(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
            fileWriter.flush();

            File ca_file = new File(ca_path);
            ca_file.createNewFile();
            fileWriter = new FileWriter(ca_file);
            fileWriter.write(Base64.getEncoder().encodeToString(caFile.getEncoded()));
            fileWriter.flush();

            System.out.println(caFile);
        }

    }

    public String getCA() throws Exception {
        String output = X509Factory.BEGIN_CERT + "\n" + Base64.getEncoder().encodeToString(caFile.getEncoded()) + "\n" + X509Factory.END_CERT;
        return output;
    }

    public String sign(String request, String user) throws Exception {
        PKCS10 csr = new PKCS10(Base64.getMimeDecoder().decode(request));
        X509CertImpl cert;

        Date first = new Date(), last = new Date();
        last.setTime(first.getTime() + 1000L * 2 * 365 * 24 * 60 * 60);
        CertificateValidity interval = new CertificateValidity(first,last);

        X509CertInfo info = new X509CertInfo();
        info.set(X509CertInfo.VERSION,
                new CertificateVersion(CertificateVersion.V3));
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(
                new java.util.Random().nextInt() & 0x7fffffff));
        AlgorithmId algID = AlgorithmId.get("SHA256WithRSA");
        info.set(X509CertInfo.ALGORITHM_ID,
                new CertificateAlgorithmId(algID));
        X500Principal pricipal = new X500Principal("OU = home, O = iot, L = HN, S = HN, C = VN, CN = " + user);
        info.set(X509CertInfo.SUBJECT, new X500Name(pricipal.getEncoded()));
        info.set(X509CertInfo.KEY, new CertificateX509Key(csr.getSubjectPublicKeyInfo()));
        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.ISSUER, name);

        CertificateExtensions extensions = new CertificateExtensions();
        boolean[] keyUsagePolicies = new boolean[9];
        keyUsagePolicies[0] = true; // Digital Signature
        keyUsagePolicies[2] = true; // Key encipherment
        KeyUsageExtension kue = new KeyUsageExtension(keyUsagePolicies);
        byte[] keyUsageValue = new DerValue(DerValue.tag_OctetString, kue.getExtensionValue()).toByteArray();
        extensions.set(KeyUsageExtension.NAME, new Extension(
                kue.getExtensionId(),
                true, // Critical
                keyUsageValue));

        GeneralNames names = new GeneralNames();
        try {
            names.add(new GeneralName(new IPAddressName("192.168.2.252")));
            names.add(new GeneralName(new IPAddressName("192.168.2.2")));
            names.add(new GeneralName(new IPAddressName("127.0.0.1")));
            names.add(new GeneralName(new IPAddressName("112.137.129.202")));
            SubjectAlternativeNameExtension san = new SubjectAlternativeNameExtension(false, names);
            extensions.set(SubjectAlternativeNameExtension.NAME, san);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        info.set(X509CertInfo.EXTENSIONS, extensions);

        cert = new X509CertImpl(info);

        cert.sign(privateKey, "SHA256WithRSA");
        String output = X509Factory.BEGIN_CERT + "\n" + Base64.getEncoder().encodeToString(cert.getEncoded()) + "\n" + X509Factory.END_CERT;
        return output;
    }
}
