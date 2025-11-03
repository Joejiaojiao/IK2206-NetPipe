import java.io.InputStream;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {
    private final X509Certificate certificate;

    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */
    public HandshakeCertificate(InputStream instream) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        this.certificate = (X509Certificate) factory.generateCertificate(instream);
    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    public HandshakeCertificate(byte[] certbytes) throws CertificateException {
        InputStream instream = new ByteArrayInputStream(certbytes);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        this.certificate = (X509Certificate) factory.generateCertificate(instream);
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() throws CertificateException {
        return this.certificate.getEncoded();
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return this.certificate;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        X509Certificate caCert = cacert.getCertificate();
        this.certificate.verify(caCert.getPublicKey());
    }
    // Extract Common Name (CN) from the certificate's Subject DN
    public String getCN() {
        String dn = this.certificate.getSubjectX500Principal().getName();
        return parseAttribute(dn, "CN");
    }

    // Extract Email from the certificate's Subject DN
    public String getEmail() {
        String dn = this.certificate.getSubjectX500Principal().getName();
        String email = parseAttribute(dn, "EMAILADDRESS");

        if (email == null) {
            email = parseAttribute(dn, "1.2.840.113549.1.9.1");
            if (email != null && email.startsWith("#")) {
                email = decodeHexEmail(email);
            }
        }

        if (email == null) {
            System.err.println("DEBUG: EMAILADDRESS not found in Subject DN.");
            System.err.println("Subject DN: " + dn);
        }

        return email;
    }

    // Helper method to parse an attribute from a DN string
    private String parseAttribute(String dn, String attribute) {
        String[] tokens = dn.split(",");
        for (String token : tokens) {
            String[] keyValue = token.trim().split("=");
            if (keyValue.length == 2 && keyValue[0].equalsIgnoreCase(attribute)) {
                return keyValue[1];
            }
        }
        return null;
    }

    private String decodeHexEmail(String hexEmail) {
        try {

            String hex = hexEmail.substring(1);
            int length = hex.length();
            byte[] bytes = new byte[length / 2];
            for (int i = 0; i < length; i += 2) {
                bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                        + Character.digit(hex.charAt(i + 1), 16));
            }

            return new String(bytes, java.nio.charset.StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            System.err.println("DEBUG: Failed to decode hex email: " + hexEmail);
            e.printStackTrace();
            return null;
        }
    }

}