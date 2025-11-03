import java.io.InputStream;
import java.io.OutputStream;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;


public class SessionCipher {
    private final SessionKey sessionKey;
    private final byte[] iv; // Initialization vector
    private Cipher encryptCipher;
    private Cipher decryptCipher;
    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    public SessionCipher(SessionKey key) {
        try {
            this.sessionKey = key;

            // Generate a random IV
            this.iv = new byte[16]; // AES block size is 16 bytes
            SecureRandom random = new SecureRandom();
            random.nextBytes(this.iv);

            // Initialize ciphers
            initCiphers();
        } catch (Exception e) {
            throw new RuntimeException("Error initializing SessionCipher", e);
        }
    }

    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes) {
        try {
            this.sessionKey = key;
            this.iv = ivbytes;

            // Initialize ciphers
            initCiphers();
        } catch (Exception e) {
            throw new RuntimeException("Error initializing SessionCipher", e);
        }


    }

    private void initCiphers() throws Exception {
        SecretKey key = this.sessionKey.getSecretKey();
        IvParameterSpec ivSpec = new IvParameterSpec(this.iv);

        // Initialize encryption cipher
        this.encryptCipher = Cipher.getInstance("AES/CTR/NoPadding");
        this.encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        // Initialize decryption cipher
        this.decryptCipher = Cipher.getInstance("AES/CTR/NoPadding");
        this.decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);



    }
    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {

        return this.sessionKey;
    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {

        return this.iv;
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    CipherOutputStream openEncryptedOutputStream(OutputStream os) {

        return new CipherOutputStream(os, this.encryptCipher);
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

    CipherInputStream openDecryptedInputStream(InputStream inputstream) {

        return new CipherInputStream(inputstream, this.decryptCipher);
    }
}