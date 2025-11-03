import javax.crypto.SecretKey;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

/*
 * Skeleton code for class SessionKey
 */

class SessionKey {
    private SecretKey Newsecretkey;
    /*
     * Constructor to create a secret key of a given length
     */
    public SessionKey(Integer length)throws NoSuchAlgorithmException{
        KeyGenerator Keygenerator = KeyGenerator.getInstance("AES");
        Keygenerator.init(length);
        Newsecretkey = Keygenerator.generateKey();
    }

    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keybytes) {
        Newsecretkey = new SecretKeySpec(keybytes, "AES");
    }

    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return Newsecretkey;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
        return Newsecretkey.getEncoded();
    }
}