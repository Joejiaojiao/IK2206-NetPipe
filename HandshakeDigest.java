import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HandshakeDigest {

    private final MessageDigest messageDigest;
    public byte[] digest;
    /*
     * Constructor -- initialise a digest for SHA-256
     */

    public HandshakeDigest(){

        try {
            // Initialize MessageDigest with SHA-256 algorithm
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
    /*
     * Update digest with input data
     */

    public void update(byte[] input) {
        messageDigest.update(input);
    }

    /*
     * Compute final digest
     */
    public byte[] digest() {

        return messageDigest.digest();
    }
}
