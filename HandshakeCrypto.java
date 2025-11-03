import javax.crypto.Cipher;
import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {

	private PublicKey publicKey;
	private PrivateKey privateKey;

	/*
	 * Constructor to create an instance for encryption/decryption with a public key.
	 * The public key is given as a X509 certificate.
	 */
	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
		try {
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			Certificate certificate = certFactory.generateCertificate(
					new ByteArrayInputStream(handshakeCertificate.getBytes())
			);
			this.publicKey = certificate.getPublicKey();
		} catch (Exception e) {
			throw new RuntimeException("Failed to extract public key from certificate.", e);
		}
	}

	/*
	 * Constructor to create an instance for encryption/decryption with a private key.
	 * The private key is given as a byte array in PKCS8/DER format.
	 */

	public HandshakeCrypto(byte[] keybytes) {
		try {
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keybytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			this.privateKey = keyFactory.generatePrivate(keySpec);
		} catch (Exception e) {
			throw new RuntimeException("Failed to load private key.", e);
		}
	}

	/*
	 * Decrypt byte array with the key, return result as a byte array
	 */
    public byte[] decrypt(byte[] ciphertext) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			if (privateKey != null) {
				cipher.init(Cipher.DECRYPT_MODE, privateKey);
			} else if (publicKey != null) {
				cipher.init(Cipher.DECRYPT_MODE, publicKey);
			} else {
				throw new IllegalStateException("No key available for decryption.");
			}
			return cipher.doFinal(ciphertext);
		} catch (Exception e) {
			throw new RuntimeException("Decryption failed.", e);
		}
    }

	/*
	 * Encrypt byte array with the key, return result as a byte array
	 */
    public byte [] encrypt(byte[] plaintext) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			if (publicKey != null) {
				cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			} else if (privateKey != null) {
				cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			} else {
				throw new IllegalStateException("No key available for encryption.");
			}
			return cipher.doFinal(plaintext);
		} catch (Exception e) {
			throw new RuntimeException("Encryption failed.", e);
		}
	}
}
