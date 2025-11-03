import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;



public class NetPipeClient {
    private static Arguments arguments;

    public enum MessageType {
        CLIENTHELLO, SERVERHELLO, SESSION, CLIENTFINISHED, SERVERFINISHED
    }

    public static void main(String[] args) {
        parseArgs(args);
        try (Socket socket = new Socket(arguments.get("host"), Integer.parseInt(arguments.get("port")))) {
            System.out.println("Connected to server at " + arguments.get("host") + ":" + arguments.get("port"));

            SessionCipher sessionCipher = performHandshake(socket);

            System.out.println("Starting secure data forwarding...");
            Forwarder.forwardStreams(
                    System.in,
                    System.out,
                    sessionCipher.openDecryptedInputStream(socket.getInputStream()),
                    sessionCipher.openEncryptedOutputStream(socket.getOutputStream()),
                    socket
            );
        } catch (Exception e) {
            System.err.println("Client error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "client certificate");
        arguments.setArgumentSpec("cacert", "CA certificate");
        arguments.setArgumentSpec("key", "client private key");
        arguments.loadArguments(args);
    }

    private static SessionCipher performHandshake(Socket socket) throws Exception {
        System.out.println("Performing handshake...");

        HandshakeCertificate clientCert = new HandshakeCertificate(new FileInputStream(arguments.get("usercert")));
        HandshakeCertificate caCert = new HandshakeCertificate(new FileInputStream(arguments.get("cacert")));
        clientCert.verify(caCert);
        HandshakeCrypto clientCrypto = new HandshakeCrypto(new FileInputStream(arguments.get("key")).readAllBytes());

        // Send ClientHello
        HandshakeMessage clientHello = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        clientHello.putParameter("Certificate", Base64.getEncoder().encodeToString(clientCert.getBytes()));
        clientHello.send(socket);
        System.out.println("ClientHello sent.");

        // Receive and verify ServerHello
        HandshakeMessage serverHello = HandshakeMessage.recv(socket);
        System.out.println("Received ClientHello message: " + clientHello.toString());

        String serverCertBase64 = serverHello.getParameter("Certificate").trim();
        System.out.println("Received message type: " + serverHello.getType());
        HandshakeCertificate serverCert = new HandshakeCertificate(Base64.getDecoder().decode(serverHello.getParameter("Certificate")));
        serverCert.verify(caCert);
        System.out.println("ServerHello verified.");
        System.out.println("Received raw message: " + new String(serverHello.getBytes(), StandardCharsets.UTF_8));

        // Generate Session Key and IV
        SessionKey sessionKey = new SessionKey(128);
        byte[] sessionIV = new byte[16];
        new SecureRandom().nextBytes(sessionIV);

        HandshakeCrypto serverPublicKey = new HandshakeCrypto(serverCert);
        HandshakeMessage sessionMessage = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        sessionMessage.putParameter("SessionKey", Base64.getEncoder().encodeToString(serverPublicKey.encrypt(sessionKey.getKeyBytes())));
        sessionMessage.putParameter("SessionIV", Base64.getEncoder().encodeToString(serverPublicKey.encrypt(sessionIV)));
        sessionMessage.send(socket);
        System.out.println("Session message sent.");

        return new SessionCipher(sessionKey, sessionIV);
    }
}
