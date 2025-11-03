import java.io.*;
import java.net.*;
import java.util.Base64;
import java.util.Arrays;

public class NetPipeServer {
    private static Arguments arguments;

    public static void main(String[] args) {
        parseArgs(args);
        try (ServerSocket serverSocket = new ServerSocket(Integer.parseInt(arguments.get("port")))) {
            System.out.println("Listening on port " + arguments.get("port"));
            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected: " + clientSocket.getInetAddress());

            SessionCipher sessionCipher = performHandshake(clientSocket);

            System.out.println("Starting secure data forwarding...");
            Forwarder.forwardStreams(
                    sessionCipher.openDecryptedInputStream(clientSocket.getInputStream()),
                    sessionCipher.openEncryptedOutputStream(clientSocket.getOutputStream()),
                    System.in,
                    System.out,
                    clientSocket
            );
        } catch (Exception e) {
            System.err.println("Server error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "server certificate");
        arguments.setArgumentSpec("cacert", "CA certificate");
        arguments.setArgumentSpec("key", "server private key");
        arguments.loadArguments(args);
    }

    private static SessionCipher performHandshake(Socket socket) throws Exception {
        System.out.println("Performing handshake...");

        HandshakeCertificate serverCert = new HandshakeCertificate(new FileInputStream(arguments.get("usercert")));
        HandshakeCertificate caCert = new HandshakeCertificate(new FileInputStream(arguments.get("cacert")));
        serverCert.verify(caCert);
        HandshakeCrypto serverCrypto = new HandshakeCrypto(new FileInputStream(arguments.get("key")).readAllBytes());

        // Receive ClientHello
        HandshakeMessage clientHello = HandshakeMessage.recv(socket);
        HandshakeCertificate clientCert = new HandshakeCertificate(Base64.getDecoder().decode(clientHello.getParameter("Certificate")));
        clientCert.verify(caCert);
        System.out.println("ClientHello verified");

        // Send ServerHello
        HandshakeMessage serverHello = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        serverHello.putParameter("Certificate", Base64.getEncoder().encodeToString(serverCert.getBytes()));
        serverHello.send(socket);
        System.out.println("ServerHello sent");

        // Receive Session message
        HandshakeMessage sessionMessage = HandshakeMessage.recv(socket);

        // Parse Base64 encoded encrypted SessionKey and IV
        byte[] encryptedSessionKey = Base64.getDecoder().decode(sessionMessage.getParameter("SessionKey"));
        byte[] encryptedSessionIV = Base64.getDecoder().decode(sessionMessage.getParameter("SessionIV"));

        // Decrypt using server private key
        byte[] decryptedSessionKey = serverCrypto.decrypt(encryptedSessionKey);
        byte[] decryptedSessionIV = serverCrypto.decrypt(encryptedSessionIV);

        // Check whether the Key and IV lengths after decryption are correct
        if (decryptedSessionKey.length != 16 || decryptedSessionIV.length != 16) {
            throw new RuntimeException("Invalid SessionKey or IV length");
        }

        System.out.println("Session message received and decrypted");
        return new SessionCipher(new SessionKey(decryptedSessionKey), decryptedSessionIV);

    }
}