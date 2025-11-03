import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Base64;
import java.util.Arrays;


public class FileDigest {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java FileDigest <filename>");
            System.exit(1);
        }

        String fileName = args[0];

        try {
            File file = new File(fileName);
            if (!file.exists() || !file.isFile()) {
                System.err.println("File not found or is not a valid file: " + fileName);
                System.exit(1);
            }

            // 使用 HandshakeDigest 计算文件的哈希值
            HandshakeDigest handshakeDigest = new HandshakeDigest();

            try (InputStream inputStream = new FileInputStream(file)) {
                byte[] buffer = new byte[8192];
                int bytesRead;

                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    handshakeDigest.update(Arrays.copyOf(buffer, bytesRead)); // 更新摘要
                }
            }

            byte[] hash = handshakeDigest.digest();

            // 将哈希值编码为 Base64
            String base64Hash = Base64.getEncoder().encodeToString(hash);
            System.out.println(base64Hash);

        } catch (Exception e) {
            System.err.println("Error computing digest for file: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
