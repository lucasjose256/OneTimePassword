import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class PasswordGeneratorApp {
    private final String username;
    private final String seedPassword;
    private final String salt;

    public PasswordGeneratorApp(String username, String seedPassword, String salt) {
        this.username = username;
        this.seedPassword = seedPassword;
        this.salt = salt;
    }

    private String generateHash(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash).substring(0, 8);
    }

    public List<String> generateOTPList(String seedPassword, String salt) throws NoSuchAlgorithmException {
        List<String> otpList = new ArrayList<>();
        String timeFactor = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmm"));

        for (int i = 0; i < 5; i++) {
            // Concatena a senha semente, o salt, o timeFactor e o índice para criar uma variação única de OTP
            String otpSource = seedPassword + salt + timeFactor + i;
            String otp = generateHash(otpSource).substring(0, 8);  // Gera uma OTP com 8 caracteres
            otpList.add(otp);
        }

        return otpList;
    }

    public void saveToFile(List<String> otpList) {
        try (PrintWriter writer = new PrintWriter(new FileWriter("otp_data.txt"))) {
            writer.println("Username: " + username);
            writer.println("SeedPasswordHash: " + generateHash(seedPassword));
            writer.println("SaltHash: " + generateHash(salt));
            writer.println("OTP List:");

            for (String otp : otpList) {
                writer.println(otp);
                System.out.println(otp);
            }

            System.out.println("Dados salvos em otp_data.txt");
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        String username = "lucas";
        String seedPassword = "seed";
        String salt = "salt123";

        PasswordGeneratorApp generatorApp = new PasswordGeneratorApp(username, seedPassword, salt);
        try {
            List<String> otpList = generatorApp.generateOTPList(seedPassword,salt);
            generatorApp.saveToFile(otpList);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}