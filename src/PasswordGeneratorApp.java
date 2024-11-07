import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class PasswordGeneratorApp {
    private final String username;
    private final String seedPasswordHash;
    private final String saltHash;
    private final String localPasswordHash;

    public PasswordGeneratorApp(String username, String seedPasswordHash, String saltHash, String localPassword) throws NoSuchAlgorithmException {
        this.username = username;
        this.seedPasswordHash = seedPasswordHash;
        this.saltHash = saltHash;
        this.localPasswordHash = generateHash(localPassword);
    }

    private String generateHash(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash).substring(0, 8);
    }

    public List<String> generateOTPList() throws NoSuchAlgorithmException {
        List<String> otpList = new ArrayList<>();
        String timeFactor = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmm"));

        for (int i = 0; i < 5; i++) {
            String otpSource = seedPasswordHash + saltHash + timeFactor + i;
            String otp = generateHash(otpSource).substring(0, 8);
            otpList.add(otp);
        }

        return otpList;
    }

    public void saveToFile(List<String> otpList) {
        try (PrintWriter writer = new PrintWriter(new FileWriter("otp_data.txt"))) {
            writer.println("Username: " + username);
            writer.println("SeedPasswordHash: " + seedPasswordHash);
            writer.println("SaltHash: " + saltHash);
            writer.println("LocalPasswordHash: " + localPasswordHash);
            writer.println("OTP List:");

            for (String otp : otpList) {
                writer.println(otp);
            }

            System.out.println("Dados salvos em otp_data.txt");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static boolean verifyHash(String input, String storedHash) throws NoSuchAlgorithmException {
        String inputHash = new PasswordGeneratorApp("", "", "", "").generateHash(input);
        return inputHash.equals(storedHash);
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        File file = new File("otp_data.txt");
        if (!file.exists()) {
            System.out.println("Primeiro acesso. Vamos criar seu usuário.");

            System.out.print("Digite o nome de usuário: ");
            String username = scanner.nextLine();

            System.out.print("Digite a senha semente: ");
            String seedPassword = scanner.nextLine();

            System.out.print("Digite o salt: ");
            String salt = scanner.nextLine();

            System.out.print("Digite uma senha local para proteger o gerador de senhas: ");
            String localPassword = scanner.nextLine();

            try {
                String seedPasswordHash = new PasswordGeneratorApp("", "", "", "").generateHash(seedPassword);
                String saltHash = new PasswordGeneratorApp("", "", "", "").generateHash(salt);

                PasswordGeneratorApp generatorApp = new PasswordGeneratorApp(username, seedPasswordHash, saltHash, localPassword);
                List<String> otpList = generatorApp.generateOTPList();
                generatorApp.saveToFile(otpList);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        } else {
            System.out.print("Digite o nome de usuário: ");
            String username = scanner.nextLine();

            System.out.print("Digite a senha local: ");
            String localPassword = scanner.nextLine();

            try (BufferedReader reader = new BufferedReader(new FileReader("otp_data.txt"))) {
                String line;
                String storedUsername = null;
                String storedSeedPasswordHash = null;
                String storedSaltHash = null;
                String storedLocalPasswordHash = null;

                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("Username: ")) {
                        storedUsername = line.split(": ")[1];
                    } else if (line.startsWith("SeedPasswordHash: ")) {
                        storedSeedPasswordHash = line.split(": ")[1];
                    } else if (line.startsWith("SaltHash: ")) {
                        storedSaltHash = line.split(": ")[1];
                    } else if (line.startsWith("LocalPasswordHash: ")) {
                        storedLocalPasswordHash = line.split(": ")[1];
                    }
                }

                if (storedUsername == null || !storedUsername.equals(username) ||
                        storedLocalPasswordHash == null || !verifyHash(localPassword, storedLocalPasswordHash)) {

                    System.out.println("Credenciais incorretas! Acesso negado.");
                    return;
                }

                System.out.println("Acesso autorizado.");

                PasswordGeneratorApp generatorApp = new PasswordGeneratorApp(username, storedSeedPasswordHash, storedSaltHash, localPassword);
                List<String> otpList = generatorApp.generateOTPList();
                generatorApp.saveToFile(otpList);
            } catch (IOException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
    }
}
