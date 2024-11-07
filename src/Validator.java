import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class Validator {
    private static final String SALT_FIXO = "salt123";
    private static final String USER_DB = "servidor.txt";
    private static List<Map<String, Object>> SENHAS_VALIDAS = new ArrayList<>();

    public static void main(String[] args) {
        try {
            ensureUserDB();
            Scanner scanner = new Scanner(System.in);

            System.out.print("Digite seu nome de usuário: ");
            String nome = scanner.nextLine().trim();

            System.out.print("Digite sua senha semente: ");
            String senha = scanner.nextLine();
            System.out.print("Digite seu sal");

            String senhaSalt =scanner.nextLine();


                System.out.println("Inicializando validador de senha.");
                Thread threadPeriodica = new Thread(() -> {
                    try {
                        threadGeraSenhaMinuto(senha,senhaSalt);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
                threadPeriodica.setDaemon(true);
                threadPeriodica.start();

                while (true) {
                    System.out.print("Digite a senha OTP: ");
                    String senhaOtp = scanner.nextLine().trim();
                    if (verificaSenha(senhaOtp)) {
                        System.out.println("Senha OTP válida! Acesso permitido.");
                        imprimeTabelaSenhas();
                    } else {
                        System.out.println("Senha OTP inválida. Tente novamente.");
                    }
                }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void ensureUserDB() throws IOException {
        if (!Files.exists(Paths.get(USER_DB))) {
            Files.createFile(Paths.get(USER_DB));
        }
    }

    private static void threadGeraSenhaMinuto(String seed,String sal) throws NoSuchAlgorithmException {
        LocalDateTime agora = LocalDateTime.now();
        SENHAS_VALIDAS = geradorSenhaOTP(seed,sal, agora);
        System.out.println("Horário atualizado: " + agora.format(DateTimeFormatter.ofPattern("HH:mm:ss")));
        imprimeTabelaSenhas();

        int minutoAnterior = agora.getMinute();
        while (true) {
            agora = LocalDateTime.now();
            if (agora.getMinute() != minutoAnterior) {
                SENHAS_VALIDAS = geradorSenhaOTP(seed,sal, agora);
                System.out.println("Horário atualizado: " + agora.format(DateTimeFormatter.ofPattern("HH:mm:ss")));
                imprimeTabelaSenhas();
                minutoAnterior = agora.getMinute();
            }
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private static List<Map<String, Object>> geradorSenhaOTP(String seed,String salt, LocalDateTime agora) throws NoSuchAlgorithmException {
        List<Map<String, Object>> listaSenhas = new ArrayList<>();
        String timeFactor = agora.format(DateTimeFormatter.ofPattern("yyyyMMddHHmm"));
        seed=hashSenha(seed);
        salt=hashSenha(salt);
        for (int i = 0; i < 5; i++) {
            Map<String, Object> senhaMap = new HashMap<>();
            senhaMap.put("senha", hashSenha(seed + salt+timeFactor + i).substring(0, 8));
            senhaMap.put("valido", true);
            senhaMap.put("indice", i);  // Índice para controlar a ordem
            listaSenhas.add(senhaMap);
        }
        return listaSenhas;
    }

    private static void imprimeTabelaSenhas() {
        System.out.println("Tabela de Senhas:");
        System.out.printf("%-10s %-10s %-10s\n", "Senha", "Valido", "Indice");
        for (Map<String, Object> senha : SENHAS_VALIDAS) {
            System.out.printf("%-10s %-10s %-10s\n", senha.get("senha"), senha.get("valido"), senha.get("indice"));
        }
    }

    private static boolean verificaSenha(String input) {
        for (Map<String, Object> senha : SENHAS_VALIDAS) {
            // Verifica se a senha está correta e ainda é válida
            if (senha.get("senha").equals(input) && (boolean) senha.get("valido")) {
                senha.put("valido", false);  // Invalida a senha usada
                invalidaSenhasPosteriores((int) senha.get("indice"));
                return true;  // Senha validada com sucesso
            }
        }
        return false;  // Senha não encontrada ou já inválida
    }


    private static void invalidaSenhasPosteriores(int indiceUsado) {
        for (Map<String, Object> senha : SENHAS_VALIDAS) {
            int indiceAtual = (int) senha.get("indice");
            if (indiceAtual > indiceUsado) {
                senha.put("valido", false);
            }
        }
    }

    private static boolean verificaUsuario(String nome, String senhaSalt) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(USER_DB))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length == 3 && parts[0].equals(nome) && parts[1].equals(senhaSalt)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static void cadastraUsuario(String nome, String senhaSalt) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(USER_DB, true))) {
            String criadoEm = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            writer.write(nome + "," + senhaSalt + "," + criadoEm);
            writer.newLine();
        }
    }

    private static String hashSenha(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash).substring(0, 8);
    }

    private static String rehashComSalt(String senhaHashed, String salt) throws NoSuchAlgorithmException {
        return hashSenha(senhaHashed + salt);
    }
}
