import java.util.Scanner;
import java.nio.charset.StandardCharsets;

public class Lab_11 {
    public static class XORCipher {
        private final byte[] key;

        public XORCipher(byte[] key) {
            this.key = key;
        }

        public byte[] encrypt(byte[] input) {
            byte[] output = new byte[input.length];
            for (int i = 0; i < input.length; i++) {
                output[i] = (byte) (input[i] ^ key[i % key.length]);
            }
            return output;
        }
    }

    private final XORCipher xorCipher;

    public Lab_11(byte[] key) {
        this.xorCipher = new XORCipher(key);
    }

    public byte[] hash(byte[] message) {
        byte[] hash = new byte[16]; // Фиксированный размер хэша 128 бит (16 байт)
        byte[] block = new byte[16]; // Фиксированный размер блока 128 бит (16 байт)

        // Инициализация начального хэша
        for (int i = 0; i < hash.length; i++) {
            hash[i] = (byte) i; // Просто для примера, можно выбрать другое начальное значение
        }

        // Добавление сообщения
        int numBlocks = (int) Math.ceil((double) message.length / block.length);
        for (int i = 0; i < numBlocks; i++) {
            int blockLength = Math.min(block.length, message.length - i * block.length);
            System.arraycopy(message, i * block.length, block, 0, blockLength);

            // Применение блочного шифра (XOR в данном случае)
            hash = xorCipher.encrypt(hash);
            for (int j = 0; j < block.length; j++) {
                hash[j % hash.length] ^= block[j % block.length];
            }
        }

        return hash;
    }

    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Введите сообщение: ");
            String inputMessage = scanner.nextLine();
            byte[] message = inputMessage.getBytes(StandardCharsets.UTF_8);

            System.out.print("Введите ключ: ");
            String inputKey = scanner.nextLine();
            byte[] key = inputKey.getBytes(StandardCharsets.UTF_8);

            Lab_11 hashFunction = new Lab_11(key);
            byte[] hashedMessage = hashFunction.hash(message);

            System.out.println("Hashed message: " + bytesToHex(hashedMessage));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
