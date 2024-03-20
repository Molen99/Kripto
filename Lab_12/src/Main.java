import java.io.*;
import java.security.*;


public class Main {

    // Генерация ключей для подписи
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024); // Размер ключа
        return keyPairGenerator.generateKeyPair();
    }

    // Подписание данных
    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA1withDSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    // Проверка подписи
    public static boolean verifySignature(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA1withDSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    public static void main(String[] args) {
        try {
            // Генерация ключей
            KeyPair keyPair = generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Пример данных для подписи
            String data = "Hello, World!";
            byte[] dataBytes = data.getBytes();

            // Подписание данных
            byte[] signature = signData(dataBytes, privateKey);

            // Сохранение подписи в файл
            FileOutputStream signatureOut = new FileOutputStream("signature.txt");
            signatureOut.write(signature);
            signatureOut.close();

            // Проверка подписи
            FileInputStream signatureIn = new FileInputStream("signature.txt");
            byte[] signatureBytes = signatureIn.readAllBytes();
            signatureIn.close();

            boolean verified = verifySignature(dataBytes, signatureBytes, publicKey);
            System.out.println("Signature verified: " + verified);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
