import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class Lab_13 {

    public static byte[] encrypt(byte[] key, byte[] iv, byte[] plaintext) throws Exception {
        BufferedBlockCipher cipher = new BufferedBlockCipher(new CFBBlockCipher(new AESEngine(), 128));
        CipherParameters params = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.init(true, params);
        byte[] output = new byte[cipher.getOutputSize(plaintext.length)];
        int bytesProcessed = cipher.processBytes(plaintext, 0, plaintext.length, output, 0);
        cipher.doFinal(output, bytesProcessed);
        return output;
    }

    public static byte[] decrypt(byte[] key, byte[] iv, byte[] ciphertext) throws Exception {
        BufferedBlockCipher cipher = new BufferedBlockCipher(new CFBBlockCipher(new AESEngine(), 128));
        CipherParameters params = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.init(false, params);
        byte[] output = new byte[cipher.getOutputSize(ciphertext.length)];
        int bytesProcessed = cipher.processBytes(ciphertext, 0, ciphertext.length, output, 0);
        cipher.doFinal(output, bytesProcessed);
        return output;
    }

    public static void main(String[] args) throws Exception {
        // Генерация случайного ключа и IV
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[16]; // 128-bit ключ
        random.nextBytes(key);
        byte[] iv = new byte[16]; // 128-bit IV
        random.nextBytes(iv);

        // Текст для шифрования
        String plaintextString = "Верблюд";
        byte[] plaintext = plaintextString.getBytes(StandardCharsets.UTF_8);

        // Шифрование
        byte[] ciphertext = encrypt(key, iv, plaintext);
        System.out.println("Зашифрованный текст: " + Hex.toHexString(ciphertext));

        // Расшифрование
        byte[] decryptedText = decrypt(key, iv, ciphertext);
        System.out.println("Расшифрованный текст: " + new String(decryptedText, StandardCharsets.UTF_8));
    }
}
