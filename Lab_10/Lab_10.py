from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import secrets

# Функция для генерации случайного ключа
def generate_symmetric_key():
    return secrets.token_bytes(32)  # Генерируем ключ длиной 32 байта (256 бит)

# Функция для шифрования сообщения
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message.encode(), AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return base64.b64encode(encrypted_message)

# Функция для дешифрования сообщения
def decrypt_message(encrypted_message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_message = base64.b64decode(encrypted_message)
    decrypted_message = cipher.decrypt(encrypted_message)
    return unpad(decrypted_message, AES.block_size).decode()

# Функция для генерации ключей RSA и сохранения их в файл
def generate_and_save_rsa_keys(file_prefix):
    # Генерация закрытого и открытого ключей RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Сохранение закрытого ключа в файл
    with open(f"{file_prefix}_private.pem", "wb") as private_key_file:
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file.write(private_key_pem)

    # Сохранение открытого ключа в файл
    with open(f"{file_prefix}_public.pem", "wb") as public_key_file:
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_file.write(public_key_pem)

    print("Ключи RSA успешно сгенерированы и сохранены в файлах.")

# Функция для загрузки ключа RSA из файла
def load_rsa_key_from_file(file_path, key_type):
    with open(file_path, "rb") as key_file:
        if key_type == "public":
            return serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        elif key_type == "private":
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

# Функция для выбора симметричного ключа по номеру
def select_symmetric_key(symmetric_key_number):
    # Преобразование номера ключа в байтовую строку
    symmetric_key_number_bytes = str(symmetric_key_number).encode()
    # Хеширование номера ключа для генерации симметричного ключа
    hashed_key = hashlib.sha256(symmetric_key_number_bytes).digest()
    return hashed_key

# Пример использования
if __name__ == "__main__":
    # Генерируем и сохраняем ключи RSA для пользователя Алисы
    file_prefix = "alice_keys"
    generate_and_save_rsa_keys(file_prefix)

    # Генерируем общий симметричный ключ для шифрования сообщений
    symmetric_key = generate_symmetric_key()

    # Пользователь 1 (Алиса) отправляет сообщение пользователю 2 (Бобу)
    plaintext_to_bob = "Привет, Боб!"
    encrypted_message_to_bob = encrypt_message(plaintext_to_bob, symmetric_key)
    print("Зашифрованное сообщение от Алисы для Боба:", encrypted_message_to_bob)

    # Пользователь 2 (Боб) получает и дешифрует сообщение от пользователя 1 (Алисы)
    decrypted_message_from_alice = decrypt_message(encrypted_message_to_bob, symmetric_key)
    print("Дешифрованное сообщение для Боба от Алисы:", decrypted_message_from_alice)

    # Генерируем и сохраняем ключи RSA для пользователя Боба
    file_prefix = "bob_keys"
    generate_and_save_rsa_keys(file_prefix)

    # Пользователь Боб загружает свой закрытый ключ RSA
    bob_private_key = load_rsa_key_from_file("bob_keys_private.pem", "private")

    # Пользователь Боб принимает симметричный ключ от Алисы
    symmetric_key_from_alice = b'...'  # Предположим, что ключ был передан напрямую

    # Пользователь Боб выбирает соответствующий симметричный ключ для обмена сообщениями с Алисой
    symmetric_key = select_symmetric_key(symmetric_key_from_alice)

    # Пользователь Боб принимает открытый текст от Алисы и шифрует его
    # В качестве примера, предположим, что открытый текст - это просто строка
    plaintext_from_alice = "Hello, Alice!"
    # Шифрование для двух различных кодировок текста: ASCII и UTF-8
    encrypted_message_ascii = encrypt_message(plaintext_from_alice, symmetric_key)
    encrypted_message_utf8 = encrypt_message(plaintext_from_alice, symmetric_key)
    print("Зашифрованное сообщение от Алисы для Боба (ASCII):", encrypted_message_ascii)
    print("Зашифрованное сообщение от Алисы для Боба (UTF-8):", encrypted_message_utf8)

    # Пользователь 2 (Боб) получает и дешифрует сообщение от пользователя 1 (Алисы)
    decrypted_message_ascii = decrypt_message(encrypted_message_ascii, symmetric_key)
    decrypted_message_utf8 = decrypt_message(encrypted_message_utf8, symmetric_key)
    print("Дешифрованное сообщение для Боба от Алисы (ASCII):", decrypted_message_ascii)
    print("Дешифрованное сообщение для Боба от Алисы (UTF-8):", decrypted_message_utf8)

