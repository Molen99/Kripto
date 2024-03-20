from Crypto.Cipher import DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import os


def generate_key():
    return get_random_bytes(16)


def save_key_to_file(key, filename):
    with open(filename, 'wb') as file:
        file.write(key)


def load_key_from_file(filename):
    with open(filename, 'rb') as file:
        return file.read()


def encrypt_message(message, key, algorithm, encoding):
    if algorithm == 'TripleDES':
        cipher = DES3.new(key, DES3.MODE_ECB)
    elif algorithm == 'AES':
        cipher = AES.new(key, AES.MODE_ECB)
    else:
        raise ValueError("Unsupported algorithm")

    message_bytes = message.encode(encoding)
    padded_message = pad(message_bytes, max(len(key), 16))
    encrypted_message = cipher.encrypt(padded_message)
    return base64.b64encode(encrypted_message).decode('utf-8')


def decrypt_message(encrypted_message, key, algorithm, encoding):
    if algorithm == 'TripleDES':
        cipher = DES3.new(key, DES3.MODE_ECB)
    elif algorithm == 'AES':
        cipher = AES.new(key, AES.MODE_ECB)
    else:
        raise ValueError("Unsupported algorithm")

    encrypted_message = base64.b64decode(encrypted_message)
    decrypted_message = cipher.decrypt(encrypted_message)
    decrypted_message = unpad(decrypted_message, max(len(key), 16))
    return decrypted_message.decode(encoding)


def read_from_file(filename):
    with open(filename, 'r') as file:
        return file.read()


def write_to_file(filename, content):
    with open(filename, 'w') as file:
        file.write(content)


def main():
    algorithm = input("Выберите алгоритм шифрования (TripleDES - T, AES - A): ").strip().upper()
    if algorithm == 'T':
        algorithm = 'TripleDES'
    elif algorithm == 'A':
        algorithm = 'AES'
    else:
        print("Неподдерживаемый алгоритм.")
        return

    key_filename = input("Введите имя файла для сохранения/загрузки ключа: ").strip()
    if os.path.exists(key_filename):
        key = load_key_from_file(key_filename)
    else:
        key = generate_key()
        save_key_to_file(key, key_filename)

    encoding = input("Выберите кодировку текста (UTF-8 - U, Windows-1251 - W): ").strip().upper()
    if encoding == 'U':
        encoding = 'UTF-8'
    elif encoding == 'W':
        encoding = 'Windows-1251'
    else:
        print("Неподдерживаемая кодировка.")
        return

    mode = input("Выберите режим работы (шифрование - E, расшифрование - D): ").strip().upper()
    if mode == 'E':
        mode = 'Encryption'
    elif mode == 'D':
        mode = 'Decryption'
    else:
        print("Неподдерживаемый режим работы.")
        return

    input_type = input("Выберите источник ввода (клавиатура - K, файл - F): ").strip().upper()
    if input_type == 'K':
        input_type = 'Keyboard'
    elif input_type == 'F':
        input_type = 'File'
    else:
        print("Неподдерживаемый источник ввода.")
        return

    if mode == 'Encryption':
        message = ""
        if input_type == 'Keyboard':
            print("Введите сообщение для шифрования (для завершения ввода введите 'end'):")
            while True:
                letter = input("Введите букву: ")
                if letter.lower() == 'end':
                    break
                message += letter
        else:
            message = read_from_file(input("Введите путь к файлу с открытым текстом: "))
        encrypted_message = encrypt_message(message, key, algorithm, encoding)
        output_type = input("Выберите куда записать результат (экран - S, файл - F): ").strip().upper()
        if output_type == 'S':
            print("Зашифрованное сообщение:", encrypted_message)
        elif output_type == 'F':
            write_to_file(input("Введите путь к файлу для записи шифртекста: "), encrypted_message)
    elif mode == 'Decryption':
        encrypted_message = input("Введите шифртекст: ") if input_type == 'Keyboard' else read_from_file(
            input("Введите путь к файлу с шифртекстом: "))
        decrypted_message = decrypt_message(encrypted_message, key, algorithm, encoding)
        output_type = input("Выберите куда записать результат (экран - S, файл - F): ").strip().upper()
        if output_type == 'S':
            print("Расшифрованное сообщение:", decrypted_message)
        elif output_type == 'F':
            write_to_file(input("Введите путь к файлу для записи открытого текста: "), decrypted_message)
    else:
        print("Неподдерживаемый режим работы")

if __name__ == "__main__":
    main()
