import base64
import getpass
import hashlib
import sys
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ModuleNotFoundError as error:
    print(error)
    print('Enter the command: pip install cryptography')
    sys.exit()


class TextEncryption():
    def __init__(self, password):
        self.password = password

    def encrypt(self, plaintext):
        fernet_key = self.get_fernet_key(self.password)
        ciphertext = fernet_key.encrypt(plaintext.encode()).decode()
        return ciphertext

    def decrypt(self, ciphertext):
        try:
            fernet_key = self.get_fernet_key(self.password)
            plaintext = fernet_key.decrypt(ciphertext.encode()).decode()
            return plaintext
        except InvalidToken:
            print('Error: invalid text or password')

    def get_fernet_key(self, password):
        salt = self.get_hash(password)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=500_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        f = Fernet(key)
        return f

    @staticmethod
    def get_hash(password):
        h = hashlib.new('sha512')
        h.update(password.encode())
        return h.digest()


def main():
    source = input('Do you want to open a text file [Y/n]? ')
    if source == 'n' or source == 'N':
        text = input('Enter text: ')
    else:
        try:
            filename = input('Enter text filename: ')
            with open(filename, 'r') as file:
                text = file.read()
        except FileNotFoundError as error:
            print(error)
            return
    if len(text) > 0:
        password = getpass.getpass(prompt='Enter password: ', stream=None)
        if len(password) > 0:
            mode = input('Do you want to encrypt or decrypt the text [E/d]? ')
            if mode == 'd' or mode == 'D':
                plaintext = TextEncryption(password).decrypt(text)
                if plaintext is not None:
                    if source == 'n' or source == 'N':
                        print(f'Plaintext: {plaintext}')
                    else:
                        file = open('plaintext.txt', 'w')
                        file.write(plaintext)
                        file.close()
                        print(f'Plaintext saved as plaintext.txt')
            else:
                ciphertext = TextEncryption(password).encrypt(text)
                if source == 'n' or source == 'N':
                    print(f'Ciphertext: {ciphertext}')
                else:
                    file = open('ciphertext.txt', 'w')
                    file.write(ciphertext)
                    file.close()
                    print(f'Ciphertext saved as ciphertext.txt')
        else:
            print('Error: empty password')
            return
    else:
        print('Error: empty text')
        return        


if __name__ == '__main__':
    main()
