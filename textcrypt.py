import base64
import os
import getpass
import hashlib
import sys
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ModuleNotFoundError:
    print('Enter the command: pip install cryptography')
    sys.exit()


class TextCrypt():
    def __init__(self, password, code):
        self.password = password
        self.code = code

    def encrypt(self, plaintext):
        fernet_key = self.get_fernet_key(self.password, self.code)
        ciphertext = fernet_key.encrypt(plaintext.encode()).decode()
        try:
            ciphertext = ciphertext.split('gAAAAABj')[1]
        except IndexError:
            print('Error')
        return ciphertext

    def decrypt(self, ciphertext):
        try:
            ciphertext = f'gAAAAABj{ciphertext}'
            fernet_key = self.get_fernet_key(self.password, self.code)
            plaintext = fernet_key.decrypt(ciphertext.encode()).decode()
            return plaintext
        except InvalidToken:
            print('Error: incorrect text, password or code')

    def get_fernet_key(self, password, code):
        salt = self.get_hash(password, code)
        iterations = int(code) * 1000
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        f = Fernet(key)
        return f

    @staticmethod
    def get_hash(password, code):
        h = hashlib.sha512()
        h.update(password.encode())
        h.update(code.encode())
        return h.digest()


def main():
    from_file = input('Do you want to open a text file [Y/n]? ')
    if from_file == 'n' or from_file == 'N':
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
        if len(password) >= 8:
            code = getpass.getpass(prompt='Enter 4 digit code: ', stream=None)
            if code.isdigit() is True and len(code) == 4:
                mode = input('Do you want to encrypt or decrypt the text [E/d]? ')
                if mode == 'd' or mode == 'D':
                    if os.path.exists('plaintext.txt'):
                        print(f'Error: file plaintext.txt already exists')
                        return
                    else:
                        plaintext = TextCrypt(password, code).decrypt(text)
                        if plaintext is not None:
                            if from_file == 'n' or from_file == 'N':
                                print(f'Plaintext: {plaintext}')
                            else:
                                file = open('plaintext.txt', 'w')
                                file.write(plaintext)
                                file.close()
                                print(f'Plaintext saved as plaintext.txt')
                else:
                    if os.path.exists('ciphertext.txt'):
                        print(f'Error: file ciphertext.txt already exists')
                        return
                    else:
                        ciphertext = TextCrypt(password, code).encrypt(text)
                        if from_file == 'n' or from_file == 'N':
                            print(f'Ciphertext: {ciphertext}')
                        else:
                            file = open('ciphertext.txt', 'w')
                            file.write(ciphertext)
                            file.close()
                            print(f'Ciphertext saved as ciphertext.txt')
            else:
                print('Error: incorrect code')
                return
        else:
            print('Error: minimum password length: 8')
            return
    else:
        print('Error: empty text')
        return


if __name__ == '__main__':
    main()
