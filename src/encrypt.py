import string
from src.globals import russian_alphabet, alphabet_len


class Encryption:

    @staticmethod
    def caesar_encrypt(text, shift):
        """
        Encrypts the input text using the Caesar cipher with the specified shift.

        Parameters:
        - text (str): The input text to be encrypted.
        - shift (int): The shift value for the Caesar cipher.

        Returns:
        - str: The encrypted text.
        """
        encrypted_text = ''
        for index in range(len(text)):
            if text[index] in string.ascii_letters:
                if text[index].isupper():
                    encrypted_text += chr((ord(text[index]) - ord('A') + shift) % alphabet_len + ord('A'))
                elif text[index].islower():
                    encrypted_text += chr((ord(text[index]) - ord('a') + shift) % alphabet_len + ord('a'))
            elif text[index] in russian_alphabet:
                encrypted_text += chr((ord(text[index]) - ord('А') + shift) % 66 + ord('А'))
            else:
                encrypted_text += text[index]

        return encrypted_text

    @staticmethod
    def vigenere_encrypt(text, key):
        """
        Encrypts the input text using the Vigenere cipher with the specified key.

         Parameters:
        - text (str): The input text to be encrypted.
        - key (str): The key for the Vigenere cipher.

        Returns:
        - str: The encrypted text.
        """
        key_len = len(key)
        encrypted_text = ''
        key_code = [ord(elem.upper()) - ord('A') for elem in key]

        for index in range(len(text)):
            if text[index] in string.ascii_letters:
                if text[index].isupper():
                    encrypted_text += chr(
                        (ord(text[index]) - ord('A') + key_code[index % key_len]) % alphabet_len + ord('A'))
                elif text[index].islower():
                    encrypted_text += chr(
                        (ord(text[index]) - ord('a') + key_code[index % key_len]) % alphabet_len + ord('a'))
            elif text[index] in russian_alphabet:
                encrypted_text += chr((ord(text[index]) - ord('А') + key_code[index % key_len]) % 66 + ord('А'))
            else:
                encrypted_text += text[index]

        return encrypted_text

    @staticmethod
    def vernam_encrypt(text, key):
        """
        Encrypts the input text using the Vernam cipher (XOR) with the specified key.

        Parameters:
        - text (str): The input text to be encrypted.
        - key (str): The key for the Vernam cipher.

        Returns:
        - str: The encrypted text.
        """
        encrypted_text = ''
        key_len = len(key)
        key_code = [ord(elem.upper()) - ord('A') for elem in key]

        for index in range(len(text)):
            if text[index].isupper():
                encrypted_text += chr(((ord(text[index]) - ord('A')) ^ key_code[index % key_len]) + ord('A'))
            elif text[index].islower():
                encrypted_text += chr(((ord(text[index]) - ord('a')) ^ key_code[index % key_len]) + ord('a'))
            else:
                encrypted_text += text[index]

        return encrypted_text
