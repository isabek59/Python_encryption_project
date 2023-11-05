import string
from src.globals import russian_alphabet, alphabet_len


class Decryption:
    @staticmethod
    def caesar_decrypt(encrypted_text, shift):
        """
        Decrypts a Caesar cipher encrypted text.

        Parameters:
        - encrypted_text (str): The text to be decrypted.
        - shift (int): The number of positions each letter is shifted during encryption.

        Returns:
        - str: The decrypted text.
        """
        decrypted_text = ''
        for index in range(len(encrypted_text)):
            if encrypted_text[index] in string.ascii_letters:
                if encrypted_text[index].isupper():
                    decrypted_text += chr((ord(encrypted_text[index]) - ord('A') - shift) % alphabet_len + ord('A'))
                elif encrypted_text[index].islower():
                    decrypted_text += chr((ord(encrypted_text[index]) - ord('a') - shift) % alphabet_len + ord('a'))
            elif encrypted_text[index] in russian_alphabet:
                decrypted_text += chr((ord(encrypted_text[index]) - ord('А') - shift) % 66 + ord('А'))
            else:
                decrypted_text += encrypted_text[index]
        return decrypted_text

    @staticmethod
    def vigenere_decrypt(encrypted_text, key):
        """
        Decrypts a Vigenere cipher encrypted text.

        Parameters:
        - encrypted_text (str): The text to be decrypted.
        - key (str): The key used for encryption.

        Returns:
        - str: The decrypted text.
        """
        key_len = len(key)
        decrypted_text = ''
        key_code = [ord(elem.upper()) - ord('A') for elem in key]

        for index in range(len(encrypted_text)):
            if encrypted_text[index] in string.ascii_letters:
                if encrypted_text[index].isupper():
                    decrypted_text += chr(
                        (ord(encrypted_text[index]) - ord('A') - key_code[index % key_len]) % alphabet_len + ord('A'))
                elif encrypted_text[index].islower():
                    decrypted_text += chr(
                        (ord(encrypted_text[index]) - ord('a') - key_code[index % key_len]) % alphabet_len + ord('a'))
            elif encrypted_text[index] in russian_alphabet:
                decrypted_text += chr(
                    (ord(encrypted_text[index]) - ord('А') - key_code[index % key_len]) % 66 + ord('А'))
            else:
                decrypted_text += encrypted_text[index]
        return decrypted_text

    @staticmethod
    def vernam_decrypt(encrypted_text, key):
        """
        Decrypts a Vernam cipher (One-Time Pad) encrypted text.

        Parameters:
        - encrypted_text (str): The text to be decrypted.
        - key (str): The key used for encryption.

        Returns:
        - str: The decrypted text.
        """
        decrypted_text = ''
        key_len = len(key)
        key_code = [ord(elem.upper()) - ord('A') for elem in key]

        for index in range(len(encrypted_text)):
            if encrypted_text[index].isupper():
                decrypted_text += chr(((ord(encrypted_text[index]) - ord('A')) ^ key_code[index % key_len]) + ord('A'))
            elif encrypted_text[index].islower():
                decrypted_text += chr(((ord(encrypted_text[index]) - ord('a')) ^ key_code[index % key_len]) + ord('a'))
            else:
                decrypted_text += encrypted_text[index]

        return decrypted_text

    @staticmethod
    def frequency_analysis(text):
        letter_frequency = {char: 0 for char in string.ascii_lowercase}
        total_letters = 0

        for char in text.lower():
            if char.isalpha():
                letter_frequency[char] += 1
                total_letters += 1

        sorted_frequency = sorted(letter_frequency.items(), key=lambda x: x[1], reverse=True)
        return sorted_frequency

    @staticmethod
    def caesar_auto_decrypt(ciphertext):
        frequencies = Decryption.frequency_analysis(ciphertext)
        most_frequent_letter = frequencies[0][0]
        shift = (ord(most_frequent_letter) - ord('e')) % 26
        return Decryption.caesar_decrypt(ciphertext, shift)
