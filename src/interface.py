import tkinter as tk
from tkinter.filedialog import askopenfilename
from src.encrypt import Encryption
from src.decrypt import Decryption
from src.globals import *


class Interface:
    def __init__(self):
        """
        Initialize the Interface class with necessary attributes.

        Attributes:
        - decryption_var (tk.StringVar): Variable to store the decryption type selected by the user.
        - key_var (tk.StringVar): Variable to store the encryption/decryption key entered by the user.
        - shift_var (tk.IntVar): Variable to store the shift value used in Caesar encryption/decryption.
        - decode_area (tk.Text): Text widget for displaying decrypted text.
        - encode_area (tk.Text): Text widget for displaying encrypted text.
        - encryption_var (tk.StringVar): Variable to store the encryption type selected by the user.
        - root (tk.Tk): The main tkinter window.
        """
        self.decryption_var = None
        self.key_var = None
        self.shift_var = None
        self.decode_area = None
        self.encode_area = None
        self.encryption_var = None
        self.root = tk.Tk()
        self.root.resizable(False, False)
        self.root.title('PythonEncryption')
        self.create_widgets()

    def start(self):
        """
        Start the tkinter main event loop to display the interface.
        """
        self.root.mainloop()

    def create_widgets(self):
        """
        Create and layout the tkinter widgets for the encryption/decryption interface.
        """
        self.encode_area = tk.Text(self.root, height=text_height, width=text_width)
        self.encode_area.pack(side=tk.LEFT, padx=pad_x, pady=pad_y)

        self.decode_area = tk.Text(self.root, height=text_height, width=text_width)
        self.decode_area.pack(side=tk.RIGHT, padx=pad_x, pady=pad_y)

        self.encryption_var = tk.StringVar()
        self.encryption_var.set("Caesar")  # Default encryption type
        encryption_menu = tk.OptionMenu(self.root, self.encryption_var, "Caesar", "Vigenere", "Vernam")
        encryption_menu.pack(side=tk.TOP, padx=pad_x, pady=pad_y)

        shift_label = tk.Label(self.root, text="Shift:")
        shift_label.pack(side=tk.TOP, padx=pad_x)

        self.shift_var = tk.IntVar()
        self.shift_var.set(default_shift)
        shift_entry = tk.Entry(self.root, textvariable=self.shift_var, width=5)
        shift_entry.pack(side=tk.TOP, padx=pad_x)

        key_label = tk.Label(self.root, text="Key:")
        key_label.pack(side=tk.TOP, padx=pad_x)

        self.key_var = tk.StringVar()
        self.key_var.set(default_key)
        key_entry = tk.Entry(self.root, textvariable=self.key_var, width=10)
        key_entry.pack(side=tk.TOP, padx=pad_x, pady=pad_y)

        encrypt_button = tk.Button(self.root, text="Encrypt", command=self.encrypt_text)
        encrypt_button.pack(side=tk.TOP, padx=pad_x, pady=pad_y)

        choose_file_button = tk.Button(self.root, text="Choose file", command=self.choose_file)
        choose_file_button.pack(side=tk.TOP, padx=pad_x, pady=pad_y)

        hack_button = tk.Button(self.root, text="Hack", command=self.hack_text)
        hack_button.pack(side=tk.BOTTOM, padx=pad_x, pady=pad_y)

        self.decryption_var = tk.StringVar()
        self.decryption_var.set("Caesar")  # Default decryption type
        decryption_menu = tk.OptionMenu(self.root, self.decryption_var, "Caesar", "Vigenere", "Vernam")
        decryption_menu.pack(side=tk.BOTTOM, padx=pad_x, pady=pad_y)

        decrypt_button = tk.Button(self.root, text="Decrypt", command=self.decrypt_text)
        decrypt_button.pack(side=tk.BOTTOM, padx=pad_x, pady=pad_y)

    def encrypt_text(self):
        """
        Encrypt the text in the encode_area based on the selected encryption type and display the result in the
        decode_area.
        """
        encryption = Encryption()
        text_to_encrypt = self.encode_area.get("1.0", "end-1c")

        selected_encryption = self.encryption_var.get()

        if selected_encryption == "Caesar":
            shift_value = self.shift_var.get()
            encrypted_text = encryption.caesar_encrypt(text_to_encrypt, shift_value)
        elif selected_encryption == "Vigenere":
            encryption_key = self.key_var.get()
            encrypted_text = encryption.vigenere_encrypt(text_to_encrypt, encryption_key)
        elif selected_encryption == "Vernam":
            encryption_key = self.key_var.get()
            encrypted_text = encryption.vernam_encrypt(text_to_encrypt, encryption_key)
        else:
            encrypted_text = "Invalid encryption type"

        self.decode_area.delete("1.0", tk.END)
        self.decode_area.insert(tk.END, encrypted_text)

    def decrypt_text(self):
        """
        Decrypt the text in the decode_area based on the selected decryption type and display the result in the
        encode_area.
        """
        decryption = Decryption()
        text_to_decrypt = self.decode_area.get("1.0", 'end-1c')

        selected_decryption = self.decryption_var.get()

        if selected_decryption == "Caesar":
            shift_value = self.shift_var.get()
            decrypted_text = decryption.caesar_decrypt(text_to_decrypt, shift_value)
        elif selected_decryption == "Vigenere":
            decryption_key = self.key_var.get()
            decrypted_text = decryption.vigenere_decrypt(text_to_decrypt, decryption_key)
        elif selected_decryption == "Vernam":
            decryption_key = self.key_var.get()
            decrypted_text = decryption.vernam_decrypt(text_to_decrypt, decryption_key)
        else:
            decrypted_text = "Invalid decryption type"

        self.encode_area.delete("1.0", tk.END)
        self.encode_area.insert(tk.END, decrypted_text)

    def choose_file(self):
        """
        Allow the user to choose a .txt file and insert its content into the encode_area.
        """
        file_path = askopenfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])

        if not file_path:
            return  # User canceled the file selection

        with open(file_path, 'r', encoding='utf-8') as file:
            file_content = file.read()

        self.encode_area.delete("1.0", tk.END)
        self.encode_area.insert(tk.END, file_content)

    def hack_text(self):
        """
        Apply caesar_auto_decrypt to the text in decode_area and display the result in encode_area.
        """
        decryption = Decryption()
        text_to_decrypt = self.decode_area.get("1.0", 'end-1c')

        decrypted_text = decryption.caesar_auto_decrypt(text_to_decrypt)

        self.encode_area.delete("1.0", tk.END)
        self.encode_area.insert(tk.END, decrypted_text)
