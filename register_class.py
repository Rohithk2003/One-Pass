import platform
from tkinter import messagebox
from tkinter.ttk import *
from tkinter import *

import hashlib
import pyAesCrypt
import os
from main_encryption import *
from string_en import *
import secrets
import pyaes
import pbkdf2

bufferSize= 64*1024

class Register:
    def __init__(self, username, password, email_id, email_password, window_after):
        self.username = str(username)
        self.password = str(password)
        self.email_id = str(email_id)
        self.email_password = str(email_password)
        self.window = window_after
    def check_password_integrity(self, passw):
        self.p = passw
        if self.username == self.password:
            return False
        with open("pass.txt", 'r') as file:
            data = file.read().split()
            for i in data:
                if i == self.p:
                    return False

        return True

    def email_exists(self):
        print(self.email_id)
        print(type(self.email_id))
        return self.email_id.endswith(("gmail.com","yahho.com"))

    def check_pass_length(self):  # checking if the entered password is lesser than 5
        return len(self.password) >= 5

    """to create a file named user and to store his accounts and also add his details to the database"""

    def saving(self, object):

        object.execute("select username from data_input")
        values_username = object.fetchall()
        for i in values_username:
            for usernames in i:
                if simple_decrypt(usernames) == self.username and os.path.exists(
                        self.username + ".bin.fenc"
                ):
                    return (
                        True,
                    )  # checking whether the username already exists in the database

        email_split = ""
        word = self.email_id.split()
        for i in word:
            for a in i:
                if i == "@":
                    break
                else:
                    email_split += i
        val = email_split[::-1]
        main_password = val + "/" + self.email_password  # static salt
        static_salt_password = self.password + "@" + main_password
        # hashing/encrypting the password and store the dynamic salt created during creat_key() fn is called along with the encrypted password in database
        cipher_text, salt_for_decryption = create_key(
            main_password, static_salt_password
        )

        for_hashing = self.password + self.username
        """for encrypting the file"""
        hash_pass = hashlib.sha3_512(for_hashing.encode()).hexdigest()
        # for encrypting the recovery password

        password_recovery_email = self.email_id + hash_pass
        passwordSalt = secrets.token_bytes(512)
        key = pbkdf2.PBKDF2(password_recovery_email, passwordSalt).read(32)
        aes = pyaes.AESModeOfOperationCTR(key)
        encrypted_pass = aes.encrypt(self.email_password)
        try:
            object.execute(
                "insert into data_input values (?,?,?,?,?,?)",
                (
                    simple_encrypt(self.username),
                    simple_encrypt(self.email_id),
                    cipher_text,
                    salt_for_decryption,
                    encrypted_pass,
                    passwordSalt,
                ),
            )
        except:
            return True
        # so inserting the users details into database

        return False

    # adding the account
    def creation(self, window):
        try:
            window.destroy()
        except:
            pass
        for_hashing = self.password + self.username
        """for encrypting the file"""
        hash_pass = hashlib.sha3_512(for_hashing.encode()).hexdigest()

        file_name = self.username + ".bin"
        with open(file_name, "wb"):
            pyAesCrypt.encryptFile(
                file_name, file_name + ".fenc", hash_pass, bufferSize
            )
        os.remove(file_name)
        # to display that his account has been created
        windows = Tk()
        windows.withdraw()
        messagebox.showinfo("Success", "Your account has been created")
        windows.destroy()
        # for opening the main section where he can store his passwords and use notepad so the file has to be decrypted
        pyAesCrypt.decryptFile(
            file_name +
            ".fenc", f"{self.username}decrypted.bin", hash_pass, bufferSize
        )
        self.window(self.username, hash_pass, self.password)
