import platform
from tkinter import messagebox
from tkinter.ttk import *
from tkinter import *

import hashlib
import pyAesCrypt
import os

from data.profile_class import *

bufferSize = 64 * 1024
if platform.system() == "Windows":
    path = "images\\"
if platform.system() == 'Darwin':
    dir_path = os.getcwd()
    path = dir_path + "/images/"

class Login:
    def __init__(self, username, password):
        self.username = str(username)
        self.password = str(password)
        
    def login_checking(self):  # verifying the user
        for_hashing_both = self.password + self.username
        main_password = hashlib.sha3_512(
            for_hashing_both.encode()
        ).hexdigest()
        if self.username == "Username":
            # checking for blank username
            root_error = Tk()
            root_error.withdraw()
            messagebox.showerror("Error", "Cannot have blank Username ")
            root_error.destroy()
            return False, main_password
        elif self.password == "Password":
            # checking for blank password
            root_error = Tk()
            root_error.withdraw()
            messagebox.showerror("Error", "Password cannot be empty ")
            root_error.destroy()
            return False, main_password, self.password
        else:
            for_hashing_both = self.password + self.username
            if os.path.exists(f"{self.username}.bin.fenc"):
                try:
                    # trying to decrypt the users file to check whether the password entered is valid
                    pyAesCrypt.decryptFile(
                        self.username + ".bin.fenc",
                        self.username + "decrypted.bin",
                        main_password,
                        bufferSize,
                    )
                except ValueError:  # if the password is incorrect
                    root = Tk()
                    root.withdraw()
                    messagebox.showerror(
                        "Error",
                        f"Wrong password for {self.username}",
                    )
                    root.destroy()
                    return False, main_password, self.password
            else:
                root_error = Tk()
                root_error.withdraw()
                messagebox.showerror(
                    "Error",
                    f"{self.username} doesn't exist, Please register or provide the correct username",
                )
                root_error.destroy()
                return False, main_password, self.password
            return True, main_password, self.password
