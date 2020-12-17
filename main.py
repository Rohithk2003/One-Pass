# all required modules
import base64
import glob
import hashlib
import os.path
import pickle
import pyAesCrypt

import random
import smtplib
import sqlite3
import pyaes
import pbkdf2
import os
import secrets
import threading

# tkinter modules
from PIL import Image as image
from PIL import ImageTk as tk_image
from tkinter import colorchooser
from tkinter import filedialog as fd
from tkinter import messagebox
from tkinter import simpledialog
from tkinter.ttk import *
from tkinter import *

# for encryption and decryption
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# for updating the file
from update_check import isUpToDate
from update_check import update

# main window
bufferSize = 64 * 1024

# database connection
if not os.path.exists("DATABASE"):
    os.mkdir("DATABASE")
connection = sqlite3.connect("DATABASE\\users.db", isolation_level=None)
my_cursor = connection.cursor()
my_cursor.execute(
    "create table if not exists data_input (username varchar(100) primary key,email_id varchar(100),password  blob,"
    "salt blob, recovery_password varchar(100), profile_path varchar(100),salt_recovery blob) "
)
# for image loading
l = [{"1": "images\\member.png"}]
# global values
catch_error = True
social_media_user_text = ""
social_media_active = False
image_path = ""
exist = False
cutting_value = False
file = 0
buttons_list = {}
btn_nr = -1

# login_class
root = Tk()
root.title("ONE-PASS")

width_window = 1057
height_window = 700

root.config(bg="#292A2D")
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = screen_width / 2 - width_window / 2
y = screen_height / 2 - height_window / 2
root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))


class Login:
    def __init__(self, username, password):
        self.username = str(username)
        self.password = str(password)

    def login_checking(self):  # verifying the user

        if self.username == "Username":
            # checking for blank username
            root_error = Tk()
            for_hashing_both = self.password + self.username
            main_password = hashlib.sha3_512(
                for_hashing_both.encode()
            ).hexdigest()  # hashing the  password for returning
            root_error.withdraw()
            messagebox.showerror("Error", "Cannot have blank Username ")
            root_error.destroy()
            return False, main_password
        elif self.password == "Password":
            # checking for blank password
            root_error = Tk()
            for_hashing_both = self.password + self.username
            main_password = hashlib.sha3_512(for_hashing_both.encode()).hexdigest()
            root_error.withdraw()
            messagebox.showerror("Error", "Password cannot be empty ")
            root_error.destroy()
            return False, main_password, self.password
        else:
            for_hashing_both = self.password + self.username
            main_password = hashlib.sha3_512(for_hashing_both.encode()).hexdigest()
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


class Profile_view:
    def __init__(
        self,
        username,
        password,
        email_id,
        email_password,
        hashed_password,
        profile,
        password_button,
        notepad_button,
    ):
        self.username = username
        self.password = password
        self.email_id = email_id
        self.email_password = email_password
        self.hashed_password = hashed_password

        for widget in profile.winfo_children():
            widget.destroy()

        self.password_button = password_button
        self.notepad = notepad_button

    def profile_window(self, profile, s, profile_button):
        profile_button["state"] = DISABLED
        self.password_button["state"] = NORMAL
        self.notepad["state"] = NORMAL
        try:
            for widget in profile.winfo_children():
                widget.destroy()
        except:
            pass
        profile.config(bg="#292A2D")
        s.title("Profile")
        s.title("Passwords")

        emptyMenu = Menu(s)

        s.config(menu=emptyMenu)

        s.iconbitmap(default="images\\new_icon.ico")
        # profile window image
        member = tk_image.PhotoImage(image.open("images\\member.png"))

        profileimg = tk_image.PhotoImage(image.open("images\\profile_image.png"))
        new_canvas = Canvas(profile, width=1270, height=700, highlightthickness=0)
        new_canvas.place(x=0, y=0)
        new_canvas.background = profileimg
        new_canvas.create_image(0, 0, image=profileimg, anchor="nw")
        new_s = Frame(
            new_canvas,
            bg="#292A2D",
            highlightcolor="black",
            highlightbackground="black",
            width=560,
            height=500,
        )

        MainWindow = new_canvas.create_window(
            600 - 30, 300 + 50, window=new_s, anchor="center"
        )

        # all labels
        username_label = Label(
            new_s,
            text="Username",
            font="consolas 15",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )
        password_label = Label(
            new_s,
            text="Password",
            font="consolas 15",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )
        email_id_label = Label(
            new_s,
            text="Email",
            font="consolas 15",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )
        email_password_label = Label(
            new_s,
            text="Email Password",
            font="consolas 15",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )

        # details label
        username_label_right = Label(
            new_s,
            text=self.username,
            font="consolas 15",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )

        password_label_right = Label(
            new_s,
            text=self.password,
            font="consolas 15",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
        )

        email_id_label_right = Label(
            new_s,
            text=self.email_id,
            font="consolas 15",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )

        email_password_label_right = Label(
            new_s,
            text=self.email_password,
            font="consolas 15",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )

        # dot label
        dot = Label(new_s, font=(200), bg="#292A2D", text=":", fg="white")
        dot1 = Label(new_s, font=(200), bg="#292A2D", text=":", fg="white")
        dot2 = Label(new_s, font=(200), bg="#292A2D", text=":", fg="white")
        dot3 = Label(new_s, font=(200), bg="#292A2D", text=":", fg="white")

        # profile image

        profile_photo = Label(
            new_s,
            bg="#292A2D",
            image=member,
            activebackground="black",
            activeforeground="white",
        )
        profile_photo.photo = member
        delete_object = Deletion(self.username, self.hashed_password, profile)
        delete_this_account = Button(
            new_s,
            text="Delete Account",
            fg="white",
            bg="black",
            activebackground="black",
            activeforeground="white",
            font="Helvetiva 10",
            command=lambda: delete_object.delete_main_account(s),
        )

        username_label.place(x=5, y=100 + 100)
        password_label.place(x=5, y=150 + 100)
        email_id_label.place(x=5, y=200 + 100)
        email_password_label.place(x=5, y=250 + 100)
        profile_photo.place(x=200, y=50)
        delete_this_account.place(x=0 + 2, y=400 + 50 + 20)

        username_label_right.place(x=300 - 70, y=100 + 100)
        password_label_right.place(x=300 - 70, y=150 + 100)
        email_id_label_right.place(x=300 - 70, y=200 + 100)
        email_password_label_right.place(x=300 - 70, y=250 + 100)

        # putting the dot on the frame
        dot.place(x=200, y=100 + 100 + 6)
        dot1.place(x=200, y=150 + 100 + 6)
        dot2.place(x=200, y=200 + 100 + 6)
        dot3.place(x=200, y=250 + 100 + 6)


# for handling registrations
class Register:
    def __init__(self, username, password, email_id, email_password):
        self.username = str(username)
        self.password = str(password)
        self.email_id = str(email_id)
        self.email_password = str(email_password)

    def check_pass_length(self):  # checking if the entered password is lesser than 5
        return len(self.password) >= 5 and len(self.email_password) >= 5

    """to create a file named user and to store his accounts and also add his details to the database"""

    def saving(self, object):
        object.execute("select username from data_input")
        values_username = object.fetchall()
        for i in values_username:
            for usernames in i:
                if usernames == self.username and os.path.exists(
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
        message = self.email_password
        passwordSalt = secrets.token_bytes(512)
        key = pbkdf2.PBKDF2(password_recovery_email, passwordSalt).read(32)
        aes = pyaes.AESModeOfOperationCTR(key)
        encrypted_pass = aes.encrypt(message)
        try:
            object.execute(
                "insert into data_input values (?,?,?,?,?,?,?)",
                (
                    self.username,
                    self.email_id,
                    cipher_text,
                    salt_for_decryption,
                    encrypted_pass,
                    0,
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
            file_name + ".fenc", f"{self.username}decrypted.bin", hash_pass, bufferSize
        )
        window_after(self.username, hash_pass, self.password)


class Deletion:
    def __init__(self, real_username, hashed_password, window):
        self.real_username = real_username
        self.hashed_password = hashed_password
        self.window = window

    def delete_social_media_account(self, password_button, Value, *account_name):

        n = StringVar()
        if Value:
            delete_med_account = Tk()
            delete_med_account.config(bg="#292A2D")
            delete_med_account.title("Delete Account")
            selectaccount = Combobox(
                delete_med_account, width=27, textvariable=n, state="#292A2D"
            )
            # Adding combobox drop down list
            tu = ()
            with open(f"{self.real_username}decrypted.bin", "rb") as selectfile:
                try:
                    ac = pickle.load(selectfile)
                    for i in ac:
                        tu += (i[2],)
                except:
                    pass
            delete = Button(
                delete_med_account,
                text="Delete",
                fg="white",
                bg="#292A2D",
                command=lambda: self.change_account_name(
                    str(selectaccount.get()), password_button, True
                ),
            )
            selectaccount["values"] = tu
            change_account_label = Label(
                delete_med_account,
                fg="white",
                bg="#292A2D",
                text="Select account to be deleted",
            )
            selectaccount.grid(column=1, row=0)
            change_account_label.grid(column=0, row=0)
            selectaccount.current()
            delete.grid(row=1, column=1)

        else:
            a = Tk()
            a.overrideredirect(1)
            a.withdraw()
            result = messagebox.askyesno(
                "Delete Account", "Are you sure you want to delete you account?"
            )
            a.destroy()
            if result:

                self.change_account_name(account_name[0], password_button, False)
            else:
                pass

    def change_account_name(self, account_name, button, val):
        if val:
            result = messagebox.askyesno(
                "Confirm", "Are you sure that you want to delete your account"
            )
        else:
            result = True
        if result == True:
            with open(f"{self.real_username}decrypted.bin", "rb") as f:
                values = pickle.load(f)
                for i in values:
                    if i[2] == account_name:
                        inde = values.index(i)
                        values.pop(inde)

                f.close()
            try:
                os.remove(f"{self.real_username}.bin.fenc")
            except:
                pass
            with open(f"{self.real_username}decrypted.bin", "wb") as f:
                pickle.dump(values, f)
                f.close()

            pyAesCrypt.encryptFile(
                f"{self.real_username}decrypted.bin",
                f"{self.real_username}.bin.fenc",
                self.hashed_password,
                bufferSize,
            )
            a = Tk()
            a.withdraw()
            messagebox.showinfo("Success", f"{account_name}  has been  deleted")
            a.destroy()

            # getting whether the password button is pressed or not
            state_current = button["state"]
            if state_current == DISABLED:
                gameloop(self.real_username, self.hashed_password, self.window, button)
            else:
                pass
        else:
            a = Tk()
            a.withdraw()
            messagebox.showinfo("Error", "Please try again")
            a.destroy()

    def delete_main_account(self, window, *another_window):
        answer = messagebox.askyesno(
            "Delete Account", "Are you sure you want to delete you account"
        )
        if answer:
            result = simpledialog.askstring(
                "Delete Account",
                f"Please type {self.real_username}-CONFIRM to delete your account",
            )
            if result == f"{self.real_username}-CONFIRM":
                try:
                    os.remove(self.real_username + "decrypted.bin")
                    os.remove(self.real_username + ".bin.fenc")

                    my_cursor.execute(
                        "delete from data_input where username = (?)",
                        (self.real_username,),
                    )
                    messagebox.showinfo(
                        "Account deletion",
                        "Success your account has been deleted. See you!!",
                    )
                    window.destroy()
                    for i in another_window:
                        i.destroy()
                    if not os.path.exists(f"{self.real_username}.bin.fenc"):
                        quit()
                except:
                    pass
            else:
                messagebox.showwarning("Error", "Please try again")
        else:
            pass


class Change_details:
    def __init__(self, real_username, hashed_password, window):
        self.real_username = real_username
        self.hashed_password = hashed_password
        self.window = window

    def change_window_creation(self, selectaccount, pass_button):
        self.but = pass_button
        password_button = pass_button
        change_acccount = Toplevel()
        change_acccount.config(bg="#292A2D")
        change_acccount.resizable(False, False)

        change_acccount.title("Change Account")

        width_window = 450
        height_window = 400
        screen_width = change_acccount.winfo_screenwidth()
        screen_height = change_acccount.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        change_acccount.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))

        iamge_load = tk_image.PhotoImage(image.open("images\\member.png"))
        iamge = Label(change_acccount, image=iamge_load, bg="#292A2D")
        iamge.photo = iamge_load
        new_username_label = Label(
            change_acccount,
            text="New Username:",
            fg="white",
            bg="#292A2D",
            font=("Sitka Text", 15),
        )
        new_password_label = Label(
            change_acccount,
            text="New Password:",
            fg="white",
            bg="#292A2D",
            font=("Sitka Text", 15),
        )
        new_account_name_label = Label(
            change_acccount,
            text="New Account Name:",
            fg="white",
            bg="#292A2D",
            font=("Sitka Text", 15),
        )

        new_username = Entry(
            change_acccount,
            width=13,
            bg="#292A2D",
            foreground="white",
            border=0,
            bd=0,
            font=("consolas", 15, "normal"),
            insertbackground="white",
        )
        new_password = Entry(
            change_acccount,
            width=13,
            bg="#292A2D",
            foreground="white",
            border=0,
            bd=0,
            font=("consolas", 15, "normal"),
            insertbackground="white",
        )
        new_account_name = Entry(
            change_acccount,
            width=13,
            bg="#292A2D",
            border=0,
            bd=0,
            font=("consolas", 15, "normal"),
            foreground="white",
            insertbackground="white",
        )

        change = Button(
            change_acccount,
            width=20,
            height=2,
            text="C H A N G E",
            font=("consolas"),
            fg="white",
            bg="#994422",
            bd=0,
            command=lambda: self.change_sub_account(
                selectaccount,
                str(new_username.get()),
                str(new_password.get()),
                str(new_account_name.get()),
            ),
        )
        change.grid(row=5, column=1)
        change.place(x=120, y=200 + 120)

        new_account_name_label.place(x=0, y=70 + 100 + 3)
        new_username_label.place(x=0, y=100 + 100 + 15 + 3)
        new_password_label.place(x=0, y=130 + 100 + 30 + 3)

        new_account_name.place(x=250, y=70 + 100 + 5)
        new_username.place(x=250, y=100 + 100 + 15 + 5)
        new_password.place(x=250, y=130 + 100 + 30 + 5)

        Frame(change_acccount, width=150, height=2, bg="white").place(
            x=250, y=70 + 100 + 10 + 16 + 5
        )
        Frame(change_acccount, width=150, height=2, bg="white").place(
            x=250, y=130 + 100 + 10 + 16 + 30 + 5
        )
        Frame(change_acccount, width=150, height=2, bg="white").place(
            x=250, y=100 + 100 + 10 + 16 + 15 + 5
        )

        iamge.place(x=145, y=10)

    def change_sub_account(
        self, accounttobechanged, new_username, new_password, account_name
    ):
        with open(f"{self.real_username}decrypted.bin", "rb") as f:
            value1 = pickle.load(f)
            f.close()
        for i in value1:

            if i[0] == str(accounttobechanged):
                i[0] = str(new_username)
                i[1] = str(new_password)
                i[2] = str(account_name)
                p = Tk()
                p.config(bg="#292A2D")
                p.withdraw()
                messagebox.showinfo("Success", "The Account details has been changed")
                p.destroy()
                os.remove(f"{self.real_username}decrypted.bin")
                with open(f"{self.real_username}decrypted.bin", "wb") as f:
                    pickle.dump(value1, f)
                    f.close()
                os.remove(f"{self.real_username}.bin.fenc")
                pyAesCrypt.encryptFile(
                    f"{self.real_username}decrypted.bin",
                    f"{self.real_username}.bin.fenc",
                    self.hashed_password,
                    bufferSize,
                )

                gameloop(
                    self.real_username, self.hashed_password, self.window, self.but
                )

    def save_email(
        self,
        new_email,
        old_email,
        recovery_password,
        another_recovery_password,
        user_password,
    ):

        email_split = ""
        word = new_email.split()
        for i in word:
            for a in i:
                if i == "@":
                    break
                else:
                    email_split += i
        val = email_split[::-1]
        main_password = val + "/" + another_recovery_password

        re_hash_text1 = user_password + self.real_username
        new_salt1 = user_password + "@" + main_password
        re_hash_new1 = hashlib.sha3_512(re_hash_text1.encode()).hexdigest()
        re_encrypt, new_salt = create_key(main_password, new_salt1)

        # encrypting the new recovery password

        password = new_email + re_hash_new1
        message = another_recovery_password
        passwordSalt = secrets.token_bytes(512)  # returns a random 64 byte
        key = pbkdf2.PBKDF2(password, passwordSalt).read(
            32
        )  # it creates a key based on the password provided by the user
        aes = pyaes.AESModeOfOperationCTR(key)
        # aes is mode of encryption for encrypting the password
        encrypted_pass = aes.encrypt(message)

        os.remove(f"{self.real_username}.bin.fenc")
        my_cursor.execute(
            "update data_input set password = (?),  email_id = (?),  salt_recovery=(?), salt = (?), recovery_password = (?) where  username = (?)",
            (
                re_encrypt,
                new_email,
                passwordSalt,
                new_salt,
                encrypted_pass,
                self.real_username,
            ),
        )
        pyAesCrypt.encryptFile(
            self.real_username + "decrypted.bin",
            self.real_username + ".bin.fenc",
            re_hash_new1,
            bufferSize,
        )
        ad = Toplevel()
        ad.withdraw()
        messagebox.showinfo(
            "Success",
            "Your email and password has been changed.Please restart the program ",
        )
        ad.destroy()

    def change_email(self, rec_pass, ogi_pass):
        self.password = ogi_pass
        self.recovery = rec_pass
        new_window = Toplevel()

        new_img = tk_image.PhotoImage(image.open("images\\user.png"))
        new_img_label = Label(new_window, image=new_img, bg="#292A2D")
        new_img_label.photo = new_img

        file_name_reentry = self.real_username + ".bin.fenc"

        width_window = 400
        height_window = 200
        screen_width = new_window.winfo_screenwidth()
        screen_height = new_window.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        new_window.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        new_window.title("Change Recovery details")
        new_window.geometry("300x300")
        new_window.config(bg="#292A2D")

        new_email = Label(new_window, text="New Email", fg="white", bg="#292A2D")
        new_email_password = Label(
            new_window, text="New Password", fg="white", bg="#292A2D"
        )

        new_email_entry = Entry(new_window)
        new_email_password_entry = Entry(new_window, show="*")

        new_img_label.grid(row=0, column=1)
        new_email.grid(row=1, column=0)
        new_email_password.grid(row=2, column=0)
        new_email_entry.grid(row=1, column=1)
        new_email_password_entry.grid(row=2, column=1)

        new_img_label.place(x=110, y=50)
        new_email.place(x=10, y=70 + 50)
        new_email_password.place(x=10, y=100 + 50)
        new_email_entry.place(x=150 - 40, y=70 + 50)
        new_email_password_entry.place(x=150 - 40, y=100 + 50)

        new_email_password_entry.config(show="")

        new_email_password_entry.config(fg="grey")
        new_email_password_entry.insert(0, "New Email password")

        new_email_entry.config(fg="grey")
        new_email_entry.insert(0, "New Email")
        my_cursor.execute(
            "select email_id from data_input where username=(?)", (self.real_username,)
        )
        for i in my_cursor.fetchall():
            save = Button(
                new_window,
                text="Save",
                command=lambda: self.save_email(
                    str(new_email_entry.get()),
                    i[0],
                    self.recovery,
                    str(new_email_password_entry.get()),
                    self.password,
                ),
            )
            save.place(x=150 - 40, y=200)

        new_email_entry.bind(
            "<FocusIn>",
            lambda event, val_val=new_email_entry, index=1: handle_focus_in(
                val_val, index
            ),
        )
        new_email_entry.bind(
            "<FocusOut>",
            lambda event, val_val=new_email_entry, val="Email", index=1: handle_focus_out(
                val_val, val, index
            ),
        )

        new_email_password_entry.bind(
            "<FocusIn>",
            lambda event, val_val=new_email_password_entry, index=2: handle_focus_in(
                val_val, index
            ),
        )
        new_email_password_entry.bind(
            "<FocusOut>",
            lambda event, val_val=new_email_password_entry, val="New Email password", index=2: handle_focus_out(
                val_val, val, index
            ),
        )

        private_img = tk_image.PhotoImage(image.open("images\\private.png"))
        unhide_img = tk_image.PhotoImage(image.open("images\\eye.png"))

        show_both_12 = Button(
            new_window,
            image=unhide_img,
            command=lambda: password_sec(new_email_password_entry, show_both_12),
            fg="white",
            bd="0",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
            activeforeground="white",
            relief=RAISED,
        )
        show_both_12.image = unhide_img
        show_both_12.place(x=250 - 15, y=100 + 50 - 5)


def create_key(password, message):
    password_key = password.encode()  # convert string to bytes
    salt = os.urandom(64)  # create a random 64 bit byte
    # PBKDF2 HMAC- it is a type of encryption-Password-Based Key Derivation Function 2,HMAC-hashed message
    # authentication code
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=salt,
        iterations=999999,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_key))
    message_encrypt = message.encode()
    f = Fernet(key)
    encrypted = f.encrypt(message_encrypt)
    return encrypted, salt


def log_out(*window):
    try:
        for i in window:
            i.destroy()

        a = Tk()
        a.withdraw()
        messagebox.showinfo("Logged Out", "You have been successfully logged out")
        a.destroy()
        list_file = glob.glob("*decrypted.bin")
        for i in list_file:
            converting_str = str(i)
            try:
                os.remove(converting_str)
            except:
                pass
        login()

    except:
        pass


def retreive_key(password, byte, de):
    password_key = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=de,
        iterations=999999,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_key))
    f = Fernet(key)

    decrypted = f.decrypt(byte)
    return decrypted.decode("utf-8")


def checkforupdates():
    # isUpToDate check whether the file ie main.py  is same as the one present in my github repository and it returns true if same else false
    if isUpToDate(
        "main.py",
        "https://raw.githubusercontent.com/Rohithk2003/One-Pass/develop/main.py",
    ):
        result = messagebox.askyesno(
            "Update Available", "Do you want to update the app?"
        )
        if result == True:
            try:
                messagebox.showinfo(
                    "Updating", "Please wait while the software is being updated"
                )
                # used for updating the file
                update(
                    "main.py",
                    "https://raw.githubusercontent.com/Rohithk2003/One-Pass/develop/main.py",
                )
                messagebox.showinfo(
                    "Updated", "The file has been updated please restart to take effect"
                )
            except:
                messagebox.showerror(
                    "No internet Available", "Internet is not available"
                )

        else:
            quit()
    else:
        messagebox.showinfo("Update", "No update is currently available")


def settings(
    real_username,
    main_window,
    hashed_password,
    window,
    password_button,
    rec_pas,
    original_password,
):
    settings_window = Tk()
    settings_window.resizable(False, False)
    width_window = 187
    height_window = 175
    screen_width = settings_window.winfo_screenwidth()
    screen_height = settings_window.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2

    settings_window.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))

    settings_window.title("Settings")
    settings_window.config(bg="#292A2D")

    delete_object = Deletion(real_username, hashed_password, window)
    change_object = Change_details(real_username, hashed_password, window)

    log_label = Button(
        settings_window,
        text="Log out",
        width=20,
        font=("consolas"),
        fg="white",
        activebackground="white",
        activeforeground="white",
        bg="#994422",
        bd=0,
        command=lambda: log_out(settings_window, window, main_window),
    )

    check_for_updates = Button(
        settings_window,
        command=checkforupdates,
        text="Check for updates",
        width=20,
        activebackground="#994422",
        font=("consolas"),
        activeforeground="white",
        fg="white",
        bg="#994422",
        bd=0,
    )
    Delete_account_button = Button(
        settings_window,
        text="Delete main account",
        command=lambda: delete_object.delete_main_account(main_window, settings_window),
        font=("consolas"),
        width=20,
        fg="black",
        activeforeground="black",
        activebackground="white",
        bg="white",
        bd=0,
    )
    Delete_social_button = Button(
        settings_window,
        text="Delete sub  account",
        command=lambda: delete_object.delete_social_media_account(
            password_button, True
        ),
        font=("consolas"),
        fg="black",
        width=20,
        activeforeground="black",
        activebackground="white",
        bg="white",
        bd=0,
    )
    change_account_button = Button(
        settings_window,
        text="Change Details",
        command=lambda: login_password("Change Details"),
        font=("consolas"),
        fg="white",
        activebackground="#994422",
        activeforeground="white",
        width=20,
        bg="#994422",
        bd=0,
    )
    change_email_button = Button(
        settings_window,
        text="Change recovery email",
        command=lambda: change_object.change_email(rec_pas, original_password),
        font=("consolas"),
        fg="black",
        activebackground="white",
        activeforeground="black",
        width=20,
        bg="white",
        bd=0,
    )

    Delete_account_button.grid(row=1, column=1, columnspan=2)
    check_for_updates.grid(row=2, column=1, columnspan=2)
    Delete_social_button.grid(row=3, column=1, columnspan=2)
    change_account_button.grid(row=4, column=1, columnspan=2)
    change_email_button.grid(row=5, column=1, columnspan=2)
    log_label.grid(row=6, column=1, columnspan=2)

    if os.stat(f"{real_username}decrypted.bin").st_size == 0:
        Delete_social_button.config(state=DISABLED)
    else:
        Delete_social_button.config(state=NORMAL)
    settings_window.mainloop()


# forgot password function


def login_password(title1):
    window = Toplevel()
    window.config(bg="#292A2D")
    window.resizable(False, False)

    window.title(title1)
    text = (
        "Please provide the recovery email  and recovery email password \n that you provided while creating an "
        "account "
    )
    text_label = Label(window, text=text, fg="white", bg="#292A2D")
    width_window = 400
    height_window = 300
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2
    window.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))

    username_forgot = Label(window, text="Username", fg="white", bg="#292A2D")
    recover_email = Label(window, text="Email", fg="white", bg="#292A2D")
    recover_password = Label(window, text="Password", fg="white", bg="#292A2D")
    recover_email_entry = Entry(window)
    recover_password_entry = Entry(window)
    username_forgot_entry = Entry(window)

    username_forgot.place(x=50, y=70)
    recover_password.place(x=50, y=100)
    recover_email.place(x=50, y=130)
    username_forgot_entry.place(x=200, y=70)
    recover_password_entry.place(x=200, y=100)
    recover_email_entry.place(x=200, y=130)
    text_label.place(x=20, y=0)
    key = ""
    l = "abcdefghijklmnopqrstuvwxyz"
    for i in range(7):
        key += random.choice(l)

    def generate_key1(file, button):
        pyAesCrypt.encryptFile(file, "otp.bin.fenc", key, bufferSize)
        os.unlink(file)
        button.config(state=DISABLED)

        messagebox.showinfo(
            "OTP", f"An OTP has been sent to  {str(recover_email_entry.get())}"
        )
        window.focus_set()

    def change_password(email, password1, username12):
        root = Toplevel()
        new_img = tk_image.PhotoImage(image.open("images\\user.png"))
        new_img_label = Label(root, image=new_img, bg="#292A2D")
        new_img_label.photo = new_img
        root.resizable(False, False)

        file_name_reentry = username12 + ".bin.fenc"

        width_window = 400
        height_window = 400
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        root.title("Change Details")
        root.geometry("300x300")
        root.config(bg="#292A2D")

        new_username = Label(root, text="New Username", fg="white", bg="#292A2D")
        new_password = Label(root, text="New Password", fg="white", bg="#292A2D")

        new_username_entry = Entry(root)
        new_password_entry = Entry(root, show="*")

        new_img_label.grid(row=0, column=1)
        new_username.grid(row=1, column=0)
        new_password.grid(row=2, column=0)
        new_username_entry.grid(row=1, column=1)
        new_password_entry.grid(row=2, column=1)

        new_username_entry.bind(
            "<FocusIn>",
            lambda event, val_val=new_username_entry, index=1: handle_focus_in(
                val_val, index
            ),
        )
        new_username_entry.bind(
            "<FocusOut>",
            lambda event, val_val=new_username_entry, val="Username", index=1: handle_focus_out(
                val_val, val, index
            ),
        )

        new_password_entry.bind(
            "<FocusIn>",
            lambda event, val_val=new_password_entry, index=2: handle_focus_in(
                val_val, index
            ),
        )
        new_password_entry.bind(
            "<FocusOut>",
            lambda event, val_val=new_password_entry, val="Password", index=2: handle_focus_out(
                val_val, val, index
            ),
        )

        unhide_img = tk_image.PhotoImage(image.open("images\\eye.png"))

        show_both_12 = Button(
            root,
            image=unhide_img,
            bd=0,
            command=lambda: password_sec(new_password_entry, show_both_12),
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
            activeforeground="white",
            relief=RAISED,
        )
        show_both_12.grid(row=0, column=5)
        show_both_12.place(x=250 - 15, y=100 + 50 - 5)

        def change():
            my_cursor.execute(
                "select password,salt from data_input where email_id = (?)", (email,)
            )
            values_password = my_cursor.fetchall()
            password_decrypt = ""
            word = email.split()

            for i in word:
                for a in i:
                    if i == "@":
                        break
                    else:
                        password_decrypt += i
            new_val = password_decrypt[::-1]
            main_pass = new_val + "/" + password1
            has = None
            salt = None
            decrypted_string = ""
            for i in values_password:
                has = i[0]
                salt = i[1]
            string = retreive_key(main_pass, has, salt)
            for i in string:
                if i == "@":
                    break
                else:
                    decrypted_string += i
            value = decrypted_string + username12

            re_hash = hashlib.sha3_512(value.encode()).hexdigest()
            try:
                pyAesCrypt.decryptFile(
                    file_name_reentry,
                    username12 + "decrypted.bin",
                    re_hash,
                    bufferSize,
                )
            except:
                pass
            if os.path.exists(f"{username12}decrypted.bin"):
                os.remove(username12 + ".bin.fenc")
                re_hash_text = str(new_password_entry.get()) + str(
                    new_username_entry.get()
                )
                new_salt = str(new_password_entry.get()) + "@" + main_pass
                re_hash_new = hashlib.sha3_512(re_hash_text.encode()).hexdigest()
                re_encrypt, new_salt = create_key(main_pass, new_salt)
                pyAesCrypt.encryptFile(
                    username12 + "decrypted.bin",
                    str(new_username_entry.get()) + ".bin.fenc",
                    re_hash_new,
                    bufferSize,
                )
                my_cursor.execute(
                    "select email_id from data_input where username=(?)", (username12,)
                )
                for i in my_cursor.fetchall():
                    password_recovery_email = i[0] + re_hash_new
                    passwordSalt = secrets.token_bytes(512)
                    key = pbkdf2.PBKDF2(password_recovery_email, passwordSalt).read(32)
                    aes = pyaes.AESModeOfOperationCTR(key)
                    encrypted_pass = aes.encrypt(password1)

                    my_cursor.execute(
                        "update data_input set username = (?),password=(?),recovery_password = (?),salt_recovery=(?) "
                        "where email_id = (?)",
                        (
                            str(new_username_entry.get()),
                            re_encrypt,
                            encrypted_pass,
                            passwordSalt,
                            email,
                        ),
                    )
                messagebox.showinfo(
                    "Success", "Your username and password has been changed"
                )

            else:
                messagebox.showinfo("Error", "Wrong recovery password")

        change_button = Button(root, text="Change", command=change)
        change_button.grid(row=3, column=0)

    def Verification(password, otp_entry, email, email_password, username12, button):
        ot = str(otp_entry)
        if ot != "":
            pyAesCrypt.decryptFile(
                "otp.bin.fenc", "otp_decyrpted.bin", password, bufferSize
            )
            with open("otp_decyrpted.bin", "rb") as f11:
                list = pickle.load(f11)
                str_value = ""
                for i in list:
                    str_value += str(i)
                str_value_hash = hashlib.sha512(ot.encode()).hexdigest()
                if str_value_hash == str_value:
                    roo1 = Tk()
                    roo1.withdraw()
                    messagebox.showinfo("Success", "OTP is verified")
                    roo1.destroy()
                    f11.close()
                    os.remove("otp_decyrpted.bin")
                    os.remove("otp.bin.fenc")
                    change_password(email, email_password, username12)
                else:
                    messagebox.showinfo("Error", "Incorrect OTP Please verify it again")
                    button.config(state=NORMAL)
                    otp_entry.delete(0, END)
        else:
            messagebox.showinfo("Error", "Please provide the OTP  send to your email")

    def forgot_password(OTP, email, username):
        try:
            global running
            running = True
            SUBJECT = "EMAIL verification for ONE-PASS-MANAGER"
            otp = f"Hey {username}! Your OTP for your ONE-PASS manager is {OTP}.Please use this to verify your email"
            msg = "Subject: {}\n\n{}".format(SUBJECT, otp)
            s = smtplib.SMTP("smtp.gmail.com", 587)
            s.starttls()
            s.login("", "")
            s.sendmail("", email, msg)
        except:
            a = Tk()
            a.withdraw()
            messagebox.showwarning("No internet", "No internet is available")

    def main(key, otp_window, button):
        run = False
        global running
        username_verify = str(username_forgot_entry.get())
        recover_email_entry_verify = str(recover_email_entry.get())
        recover_password_entry_verify = str(recover_password_entry.get())
        if (
            username_verify == "Username"
            and recover_email_entry_verify == "Email ID"
            and recover_password_entry_verify == "Password"
        ):
            roo21 = Tk()
            roo21.withdraw()
            messagebox.showinfo(
                "Error",
                "Please provide the details",
            )
            roo21.destroy()

        elif username_verify == "Username":

            messagebox.showwarning("Warning", f"Username cannot be blank")

        elif recover_password_entry_verify == "Password":
            messagebox.showwarning("Warning", f"Password cannot be blank")
        elif not os.path.exists(username_verify + ".bin.fenc"):

            messagebox.showwarning("Warning", f"Cannot find user {username_verify}")

        else:
            if os.path.exists(username_verify + ".bin.fenc"):
                verify_password = ""
                for i in recover_email_entry_verify:
                    if i == "@":
                        break
                    else:
                        verify_password += i
                verify_password += recover_password_entry_verify
                my_cursor.execute(
                    "select email_id from data_input where username = (?)",
                    (username_verify,),
                )
                values_fetch = my_cursor.fetchall()

                if values_fetch != []:
                    for i in values_fetch:

                        if i[0] == recover_email_entry_verify:
                            run = True
                        else:
                            run = False

                            messagebox.showerror("Error", "Wrong Recovey email")
                else:
                    messagebox.showerror("Error", "No such account exists")

                if run:

                    otp_entry = Entry(otp_window)
                    otp_entry.grid(row=6, column=1)
                    otp_entry_button = Button(
                        otp_window,
                        text="verify otp",
                        command=lambda: Verification(
                            key,
                            otp_entry.get(),
                            recover_email_entry_verify,
                            recover_password_entry_verify,
                            username_verify,
                            button,
                        ),
                        fg="white",
                        bg="#292A2D",
                    )
                    otp_entry_button.grid(row=8, column=1)
                    otp_entry_button.place(x=50, y=200)
                    otp_entry.place(x=200, y=200)
                    digits = "1234567890"
                    OTP = ""
                    for i in range(6):
                        OTP += random.choice(digits)
                    OTP_secure = hashlib.sha512(OTP.encode()).hexdigest()
                    l = list(OTP_secure)
                    with open("otp.bin", "wb") as f:
                        pickle.dump(l, f)
                        f.close()
                    generate_key1("otp.bin", button)
                    forgot_password(OTP, recover_email_entry_verify, username_verify)
            else:
                messagebox.showerror("Error", "No such account exists")

    forgot_password_button = Button(
        window,
        text="verify",
        command=lambda: main(key, window, forgot_password_button),
        bg="#292A2D",
        fg="white",
    )
    forgot_password_button.grid(row=5, column=1)
    forgot_password_button.place(x=250, y=170)

    unhide_img = tk_image.PhotoImage(image.open("images\\eye.png"))

    show_both_1 = Button(
        window,
        image=unhide_img,
        bd=0,
        command=lambda: password_sec(recover_password_entry, show_both_1),
        fg="white",
        bg="#292A2D",
        highlightcolor="#292A2D",
        activebackground="#292A2D",
        activeforeground="white",
        relief=RAISED,
    )
    show_both_1.photo = unhide_img
    show_both_1.grid(row=0, column=0)
    show_both_1.place(x=325, y=95)
    username_forgot_entry.insert(0, "Username")
    username_forgot_entry.config(fg="grey")
    recover_password_entry.insert(0, "Password")
    recover_password_entry.config(fg="grey")
    recover_password_entry.config(show="")

    recover_email_entry.config(fg="grey")
    recover_email_entry.insert(0, "Email ID")

    username_forgot_entry.bind(
        "<FocusIn>",
        lambda event, val_val=username_forgot_entry, index=1: handle_focus_in(
            val_val, index
        ),
    )
    username_forgot_entry.bind(
        "<FocusOut>",
        lambda event, val_val=username_forgot_entry, val="Username", index=1: handle_focus_out(
            val_val, val, index
        ),
    )

    recover_password_entry.bind(
        "<FocusIn>",
        lambda event, val_val=recover_password_entry, index=2: handle_focus_in(
            val_val, index
        ),
    )
    recover_password_entry.bind(
        "<FocusOut>",
        lambda event, val_val=recover_password_entry, val="Password", index=2: handle_focus_out(
            val_val, val, index
        ),
    )

    recover_email_entry.bind(
        "<FocusIn>",
        lambda event, val_val=recover_email_entry, index=3: handle_focus_in(
            val_val, index
        ),
    )
    recover_email_entry.bind(
        "<FocusOut>",
        lambda event, val_val=recover_email_entry, val="Email ID", index=3: handle_focus_out(
            val_val, val, index
        ),
    )


var = 0


def window_after(username, hash_password, password_new, *window):
    try:
        for i in window:
            i.destroy()
    except:
        pass
    # sidebar
    root = Tk()
    root.resizable(False, False)

    root.focus_set()
    global var
    global file
    status_name = False
    sidebar = Frame(
        root, width=30, bg="#292A2D", height=500, relief="sunken", borderwidth=1
    )
    sidebar.pack(expand=False, fill="both", side="left")
    file = None
    root.title("ONE-PASS")
    width_window = 1300
    height_window = 700
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2

    root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))

    def testing(root, mainarea, username, hash_password, password_button):
        button["state"] = DISABLED
        notes_buttons["state"] = NORMAL
        profile_button["state"] = NORMAL
        root.title("Passwords")
        emptyMenu = Menu(root)
        root.geometry("1300x700")
        mainarea.config(bg="#292A2D")
        root.config(menu=emptyMenu)
        root.iconbitmap("images\\password.ico")
        list = mainarea.pack_slaves()
        for l in list:
            l.destroy()
        list = mainarea.grid_slaves()
        for l in list:
            l.destroy()
        gameloop(username, hash_password, mainarea, password_button)

    def note_pad_sec():
        global status_name
        global var
        notes_buttons["state"] = DISABLED
        button["state"] = NORMAL
        profile_button["state"] = NORMAL

        list = mainarea.grid_slaves()
        for l in list:
            l.destroy()

        if __name__ == "__main__":
            emptyMenu = Menu(root)
            root.config(menu=emptyMenu)
            try:
                list = mainarea.grid_slaves()
                for l in list:
                    l.destroy()
            except:
                pass

            def newFile():
                root.title("Untitled - Notepad")
                TextArea.delete(1.0, END)

            def openFile():
                global file
                file = fd.askopenfilename(
                    defaultextension=".txt",
                    filetypes=[("All Files", "*.*"), ("Text Documents", "*.txt")],
                )

                # check to if there is a file_name
                global status_name
                status_name = file
                if file == "":
                    file = None
                else:
                    root.title(os.path.basename(file) + " - Notepad")
                    TextArea.delete(1.0, END)
                    with open(file, "r") as f:
                        TextArea.insert(1.0, f.read())
                        f.close()

            def rename_file():
                global file
                if root.title() != "Untitled-Notepad":
                    application_window = Tk()
                    application_window.withdraw()
                    a = simpledialog.askstring(
                        "Input", "What is new file name?", parent=application_window
                    )
                    application_window.destroy()
                    if file != None or file != 0:
                        new_file, file_extension = os.path.splitext(file)
                        f = open(file, "r")
                        dir = os.path.dirname(file)
                        values = f.read()
                        f.close()
                        os.remove(file)
                        file = (dir) + "/" + a + file_extension
                        with open(file, "w") as f:
                            f.write(values)
                            f.close()
                        TextArea.delete(1.0, END)
                        with open(file, "r") as f:
                            TextArea.insert(1.0, f.read())
                            f.close()
                        root.title(a + file_extension + " - Notepad")
                    else:
                        messagebox.showinfo(
                            "Rename", "Please save your file before renaming it"
                        )
                        save_as_File()
                else:
                    messagebox.showinfo(
                        "Rename", "Please save your file before renaming it"
                    )
                    save_as_File()

            def save_as_File():
                global file
                if file == None:

                    file = fd.asksaveasfilename(
                        initialfile="Untitled.txt",
                        defaultextension=".txt",
                        filetypes=[
                            ("All Files", "*.*"),
                            ("Text Documents", "*.txt"),
                        ],
                    )
                    if file == "":
                        file = None

                    else:
                        # Save as a new file
                        with open(file, "w") as f:
                            f.write(TextArea.get(1.0, END))
                            f.close()
                        root.title(os.path.basename(file) + " - Notepad")
                        file = file

            def save_file():
                global status_name
                global file
                if status_name:
                    with open(file, "w") as f:
                        f.write(TextArea.get(1.0, END))
                        f.close()
                else:
                    file = fd.asksaveasfilename(
                        initialfile="Untitled.txt",
                        defaultextension=".txt",
                        filetypes=[
                            ("All Files", "*.*"),
                            ("Text Documents", "*.txt"),
                        ],
                    )
                    status_name = file
                    if file == "":
                        file = None

                    else:
                        # Save as a new file
                        with open(file, "w") as f:
                            status_name = True
                            f.write(TextArea.get(1.0, END))
                            f.close()
                        root.title(os.path.basename(file) + " - Notepad")

            def quitApp():
                try:
                    root.destroy()
                except:
                    pass

            def cut(*event):
                global cutting_value
                try:
                    if TextArea.selection_get():
                        # grabbing selected text from text area
                        cutting_value = TextArea.selection_get()
                        TextArea.delete("sel.first", "sel.last")
                except:
                    cutting_value = ""

            def copy(*event):
                global cutting_value
                try:
                    if TextArea.selection_get():
                        # grabbing selected text from text area
                        cutting_value = TextArea.selection_get()
                except:
                    cutting_value = ""

            def paste(*event):
                if cutting_value:
                    postion = TextArea.index(INSERT)
                    TextArea.insert(postion, cutting_value)

            def about():
                messagebox.showinfo("Notepad", "Notepad by Rohithk-25-11-2020")

            # Basic tkinter setup
            root.geometry("1300x700")
            root.iconbitmap(False, "images\\notes.ico")
            root.title("Untitled - Notepad")
            # Add TextArea
            root.resizable(0, 0)
            font_main = ("freesansbold", 12)
            Scroll_y = Scrollbar(mainarea, orient="vertical")
            Scroll_y.pack(side="right", fill=Y)
            TextArea = Text(
                mainarea,
                font=font_main,
                fg="#292A2D",
                insertofftime=600,
                insertontime=600,
                insertbackground="#292A2D",
                undo=True,
                yscrollcommand=Scroll_y.set,
            )

            Scroll_y.config(command=TextArea.yview)
            TextArea.pack(expand=True, fill=BOTH)

            # create a menubar
            MenuBar = Menu(root)
            MenuBar.config(bg="#292A2D", bd=0, activebackground="#292A2D")
            status_name = False
            root.config(bg="red", menu=MenuBar)
            # File Menu Starts

            FileMenu = Menu(MenuBar, tearoff=0)
            FileMenu.config(
                background="black",
                borderwidth="0",
                relief=SUNKEN,
                activebackground="#292A2D",
            )
            FileMenu.config(activebackground="#292A2D")
            # To open new file
            FileMenu.add_command(
                label="New",
                command=newFile,
                background="#292A2D",
                foreground="white",
                activebackground="#4B4C4F",
            )

            FileMenu.add_command(
                label="Open",
                command=openFile,
                background="#292A2D",
                foreground="white",
                activebackground="#4B4C4F",
            )
            # To save the current file
            FileMenu.add_command(
                label="Save",
                command=lambda: save_file(),
                background="#292A2D",
                foreground="white",
                activebackground="#4B4C4F",
            )
            FileMenu.add_command(
                label="Save As",
                command=lambda: save_as_File(),
                background="#292A2D",
                foreground="white",
                activebackground="#4B4C4F",
            )
            FileMenu.add_command(
                label="Rename",
                command=lambda: rename_file(),
                background="#292A2D",
                foreground="white",
                activebackground="#4B4C4F",
            )
            FileMenu.add_command(
                label="Exit",
                command=quitApp,
                foreground="white",
                background="#292A2D",
                activebackground="#4B4C4F",
            )
            MenuBar.add_cascade(
                label="File",
                menu=FileMenu,
                foreground="white",
                activebackground="#4B4C4F",
            )

            # File Menu ends
            def select_font(font):
                size = TextArea["font"]
                num = ""
                for i in size:
                    if i in "1234567890":
                        num += i
                real_size = int(num)
                new_font_size = (font, real_size)
                TextArea.config(font=new_font_size)

            def size_change(event):

                original_font = TextArea["font"]
                find_font = ""
                var = ""
                for i in original_font:
                    if i == " " or i.isalpha():
                        var += i
                size = 0

                find_font = var.rstrip()
                new_str = original_font.split()
                for i in new_str:
                    for a in i:
                        if a in "0123456789":
                            size = int(i)
                if size != 60 and event.delta == 120:
                    size += 1
                if size != 6 and event.delta == -120:
                    size -= 1
                new_font = (find_font, size)
                TextArea.configure(font=new_font)

            def change_size(size):
                global var
                lb = Label(mainarea, text=var, anchor=E)
                lb.pack(fill=X, side=TOP)
                var = len(str(TextArea.get("1.0", "end-1c")))
                lb.config(text=var)

                def update(event):
                    var = len(str(TextArea.get("1.0", "end-1c")))
                    lb.config(text=var)

                TextArea.bind("<KeyPress>", update)
                TextArea.bind("<KeyRelease>", update)
                original_font = TextArea["font"]
                find_font = ""
                var = ""
                for i in original_font:
                    if i == " " or i.isalpha():
                        var += i
                find_font = var.rstrip()
                new_font = (find_font, size)
                TextArea.configure(font=new_font)

            def change_color():
                my_color = colorchooser.askcolor()[1]
                TextArea.config(fg=my_color)

            def bg_color():
                my_color = colorchooser.askcolor()[1]
                TextArea.config(bg=my_color)

            def highlight_text():
                TextArea.tag_configure(
                    "start", background="#FFFF00", foreground="#292A2D"
                )
                try:
                    TextArea.tag_add("start", "sel.first", "sel.last")
                except TclError:
                    pass

            def secondary(*event):
                replace_window = Toplevel(mainarea)
                replace_window.focus_set()
                replace_window.grab_set()
                replace_window.title("Replace")
                replace_entry = Entry(replace_window)
                find_entry_new = Entry(replace_window)
                find_entry_new.grid(row=0, column=0)
                replace_button = Button(
                    replace_window,
                    text="Replace",
                    command=lambda: replacenfind(
                        find_entry_new.get(), replace_window, str(replace_entry.get())
                    ),
                )
                replace_button.grid(row=1, column=1)
                replace_entry.grid(row=1, column=0)

            def primary(*event):
                find_window = Toplevel(mainarea)
                find_window.geometry("100x50")
                find_window.focus_set()
                find_window.grab_set()
                find_window.title("Find")
                find_entry = Entry(find_window)
                find_button = Button(
                    find_window,
                    text="Find",
                    command=lambda: find(find_entry.get(), find_window),
                )
                find_entry.pack()
                find_button.pack(side="right")

            def replacenfind(value, window, replace_value):
                text_find = str(value)
                index = "1.0"
                TextArea.tag_remove("found", "1.0", END)
                if value:
                    while 1:
                        index = TextArea.search(
                            text_find, index, nocase=1, stopindex=END
                        )
                        if not index:
                            break
                        lastidx = "% s+% d" % (index, len(text_find))
                        TextArea.delete(index, lastidx)
                        TextArea.insert(index, replace_value)
                        lastidx = "% s+% d" % (index, len(replace_value))
                        TextArea.tag_add("found", index, lastidx)
                        index = lastidx
                    TextArea.tag_config("found", foreground="blue")
                window.focus_set()

            def find(value, window):
                text_find = str(value)
                index = "1.0"
                TextArea.tag_remove("found", "1.0", END)
                if value:
                    while 1:
                        index = TextArea.search(
                            text_find, index, nocase=1, stopindex=END
                        )
                        if not index:
                            break
                        lastidx = "% s+% dc" % (index, len(text_find))
                        TextArea.tag_add("found", index, lastidx)
                        index = lastidx
                    TextArea.tag_config("found", foreground="red")
                window.focus_set()

            def popup_menu(e):
                my_menu.tk_popup(e.x_root, e.y_root)

            root.bind("<Control-Key-f>", primary)
            root.bind("<Control-Key-h>", secondary)

            EditMenu = Menu(MenuBar, tearoff=0)
            EditMenu.config(
                bg="#292A2D", bd="0", relief="ridge", activebackground="#292A2D"
            )
            TextArea.bind("<Control-MouseWheel>", size_change)

            my_menu = Menu(
                mainarea, tearoff=0, bd="0", borderwidth="0", background="#292A2D"
            )
            my_menu.config(bg="#292A2D", bd="0", activebackground="#292A2D")
            my_menu.add_command(
                label="Highlight",
                command=highlight_text,
                foreground="white",
                background="#292A2D",
                activebackground="#4B4C4F",
            )
            my_menu.add_command(
                label="Copy",
                command=copy,
                foreground="white",
                background="#292A2D",
                activebackground="#4B4C4F",
            )
            my_menu.add_command(
                label="Cut",
                command=cut,
                background="#292A2D",
                foreground="white",
                activebackground="#4B4C4F",
            )
            my_menu.add_command(
                label="Paste",
                command=paste,
                foreground="white",
                background="#292A2D",
                activebackground="#4B4C4F",
            )
            my_menu.add_separator()

            def undo():
                try:
                    TextArea.edit_undo()
                except:
                    pass

            def redo():
                try:
                    TextArea.edit_redo()
                except:
                    pass

            try:
                my_menu.add_command(
                    label="Undo",
                    command=undo,
                    foreground="white",
                    background="#292A2D",
                    activebackground="#4B4C4F",
                )
            except:
                pass

            try:
                my_menu.add_command(
                    label="Redo",
                    command=redo,
                    foreground="white",
                    background="#292A2D",
                    activebackground="#4B4C4F",
                )
            except:
                pass
            TextArea.focus_set()
            TextArea.bind("<Button-3>", popup_menu)

            # To give a feature of cut, copy and paste
            highlight_text_button = Button(
                MenuBar, text="highlight", command=highlight_text
            )
            highlight_text_button.grid(row=0, column=5, sticky=W)
            submenu = Menu(EditMenu, tearoff=0)
            submenu_size = Menu(EditMenu, tearoff=0)
            submenu.config(bg="#292A2D", bd="0", activebackground="#292A2D")
            submenu_size.config(bg="#292A2D", bd="0", activebackground="#292A2D")

            submenu.add_command(
                label="MS Sans Serif",
                command=lambda: select_font("MS Sans Serif"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Arial",
                command=lambda: select_font("Arial"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Bahnschrift",
                command=lambda: select_font("Bahnschrift"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Cambria",
                command=lambda: select_font("Cambria"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Consolas",
                command=lambda: select_font("Consolas"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Courier",
                command=lambda: select_font("Courier"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Century",
                command=lambda: select_font("Century"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Calibri",
                command=lambda: select_font("Calibri"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Yu Gothic",
                command=lambda: select_font("Yu Gothic"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Times New Roman",
                command=lambda: select_font("Times New Roman"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Sylfaen",
                command=lambda: select_font("Sylfaen"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Nirmala UI",
                command=lambda: select_font("Nirmala UI"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Ebrima",
                command=lambda: select_font("Ebrima"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Comic Sans MS",
                command=lambda: select_font("Comic Sans MS"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Microsoft PhagsPa",
                command=lambda: select_font("Microsoft PhagsPa"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Lucida  Console",
                command=lambda: select_font("Lucida Console"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Franklin Gothic Medium",
                command=lambda: select_font("Franklin Gothic Medium"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Cascadia Code",
                command=lambda: select_font("Cascadia Code"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="6",
                command=lambda: change_size(6),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="7",
                command=lambda: change_size(7),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="8",
                command=lambda: change_size(8),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="9",
                command=lambda: change_size(9),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="10",
                command=lambda: change_size(10),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="11",
                command=lambda: change_size(11),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="12",
                command=lambda: change_size(12),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="13",
                command=lambda: change_size(13),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="14",
                command=lambda: change_size(14),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="15",
                command=lambda: change_size(15),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="16",
                command=lambda: change_size(16),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="17",
                command=lambda: change_size(17),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="18",
                command=lambda: change_size(18),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="19",
                command=lambda: change_size(19),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="20",
                command=lambda: change_size(20),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="21",
                command=lambda: change_size(21),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="22",
                command=lambda: change_size(22),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="23",
                command=lambda: change_size(23),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="24",
                command=lambda: change_size(24),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="25",
                command=lambda: change_size(25),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="26",
                command=lambda: change_size(26),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="27",
                command=lambda: change_size(27),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="28",
                command=lambda: change_size(28),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="29",
                command=lambda: change_size(29),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(30),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(31),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(32),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(33),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(34),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(35),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(36),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(37),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(38),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(39),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(40),
                foreground="white",
                activebackground="#4B4C4F",
            )

            EditMenu.add_command(
                label="Text Color",
                command=change_color,
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Background Color",
                command=bg_color,
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Cut",
                command=cut,
                accelerator="(Ctrl+x)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Copy",
                command=copy,
                accelerator="(Ctrl+c)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Paste",
                command=paste,
                accelerator="(Ctrl+v)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Find",
                command=primary,
                accelerator="(Ctrl+f)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Replace",
                command=secondary,
                accelerator="(Ctrl+h)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Undo",
                command=TextArea.edit_undo,
                accelerator="(Ctrl+z)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Redo",
                command=TextArea.edit_redo,
                accelerator="(Ctrl+y)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_cascade(
                label="Font",
                menu=submenu,
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_cascade(
                label="Size",
                menu=submenu_size,
                foreground="white",
                activebackground="#4B4C4F",
            )
            MenuBar.add_cascade(
                label="Edit",
                menu=EditMenu,
                foreground="white",
                activebackground="#4B4C4F",
            )

            def callback(event):
                save_file()

            def second_callback(event):
                file = None
                save_as_File(file)
                # To Open already existing file

            # bindings
            root.bind("<Control-Key-s>", callback)
            root.bind("<Control-Shift-S>", second_callback)
            root.bind("<Control-Key-x>", cut)
            root.bind("<Control-Key-c>", copy)
            root.bind("<Control-Key-v>", paste)
            # Help Menu Starts
            HelpMenu = Menu(
                MenuBar, tearoff=0, bg="#292A2D", bd="0", activebackground="#292A2D"
            )
            HelpMenu.add_command(
                label="About Notepad",
                command=about,
                foreground="white",
                activebackground="#4B4C4F",
            )
            MenuBar.add_cascade(
                label="Help",
                menu=HelpMenu,
                foreground="white",
                activebackground="#4B4C4F",
            )

            # Help Menu Ends
            MenuBar.pack_propagate(0)
            sidebar.pack_propagate(0)
            root.config(menu=MenuBar)

    # main content area
    # main content area
    pass_img = tk_image.PhotoImage(image.open("images\\password.png"))
    notes_img = tk_image.PhotoImage(image.open("images\\notes.png"))
    mainarea = Frame(root, bg="#292A2D", width=500, height=500)
    mainarea.pack(expand=True, fill="both", side="right")

    button = Button(
        sidebar,
        image=pass_img,
        text="Passwords",
        padx=20,
        compound="left",
        fg="white",
        bg="black",
        command=lambda: testing(root, mainarea, username, hash_password, button),
    )

    my_cursor.execute(
        "select email_id,salt_recovery from data_input where username = (?)",
        (username,),
    )

    email_id = ""
    for email in my_cursor.fetchall():
        email_id = email[0]
    # getting password
    # generating the static salt and decrypting the password
    email_split = ""
    decrypted_string = ""
    word = email_id.split()
    for i in word:
        for a in i:
            if i == "@":
                break
            else:
                email_split += i
    val = email_split[::-1]

    # decrypting the recovery passworwd using pbkdf2
    my_cursor.execute(
        "select recovery_password,salt_recovery from data_input where username = (?)",
        (username,),
    )
    encrypted_pass = ""
    d = my_cursor.fetchall()
    for i in d:
        password = email_id + hash_password

        key = pbkdf2.PBKDF2(password, i[1]).read(32)

        aes = pyaes.AESModeOfOperationCTR(key)
        encrypted_pass = aes.decrypt(i[0])

    notes_buttons = Button(
        sidebar,
        image=notes_img,
        text="Notes",
        padx=27,
        compound="left",
        command=note_pad_sec,
        fg="white",
        bg="black",
    )
    button.grid(row=0, column=1)
    notes_buttons.grid(row=1, column=1)
    # profile_button.grid(row=2,column=1)
    settings_image = tk_image.PhotoImage(image.open("images\\settings.png"))
    settings_button = Button(
        sidebar,
        activebackground="#292A2D",
        image=settings_image,
        fg="white",
        bg="#292A2D",
        border="0",
        command=lambda: settings(
            username,
            root,
            hash_password,
            mainarea,
            button,
            encrypted_pass,
            password_new,
        ),
        relief=FLAT,
        highlightthickness=0,
        activeforeground="white",
        bd=0,
        borderwidth=0,
    )
    profile_object = Profile_view(
        username,
        password_new,
        email_id,
        encrypted_pass,
        hash_password,
        mainarea,
        button,
        notes_buttons,
    )

    profile_button = Button(
        sidebar,
        text="Profile",
        activebackground="#292A2D",
        activeforeground="white",
        command=lambda: profile_object.profile_window(mainarea, root, profile_button),
        padx=46,
        fg="white",
        bg="black",
    )
    profile_button.grid(row=2, column=1)

    settings_button.photo = settings_image
    settings_button.grid(row=10, column=1, columnspan=1)
    settings_button.place(x=30 + 50 + 10, y=440 + 200 + 20)

    root.mainloop()


def change_icon(
    button, usernam, users_username, hashed_password, window, password_button
):
    file_name = users_username + "decrypted.bin"
    l = [(32, 32), (16, 16)]
    image_path = fd.askopenfilename(
        filetypes=[("image", "*.png"), ("image", "*.jpeg"), ("image", "*.jpg")],
        title="Add icon",
    )
    f = open(file_name, "rb")
    pad = pickle.load(f)
    f.close()
    path = ""
    for i in pad:
        if i[0] == usernam:
            path = i[3]
    if path == "":
        path_im = image.open("images\\camera.png")
    else:
        path_im = image.open(path)

    try:
        im = image.open(image_path)

        if im:

            if im.size in l:
                for i in pad:
                    if i[0] == usernam:
                        i[3] = image_path
                f.close()
                with open(file_name, "wb") as f1:
                    pickle.dump(pad, f1)
                    f1.close()
                os.remove(users_username + ".bin.fenc")

                pyAesCrypt.encryptFile(
                    file_name, users_username + ".bin.fenc", hashed_password, bufferSize
                )
                new_tk = tk_image.PhotoImage(im)
                button.config(image=new_tk)
                button.photo = new_tk
                gameloop(users_username, hashed_password, window, password_button)
            else:
                messagebox.showerror(
                    "Error", "Please provide icon size of 32x32 or 16x16 "
                )
                im = image.open("images\\camera.png")
                new_tk = tk_image.PhotoImage(im)
                button.config(image=new_tk)
                button.photo = new_tk
                image_path = fd.askopenfilename(
                    filetypes=[("image", "*.png")], title="Add icon"
                )
                gameloop(users_username, hashed_password, window, password_button)

    except:
        new_tk = tk_image.PhotoImage(path_im)
        button.config(image=new_tk)
        button.photo = new_tk


def addaccount(username, button, hashed_password, window, sidebar, password_button):
    root1 = Toplevel()
    root1.geometry("400x300")
    root1.title("Add Account")
    root1.focus_set()
    root1.grab_set()
    root1.resizable(False, False)
    width_window = 400
    height_window = 400
    screen_width = root1.winfo_screenwidth()
    screen_height = root1.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2
    root1.config(bg="#292A2D")
    root1.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
    name_of_social = Label(root1, text="Name of the account", fg="white", bg="#292A2D")
    name_of_social_entry = Entry(root1)
    username_window = Label(root1, text="Username:", fg="white", bg="#292A2D")
    password_window = Label(root1, text="Password:", fg="white", bg="#292A2D")
    username_window_entry = Entry(root1)
    password_entry = Entry(root1)

    password_entry.grid(row=2, column=2)
    username_window_entry.grid(row=1, column=2)
    password_window.grid(row=2, column=1)
    username_window.grid(row=1, column=1)
    name_of_social_entry.grid(row=0, column=2)
    name_of_social.grid(row=0, column=1)

    username_window.place(x=50, y=100 + 100)
    password_window.place(x=50, y=130 + 100)
    name_of_social.place(x=50, y=70 + 100)
    username_window_entry.place(x=200, y=100 + 100)
    password_entry.place(x=200, y=130 + 100)
    name_of_social_entry.place(x=200, y=70 + 100)

    def browsefunc():
        try:
            image_path = fd.askopenfilename()
            im = image.open(image_path)
            tkimage = tk_image.PhotoImage(im)
            add_icon_button.config(image=tkimage)
            add_icon_button.photo = tkimage
        except:
            image_path = "images\\photo.png"
            im = image.open(image_path)
            tkimage = tk_image.PhotoImage(im)
            add_icon_button.config(image=tkimage)
            add_icon_button.photo = tkimage

    new_id = tk_image.PhotoImage(image.open("images\\photo.png"))
    add_icon_button = Button(
        root1,
        image=new_id,
        borderwidth="0",
        command=browsefunc,
        border="0",
        highlightthickness="0",
        activebackground="#292A2D",
        bg="#292A2D",
    )
    add_icon_button.photo = new_id
    add_icon_button.grid(row=3, column=0)
    add_icon_button.place(x=125, y=200)

    def save():
        global exist
        list_account = [
            str(username_window_entry.get()),
            str(password_entry.get()),
            str(name_of_social_entry.get()),
            image_path,
        ]
        if str(username_window_entry.get()) == "":
            messagebox.showwarning("Warning", "Username cannot be empty")
        elif str(password_entry.get()) == "":
            messagebox.showwarning("Warning", "Password cannot be empty")
        elif str(name_of_social_entry.get()) == "":
            messagebox.showwarning("Warning", "Name of the account cannot be empty")
        else:
            verifying = verify(
                username_window_entry.get(), name_of_social_entry.get(), username
            )

            if verifying:
                messagebox.showerror("Error", "The account already exists")
            else:
                name_file = username + "decrypted.bin"
                with open(name_file, "rb") as f:
                    try:
                        line = pickle.load(f)
                    except:
                        line = []
                    line.append(list_account)
                    f.close()
                with open(name_file, "wb") as f1:
                    pickle.dump(line, f1)
                    f.close()
                os.remove(username + ".bin.fenc")
                pyAesCrypt.encryptFile(
                    name_file, username + ".bin.fenc", hashed_password, bufferSize
                )
                messagebox.showinfo("Success", "Your account has been saved")
                root1.destroy()
                with open(f"{username}decrypted.bin", "rb") as f:
                    val = pickle.load(f)
                    button.grid(row=len(val) + 1, column=0)
                gameloop(username, hashed_password, window, password_button)

    save_button = Button(root1, text="Save", command=save, fg="white", bg="#292A2D")
    save_button.grid(row=4, column=1)
    save_button.place(x=250, y=170 + 100)
    add_icon_button.place(x=150, y=50)
    root1.mainloop()


def verify(social_username, social_media, real_username):
    file_name = f"{real_username}decrypted.bin"
    with open(file_name, "rb") as f:
        try:
            test_values = pickle.load(f)
            for user in test_values:
                if user[0] == str(social_username) and user[2] == str(social_media):
                    return True
        except:
            return False


def actions(button, window, username, hashed_password, bg_img, password_button):
    global buttons_list

    change_object = Change_details(username, hashed_password, window)

    delete_object = Deletion(username, hashed_password, window)

    try:
        for widget in window.winfo_children():
            if str(widget.winfo_class()) != "Frame":
                widget.destroy()
    except:
        pass
    # creating a canvas to fix background image
    new_canvas = Canvas(
        window, width=1000 + 50, height=1057, bd="0", highlightthickness=0
    )
    new_canvas.place(x=120 + 20, y=0)
    new_canvas.create_image(0, 0, image=bg_img, anchor="nw")
    new_s = Frame(new_canvas, bg="#292A2D", width=450, height=400, bd=0)
    MainWindow = new_canvas.create_window(650 + 60, 600 - 60, window=new_s, anchor="se")

    with open(f"{username}decrypted.bin", "rb") as f:

        lists = pickle.load(f)
        dot_text = Label(new_s, text=":", bg="#292A2D", fg="white", font=(20))
        dot_text1 = Label(new_s, text=":", bg="#292A2D", fg="white", font=(20))
        dot_text2 = Label(new_s, text=":", bg="#292A2D", fg="white", font=(20))

        delete_account = Button(
            new_s,
            text="Delete Account",
            bg="#292A2D",
            fg="white",
            font=("Verdana", 15),
            command=lambda: delete_object.delete_social_media_account(
                password_button, False, lists[button][2]
            ),
        )

        ChangeAccount = Button(
            new_s,
            text="Change Details",
            bg="#292A2D",
            fg="white",
            font=("Verdana", 15),
            command=lambda: change_object.change_window_creation(
                lists[button][0], password_button
            ),
        )

        username_label = Label(
            new_s,
            text="Username",
            bg="#292A2D",
            fg="white",
            font=("Verdana", 15),
        )
        password_label = Label(
            new_s,
            text="Password",
            bg="#292A2D",
            fg="white",
            font=("Verdana", 15),
        )
        social_account = Label(
            new_s,
            text="Account Name",
            bg="#292A2D",
            fg="white",
            font=("Verdana", 15),
        )

        username_text = Label(
            new_s,
            text=lists[button][0],
            bg="#292A2D",
            fg="white",
            font=("Verdana", 15),
        )
        password_text = Label(
            new_s,
            text=lists[button][1],
            bg="#292A2D",
            fg="white",
            font=("Verdana", 15),
        )
        social_account_text = Label(
            new_s,
            text=lists[button][2],
            bg="#292A2D",
            fg="white",
            font=("Verdana", 15),
        )

        if lists[button][3] == "":
            img = tk_image.PhotoImage(image.open("images\\camera.png"))
        else:
            img = tk_image.PhotoImage(image.open(lists[button][3]))
        img_button = Button(
            new_s,
            image=img,
            border="0",
            bg="#292A2D",
            activebackground="#292A2D",
            command=lambda: change_icon(
                img_button,
                lists[button][0],
                username,
                hashed_password,
                new_s,
                password_button,
            ),
        )
        img_button.photo = img

        img_button.place(x=160, y=30)
        dot_text.place(x=170 + 20, y=175 + 3)
        dot_text1.place(x=170 + 20, y=200 + 25 + 3)
        dot_text2.place(x=170 + 20, y=250 + 25 + 3)

        delete_account.place(x=0 + 10, y=350)
        username_label.place(x=30, y=175)
        password_label.place(x=30, y=200 + 25)
        social_account.place(x=30, y=250 + 25)
        username_text.place(x=250, y=150 + 25)
        password_text.place(x=250, y=200 + 25)
        social_account_text.place(x=250, y=250 + 25)
        ChangeAccount.place(x=250 + 25 - 3, y=350)


def buttons_blit(
    username, window, add_button, mainarea, hashed_password, bg_img, password_button
):
    global buttons_list
    global btn_nr
    new = []

    with open(f"{username}decrypted.bin", "rb") as f:
        try:
            val = pickle.load(f)
            for i in val:
                new.append(i[2])
            d = {}
            for i in range(len(new)):
                if val[i][3] == "":
                    button_img = tk_image.PhotoImage(image.open("images\\photo.png"))
                else:
                    button_img = tk_image.PhotoImage(image.open(val[i][3]))
                d[
                    Button(
                        window,
                        text=f"{new[i]}",
                        bg="#292A2D",
                        fg="white",
                        activeforeground="white",
                        activebackground="#292A2D",
                        width=120,
                        font=("Segoe UI Semibold", 9),
                        image=button_img,
                        compound="top",
                        command=lambda a=i: actions(
                            a,
                            mainarea,
                            username,
                            hashed_password,
                            bg_img,
                            password_button,
                        ),
                    )
                ] = [i, button_img]

            for i in d:
                i.image = d[i][1]
                i.grid(row=d[i][0], column=0)
            with open(f"{username}decrypted.bin", "rb") as f:
                try:
                    values = pickle.load(f)
                except:
                    values = []
            length_list = len(values)
            add_button.grid(row=length_list + 1, column=0)
        except:
            pass


def gameloop(username, hashed_password, window, password_button):
    bg_img = tk_image.PhotoImage(image.open("images\\log.jpg"))
    vals = window.grid_slaves()
    try:
        for i in vals:
            i.destroy()
    except:
        pass

    window.config(bg="#292A2D")
    subbar = Frame(
        window, bg="black", width=120, height=1027, relief="sunken", borderwidth=2
    )
    subbar.grid(row=0, column=0)
    subbar.grid_propagate(False)
    new_l = Label(window, image=bg_img, bd=0)
    new_l.image = bg_img
    new_l.place(x=120 + 20, y=0)
    canvas = Canvas(
        subbar, width=120, height=1027, bg="black", bd="0", highlightthickness=0
    )
    canvas.pack(side="left", fill=BOTH)

    scrollbar = Scrollbar(
        subbar,
        orient=VERTICAL,
        activebackground="#292A2D",
        troughcolor="white",
        takefocus=1,
        highlightbackground="#292A2D",
        highlightthickness=0,
        bg="#292A2D",
        command=canvas.yview,
    )

    scrollbar.pack(expand=1, fill=Y)

    # configure the canvas
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.bind(
        "<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all"))
    )

    # creating another frame
    second_frame = Frame(
        canvas, width=120, height=1027, bd="0", bg="black", highlightbackground="black"
    )

    # add that new frame to a new window in the canvas
    canvas.create_window((0, 0), window=second_frame, anchor="ne")
    image_new = tk_image.PhotoImage(image.open("images\\add-button.png"))
    bg_img = tk_image.PhotoImage(image.open("images\\log.jpg"))

    add_button = Button(
        second_frame,
        text="Add",
        fg="white",
        image=image_new,
        compound="top",
        activeforeground="white",
        bg="#292A2D",
        height=80,
        activebackground="#292A2D",
        width=120,
        relief=RAISED,
        font=("Verdana", 9),
        command=lambda: addaccount(
            username, add_button, hashed_password, window, subbar, password_button
        ),
    )
    add_button.photo = image_new
    values = []
    with open(f"{username}decrypted.bin", "rb") as f:
        try:
            values = pickle.load(f)
        except:
            pass
    length_list = len(values)
    add_button.grid(row=length_list, column=0)
    buttons_blit(
        username,
        second_frame,
        add_button,
        window,
        hashed_password,
        bg_img,
        password_button,
    )


def get(window, name):
    global l
    for i in l:
        for a in i:
            if a == name:
                d = tk_image.PhotoImage(image.open(i[a]), master=window)
                return d


def handle_focus_in(entry, index, *number):
    val = str(entry.get())
    if val == "Username" or val == "Email ID" or val == "New Email":
        entry.delete(0, END)
        entry.config(foreground="black")
    if val == "Password" or val == "Email password" or val == "New Email password":
        entry.delete(0, END)
        entry.config(foreground="black")
        entry.config(show="*")
    elif (
        index == 2
        and val == "Password"
        or index == 4
        and val == "Email password"
        or index == 2
        and val == "New Email password"
    ):
        entry.config(foreground="white")
        state_entry = entry["show"]
        entry.config(show=state_entry)
    try:
        for i in number:
            if i == 0:
                entry.config(foreground="white")
            elif i == 1:
                entry.config(foreground="white")
    except:
        pass


def handle_focus_out(entry, val, index):
    a = entry.get()
    if a == "" and index == 2 or a == "" and index == 4:
        entry.delete(0, END)
        entry.config(foreground="grey")
        entry.config(show="")
        entry.insert(0, val)
    elif a == "":
        entry.delete(0, END)
        entry.config(foreground="grey")
        entry.insert(0, val)


def splash_screen(fn, username, main_password, passw):
    import time

    try:
        splash_screen = Tk()
        loading_acc = Label(
            splash_screen, fg="black", bg="white", text="Loading Your Accounts....."
        )
        # Progress bar widget
        progress = Progressbar(
            splash_screen, orient=HORIZONTAL, length=100, mode="determinate"
        )

        # Function responsible for the updation
        # of the progress bar value
        def bar():
            try:
                for i in range(0, 101):
                    progress["value"] = i
                    splash_screen.update_idletasks()
                    time.sleep(0.01)
            except:
                pass

        progress.pack(pady=10)
        loading_acc.pack(pady=20)
        threading.Thread(target=bar).start()
        splash_screen.config(bg="white")
        width_window = 400
        height_window = 100
        screen_width = splash_screen.winfo_screenwidth()
        screen_height = splash_screen.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        splash_screen.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))

        splash_screen.overrideredirect(True)
        splash_screen.after(
            1600, lambda: fn(username, main_password, passw, splash_screen)
        )
        splash_screen.mainloop()
    except:
        pass


def password_sec(entry, button):
    a = entry["show"]
    private_img = tk_image.PhotoImage(image.open("images\\private.png"))
    unhide_img = tk_image.PhotoImage(image.open("images\\eye.png"))
    val = str(entry.get())
    if val == "Password" or val == "Email Password":
        entry.config(show="")
    else:
        if a == "*":
            entry.config(show="")
            button.config(image=private_img)
            button.photo = private_img
            button.image = private_img
        if a == "":
            entry.config(show="*")
            button.config(image=unhide_img)
            button.photo = unhide_img
            button.image = unhide_img


def login(*window):
    global private_img
    global unhide_img
    try:
        for i in window:
            i.destroy()
    except:
        pass

    login_window = Tk()

    login_window.resizable(False, False)
    login_window.title("Login")
    width_window = 1057
    height_window = 700
    login_window.focus_set()
    login_window.grab_set()
    login_window.config(bg="white")
    screen_width = login_window.winfo_screenwidth()
    screen_height = login_window.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2
    login_window.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))

    image1 = tk_image.PhotoImage(image.open("images\\loginbg.jpg"))
    image1_label = Label(login_window, image=image1, bd=0)
    image1_label.image = image1
    image1_label.place(x=0, y=0)

    labelframe = LabelFrame(
        login_window, bg="white", width=900, height=450, borderwidth=2, relief="solid"
    )
    labelframe.place(x=80, y=125)

    # canvas for showing lines
    my_canvas = Canvas(labelframe, bg="grey", width=1, height=440 + 2)
    my_canvas.place(x=490 - 50, y=0)
    my_canvas.create_line(500, 0, 490, 450, width=0, fill="grey")

    submit_button = tk_image.PhotoImage(image.open("images\\submit.png"))
    # all label text widgets

    create_text = Label(
        labelframe,
        fg="black",
        bg="white",
        font=("Yu Gothic Ui", 15),
        text="If you don't already have an account click\nthe button below to create your account.",
        justify=LEFT,
    )
    create_text.place(x=500, y=50, anchor="w")

    or_text = Label(
        labelframe, text="OR", fg="black", bg="white", font=("Yu Gothic Ui", 15)
    )
    or_text.place(x=670, y=165)

    forgot_text = Label(
        labelframe,
        fg="black",
        bg="white",
        text="So you can't get in your account?Did you \nforget your password?",
        font=("Yu Gothic Ui", 15),
        justify=LEFT,
    )
    forgot_text.place(x=500, y=240, anchor="w")

    # ------------------Entry---------------------------
    input_entry = Entry(
        labelframe,
        width=20 + 5,
        foreground="white",
        bg="white",
        relief=RAISED,
        selectforeground="white",
        fg="white",
        bd=0,
        insertbackground="black",
        font=("consolas", 15, "normal"),
    )

    pass_entry = Entry(
        labelframe,
        fg="white",
        bg="white",
        width=17 + 5,
        relief=RAISED,
        show="*",
        bd=0,
        insertbackground="black",
        font=("consolas", 15, "normal"),
    )

    pass_entry.icursor(0)
    input_entry.icursor(0)

    pass_entry.place(x=50 + 3, y=200 + 30)
    input_entry.place(x=50 + 3, y=150)
    # login label
    login_label = Label(
        labelframe,
        text="Login",
        fg="black",
        bg="white",
        font=("Cascadia Mono SemiBold", 20, "bold"),
    )
    login_label.place(x=50, y=70)

    # dot label

    Frame(labelframe, width=280, height=2, bg="black").place(x=50 + 3, y=230 + 30)
    Frame(labelframe, width=280, height=2, bg="black").place(x=50 + 3, y=150 + 30)

    # ------------------Button---------------------------

    forgot = Button(
        labelframe,
        text="FORGOT PASSWORD?",
        width=33,
        command=lambda: login_password("Forgot Password"),
        fg="white",
        bg="#405A9B",
        border="0",
        highlightcolor="white",
        activebackground="#405A9B",
        activeforeground="white",
        relief=RAISED,
        font=("Segoe UI Semibold", 15),
    )
    register_button = Button(
        labelframe,
        text="CREATE ACCOUNT",
        width=33,
        command=lambda: register(window, login_window),
        fg="white",
        bg="black",
        border="0",
        highlightcolor="white",
        activebackground="black",
        activeforeground="white",
        relief=RAISED,
        font=("Segoe UI Semibold", 15),
    )

    register_button.place(x=500 + 2, y=100)

    forgot.place(x=500, y=280)
    bar_label = Label(labelframe, text="|", bg="white", fg="white", font=(100))

    bar_label.place(x=200, y=470 - 10 + 2)

    private_img = tk_image.PhotoImage(image.open("images\\private.png"))
    unhide_img = tk_image.PhotoImage(image.open("images\\eye.png"))
    show_both_1 = Button(
        labelframe,
        fg="white",
        bg="white",
        command=lambda: password_sec(pass_entry, show_both_1),
        highlightcolor="white",
        activebackground="white",
        activeforeground="white",
        bd=0,
        relief=RAISED,
        font=("consolas", 18),
    )
    show_both_1.config(
        image=unhide_img,
    )
    show_both_1.photo = unhide_img

    def login_checking_1(*event):
        try:
            my_cursor.execute(
                "select email_id from data_input where username = (?)",
                (str(input_entry.get()),),
            )
            val_list = my_cursor.fetchall()
            password = str(pass_entry.get())
            username = str(input_entry.get())
            login = Login(username, password)
            if username != "" or password != "":
                check, main_password, passw = login.login_checking()
                if check:
                    try:
                        root = Tk()
                        root.withdraw()

                        messagebox.showinfo("Success", "You have now logged in ")
                        root.destroy()
                        try:
                            login_window.destroy()
                        except:
                            pass
                        splash_screen(window_after, username, main_password, passw)
                    except:
                        pass
                else:
                    pass
            else:
                if username == "":
                    messagebox.showwarning("Error", "Cannot have username")
                elif password == "":
                    messagebox.showwarning("Error", "Cannot have blank password")
        except:
            pass

    login_window.bind("<Return>", login_checking_1)

    input_entry.insert(END, "Username")
    input_entry.config(foreground="grey")
    pass_entry.insert(END, "Password")
    pass_entry.config(foreground="grey")
    pass_entry.config(show="")

    sub_button = Button(
        labelframe,
        bd=0,
        width=23,
        height=1,
        text="LOG IN",
        font=("Cascadia Mono SemiBold", 15),
        activeforeground="white",
        relief=SUNKEN,
        fg="white",
        bg="#C52522",
        activebackground="#C52522",
        command=login_checking_1,
    )
    sub_button.image = submit_button
    sub_button.place(x=50 + 3, y=300 + 30)

    show_both_1.place(x=300, y=200 + 30 - 5)

    input_entry.bind(
        "<FocusIn>",
        lambda event, val_val=input_entry, index=1: handle_focus_in(val_val, index),
    )
    input_entry.bind(
        "<FocusOut>",
        lambda event, val_val=input_entry, val="Username", index=1: handle_focus_out(
            val_val, val, index
        ),
    )

    pass_entry.bind(
        "<FocusIn>",
        lambda event, val_val=pass_entry, index=2: handle_focus_in(val_val, index),
    )
    pass_entry.bind(
        "<FocusOut>",
        lambda event, val_val=pass_entry, val="Password", index=2: handle_focus_out(
            val_val, val, index
        ),
    )


def register(window, *a):
    try:
        for wins in a:
            wins.destroy()
        window.destroy()

    except:
        pass
    login_window1 = Tk()
    login_window1.resizable(False, False)
    login_window1.focus_set()

    login_window1.title("Register")
    login_window1.config(bg="#292A2D")
    width_window = 1057
    height_window = 700
    screen_width = login_window1.winfo_screenwidth()
    screen_height = login_window1.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2

    login_window1.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))

    image1 = tk_image.PhotoImage(image.open("images\\background.jpg"))
    back_button = tk_image.PhotoImage(image.open("images\\cancel.png"))
    submit_button = tk_image.PhotoImage(image.open("images\\submit.png"))

    image1_label = Label(login_window1, bd=0, image=image1)
    image1_label.image = image1
    image1_label.place(x=0, y=0)
    iconimage = tk_image.PhotoImage(image.open("images\\member.png"))
    labelframe1 = LabelFrame(
        login_window1,
        bg="#292A2D",
        width=500,
        height=550,
        borderwidth=2,
        relief="solid",
    )
    labelframe1.place(x=270, y=75)

    icon_label = Label(labelframe1, image=iconimage, bg="#292A2D")
    icon_label.image = iconimage
    icon_label.place(x=180, y=20 + 30)

    # ------------------Labels---------------------------

    username = Label(
        labelframe1,
        fg="#ebebeb",
        text="Username",
        bd=5,
        bg="#292A2D",
        font=("Sitka Text", 15),
    )
    password = Label(
        labelframe1,
        fg="#ebebeb",
        text="Password",
        bd=5,
        bg="#292A2D",
        font=("Sitka Text", 15),
    )
    email_id = Label(
        labelframe1,
        fg="#ebebeb",
        text="Recovery Email",
        bg="#292A2D",
        bd=5,
        font=("Sitka Text", 15),
    )
    email_password = Label(
        labelframe1,
        fg="#ebebeb",
        text="Recovery Password",
        bg="#292A2D",
        bd=5,
        font=("Sitka Text", 15),
    )
    # placing the labels
    username.place(x=0, y=170 + 20 + 40 - 2)
    password.place(x=0, y=220 + 20 + 40 - 2)
    email_id.place(x=0, y=270 + 20 + 40 - 2)
    email_password.place(x=0, y=320 + 20 + 40 - 2)

    # ------------------Entry---------------------------
    username_entry = Entry(
        labelframe1,
        width=20,
        borderwidth=0,
        fg="#ebebeb",
        bg="#292A2D",
        relief=SUNKEN,
        insertbackground="white",
        font=("Leelawadee", 15, "normal"),
    )
    password_entry = Entry(
        labelframe1,
        show="*",
        fg="#ebebeb",
        bg="#292A2D",
        borderwidth=0,
        width=20,
        insertbackground="white",
        font=("Leelawadee", 15, "normal"),
    )
    email_id_entry = Entry(
        labelframe1,
        borderwidth=0,
        fg="#ebebeb",
        bg="#292A2D",
        width=20,
        insertbackground="white",
        font=("Leelawadee", 15, "normal"),
    )
    email_password_entry = Entry(
        labelframe1,
        borderwidth=0,
        fg="#ebebeb",
        bg="#292A2D",
        width=20,
        show="*",
        insertbackground="white",
        font=("Leelawadee", 15, "normal"),
    )

    username_entry.place(x=230, y=170 + 18 + 40 + 4)
    password_entry.place(x=230, y=220 + 18 + 40 + 4)
    email_id_entry.place(x=230, y=270 + 18 + 40 + 4)
    email_password_entry.place(x=230, y=320 + 18 + 40 + 4)

    Frame(labelframe1, width=220, height=2, bg="#ebebeb").place(
        x=230, y=170 + 18 + 40 + 4 + 20 + 7
    )
    Frame(labelframe1, width=220, height=2, bg="#ebebeb").place(
        x=230, y=220 + 18 + 40 + 4 + 20 + 7
    )
    Frame(labelframe1, width=220, height=2, bg="#ebebeb").place(
        x=230, y=270 + 18 + 40 + 4 + 20 + 7
    )
    Frame(labelframe1, width=220, height=2, bg="#ebebeb").place(
        x=230, y=320 + 18 + 40 + 4 + 20 + 7
    )

    # register function
    def register_saving(a, b, c, d):
        username_register = a
        password_register = b
        email_id_register = c
        email_password_register = d
        if username_register == "Username" or password_register == "Password":
            messagebox.showinfo("Fields Empty", "Fields cannot be empty")
        else:
            register_user = Register(
                username_register,
                password_register,
                email_id_register,
                email_password_register,
            )
            checking = register_user.check_pass_length()
            if checking:
                registering = register_user.saving(my_cursor)
                if registering:
                    messagebox.showinfo("Error", "Username  or email already exists")
                if not registering:
                    register_user.creation(login_window1)

            else:
                root2 = Tk()
                root2.withdraw()
                messagebox.showinfo(
                    "Error", "Please provide password greater than 6 characters"
                )
                root2.destroy()

    # except:
    #     pass

    submit_but = Button(
        labelframe1,
        bd=0,
        width=20,
        height=2,
        text="R E G I S T E R",
        font=("consolas"),
        fg="#292A2D",
        bg="#994422",
        activebackground="#994422",
        command=lambda: register_saving(
            str(username_entry.get()),
            str(password_entry.get()),
            str(email_id_entry.get()),
            str(email_password_entry.get()),
        ),
    )

    private_img = tk_image.PhotoImage(image.open("images\\private.png"))
    unhide_img = tk_image.PhotoImage(image.open("images\\eye.png"))

    show_both_1 = Button(
        labelframe1,
        image=unhide_img,
        command=lambda: password_sec(password_entry, show_both_1),
        fg="#292A2D",
        bg="#292A2D",
        bd=0,
        highlightcolor="#292A2D",
        activebackground="#292A2D",
        activeforeground="#292A2D",
        relief=RAISED,
    )
    show_both_1.image = unhide_img
    show_both_12 = Button(
        labelframe1,
        image=unhide_img,
        command=lambda: password_sec(email_password_entry, show_both_12),
        fg="#292A2D",
        bg="#292A2D",
        bd=0,
        highlightcolor="#292A2D",
        activebackground="#292A2D",
        activeforeground="#292A2D",
        relief=RAISED,
    )
    show_both_12.image = unhide_img

    show_both_1.place(x=450 + 8, y=220 + 18 + 40)
    show_both_12.place(x=450 + 8, y=320 + 18 + 40)

    login_button = Button(
        labelframe1,
        text="L O G I N",
        width=22,
        height=2,
        font=("consolas"),
        fg="#292A2D",
        bg="#994422",
        activebackground="#994422",
        bd=0,
        relief=SUNKEN,
        command=lambda: login(login_window1),
    )
    login_button.place(x=30, y=470)

    submit_but.place(x=300 - 20, y=470)
    login_window1.mainloop()


# ---------------------Importing Images------------------

image1 = tk_image.PhotoImage(image.open("images\\background.jpg"))
login_window = tk_image.PhotoImage(image.open("images\\login_but.png"))
imagelogin_windoweg = tk_image.PhotoImage(image.open("images\\reg_button.png"))
iconimage = tk_image.PhotoImage(image.open("images\\icon.png"))
cancelimage = tk_image.PhotoImage(image.open("images\\cancel.png"))

image1_label = Label(root, image=image1, bd=0)
image1_label.place(x=0, y=0)

root.config(bg="black")

labelframe = LabelFrame(
    root, bg="#2B2B2B", width=350, height=500, borderwidth=2, relief="solid"
)
labelframe.pack(padx=100, pady=100)

icon_label = Label(labelframe, bg="#2B2B2B", image=iconimage)
icon_label.place(x=110, y=20)

# ----------------------Buttons----------------------------

register_button = Button(
    labelframe,
    text="Login",
    bd=0,
    activebackground="#292A2D",
    bg="#292A2D",
    image=login_window,
    command=lambda: login(root),
)
register_button.place(x=80, y=210)
view = Button(
    labelframe,
    text="Register",
    bd=0,
    activebackground="#292A2D",
    image=imagelogin_windoweg,
    command=lambda: register(root),
    bg="#292A2D",
)
view.place(x=80, y=300 - 10)
close = Button(
    labelframe,
    image=cancelimage,
    activebackground="#292A2D",
    bd=0,
    command=root.destroy,
    bg="#292A2D",
)
close.place(x=80, y=370)

root.resizable(False, False)
root.mainloop()

""" to remove all decrypted files
the glob function returns a list of files ending with decrypted.bin"""
list_file = glob.glob("*decrypted.bin")
for i in list_file:
    try:
        os.remove(str(i))
    except:
        pass
