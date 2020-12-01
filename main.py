# all required modules
import base64
import glob
import hashlib
import os
import os.path
import pickle
import pyAesCrypt
import random
import smtplib
import sqlite3
import sys
import pyaes
import pbkdf2
import binascii
import os
import secrets
import base64

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
root = Tk()
root.title("ONE-PASS")
width_window = 300
height_window = 300
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = screen_width / 2 - width_window / 2
y = screen_height / 2 - height_window / 2
root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))

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
l = [{"1": "member.png"}]
# global values
catch_error = True
social_media_user_text = ""
social_media_active = False
image_path = ""
exist = False
cutting_value = False
file = 0


class Login:  # login_class
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
            main_password = hashlib.sha3_512(
                for_hashing_both.encode()).hexdigest()
            root_error.withdraw()
            messagebox.showerror("Error", "Password cannot be empty ")
            root_error.destroy()
            return False, main_password, self.password
        else:
            for_hashing_both = self.password + self.username
            main_password = hashlib.sha3_512(
                for_hashing_both.encode()).hexdigest()
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
            print(self.password)
            return True, main_password, self.password


class Profile_view:
    def __init__(
        self, username, password, email_id, email_password, hashed_password, profile
    ):
        self.username = username
        self.password = password
        self.email_id = email_id
        self.email_password = email_password
        self.hashed_password = hashed_password

    def profile_window(self, profile, s):
        profile.config(bg="#292A2D")
        s.title("Profile")
        # decrypting the password
        print(self.password)
        old_text = f"{self.password}"
        new_text = old_text.translate("*" * 256)

        old_text_email = f"{self.email_password}"
        new_text_email = old_text_email.translate("*" * 256)

        # all labels
        username_label = Label(
            profile,
            text="Username:",
            font="Verdana 10",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )
        password_label = Label(
            profile,
            text="Password:",
            font="Verdana 10",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )
        email_id_label = Label(
            profile,
            text="Email:",
            font="Verdana 10",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )
        email_password_label = Label(
            profile,
            text="Email Password:",
            font="Verdana 10",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )

        # details label
        username_label_right = Label(
            profile,
            text=self.username,
            font="Verdana 10",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )

        password_label_right = Label(
            profile,
            text=old_text,
            font="Verdana 10",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
        )

        email_id_label_right = Label(
            profile,
            text=self.email_id,
            font="Verdana 10",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )

        email_password_label_right = Label(
            profile,
            text=new_text_email,
            font="Verdana 10",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )

        # profile image
        profile_text = Label(
            profile,
            text="Add profile photo",
            font="Verdana 10",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )

        def show_pass(label, index, button):
            button.config(text="Hide")
            if index == 1:
                label.config(text=old_text)
            elif index == 2:
                label.config(text=old_text_email)

        def hide_pass(label, index, button):
            button.config(text="Show")
            if index == 1:
                label.config(text=new_text)
            elif index == 2:
                label.config(text=new_text_email)

        my_cursor.execute(
            "select profile_path from data_input where username = (?)", (
                self.username,)
        )
        for i in my_cursor.fetchall():
            if i[0] == "" or not i[0] or i[0] == "0":
                profile_image = tk_image.PhotoImage(image.open("member.png"))

            else:
                profile_text.config(text="")
                a = image.open(i[0])
                profile_image = tk_image.PhotoImage(a)

        show = Button(
            profile,
            text="Show",
            font="Verdana 8",
            fg="white",
            bg="black",
            highlightcolor="black",
            activebackground="black",
            command=lambda: show_pass(password_label_right, 1, show),
        )
        show1 = Button(
            profile,
            text="Show",
            font="Verdana 8",
            command=lambda: show_pass(email_password_label_right, 2, show1),
        )

        profile_photo = Label(profile, image=profile_image)

        delete_object = Deletion(self.username, self.hashed_password, profile)
        delete_this_account = Button(
            profile,
            text="Delete Account",
            command=lambda: delete_object.delete_main_account(),
        )

        username_label.grid(row=0, column=0)
        password_label.grid(row=1, column=0)
        email_id_label.grid(row=2, column=0)
        email_password_label.grid(row=3, column=0)

        username_label_right.grid(row=0, column=1)
        password_label_right.grid(row=1, column=1)
        email_id_label_right.grid(row=2, column=2)
        email_password_label_right.grid(row=3, column=1)

        show.grid(row=1, column=2)
        show1.grid(row=1, column=2)

        username_label.place(x=100, y=100)
        password_label.place(x=100, y=150)
        email_id_label.place(x=100, y=200)
        email_password_label.place(x=100, y=250)

        username_label_right.place(x=200, y=100)
        password_label_right.place(x=200, y=150)
        email_id_label_right.place(x=200, y=200)
        email_password_label_right.place(x=200, y=250)

        show.place(x=200, y=250)
        show1.place(x=200, y=350)


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
        my_cursor.execute("select username from data_input")
        values_username = my_cursor.fetchall()
        for i in values_username:
            for usernames in i:
                if usernames == self.username and os.path.exists(
                    self.username + ".bin.fenc"
                ):
                    return True  # checking whether the username already exists in the database

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
        iv = secrets.randbits(256)
        aes = pyaes.AESModeOfOperationCTR(key)
        encrypted_pass = aes.encrypt(message)

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
        with open(file_name, "wb") as f:
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
        window_after(self.username, hash_pass, self.password)


# for hashing-encryting and decrypting password and for (forgot_password)


class Deletion:
    def __init__(self, real_username, hashed_password, window):
        self.real_username = real_username
        self.hashed_password = hashed_password
        self.window = window

    def delete_social_media_account(self):
        delete_med_account = Tk()
        delete_med_account.config(bg="#292A2D")
        delete_med_account.title("Delete Account")
        n = StringVar()
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
            command=lambda: self.change_account_name(str(selectaccount.get())),
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
        delete.grid(row=1, column=1)
        selectaccount.current()

    def change_account_name(self, account_name):
        result = messagebox.askyesno(
            "Confirm", "Are you sure that you want to delete your account"
        )
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
            x = my_cursor.execute(
                "select no_of_accounts from data_input where username=(?)",
                (self.real_username,),
            )
            new_val = 0
            for i in x:
                new_val = i[0]
            new_val -= 1
            my_cursor.execute(
                f"update data_input set no_of_accounts = (?) where username=(?)",
                (new_val, self.real_username),
            )
            pyAesCrypt.encryptFile(
                f"{self.real_username}decrypted.bin",
                f"{self.real_username}.bin.fenc",
                self.hashed_password,
                bufferSize,
            )
            a = Tk()
            a.withdraw()
            messagebox.showinfo(
                "Success", f"{account_name}  has been  deleted")
            a.destroy()
            with open(f"{self.real_username}decrypted.bin", "rb") as f:
                values = pickle.load(f)
                for i in values:
                    print(i[0])
            add_account_window(self.real_username,
                               self.window, self.hashed_password)
        else:
            a = Tk()
            a.withdraw()
            messagebox.showinfo("Error", "Please try again")
            a.destroy()

    def delete_main_account(self):
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
                    sys.exit()
                    quit()
                except:
                    pass
            else:
                quit()
        else:
            quit()


class Change_details:
    def __init__(self, real_username, hashed_password, window):
        self.real_username = real_username
        self.hashed_password = hashed_password
        self.window = window

    def change_window_creation(self):
        change_acccount = Toplevel()
        change_acccount.config(bg="#292A2D")
        change_acccount.resizable(False, False)
        n = StringVar()
        selectaccount = Combobox(change_acccount, width=27, textvariable=n)
        # Adding combobox drop down list
        tu = ()
        with open(f"{self.real_username}decrypted.bin", "rb") as selectfile:
            try:
                ac = pickle.load(selectfile)
                for i in ac:
                    tu += (i[2],)
            except:
                pass
        print(tu)
        selectaccount["values"] = tu

        selectaccount.grid(column=1, row=5)
        selectaccount.current()
        change_acccount.geometry("300x300")
        main_label = Label(
            change_acccount,
            text="Select the account to be deleted",
            bg="#292A2D",
            fg="white",
        )

        change_acccount.title("Change Account")
        text = (
            "    Please provide the recovery email  and recovery  password \n that you provided while creating an "
            "account "
        )
        text_label = Label(change_acccount, text=text,
                           fg="white", bg="#292A2D")
        width_window = 400
        height_window = 400
        screen_width = change_acccount.winfo_screenwidth()
        screen_height = change_acccount.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        change_acccount.geometry("%dx%d+%d+%d" %
                                 (width_window, height_window, x, y))

        new_username_label = Label(
            change_acccount, text="New Username:", fg="white", bg="#292A2D"
        )
        new_password_label = Label(
            change_acccount, text="New Password:", fg="white", bg="#292A2D"
        )
        new_account_name_label = Label(
            change_acccount, text="New Account Name:", fg="white", bg="#292A2D"
        )

        new_username = Entry(change_acccount)
        new_password = Entry(change_acccount)
        new_account_name = Entry(change_acccount)

        main_label.grid(row=0, column=1)
        text_label.grid(row=0, column=0, columnspan=2)

        new_account_name_label.grid(row=1, column=0)
        new_account_name.grid(row=1, column=1)

        new_username_label.grid(row=2, column=1)
        new_username.grid(row=2, column=0)

        new_password_label.grid(row=3, column=0)
        new_password.grid(row=3, column=1)

        change = Button(
            change_acccount,
            text="Change",
            bg="#292A2D",
            fg="white",
            command=lambda: self.change_sub_account(
                self,
                str(selectaccount.get()),
                str(new_username.get()),
                str(new_password.get()),
                str(new_account_name.get()),
            ),
        )

        change.grid(row=5, column=1)
        main_label.place(x=0, y=40)
        change.place(x=200, y=200)

        new_account_name_label.place(x=50, y=70)
        new_username_label.place(x=50, y=100)
        new_password_label.place(x=50, y=130)

        new_account_name.place(x=200, y=70)
        new_username.place(x=200, y=100)
        new_password.place(x=200, y=130)

        selectaccount.place(x=200, y=40)

    def change_sub_account(
        self, accounttobechanged, new_username, new_password, account_name
    ):
        with open(f"{self.real_username}decrypted.bin", "rb") as f:
            value1 = pickle.load(f)
            print(value1)
            for i in value1:
                if i[2] == str(accounttobechanged):
                    print("hi")
                    i[0] = str(new_username)
                    i[1] = str(new_password)
                    i[2] = str(account_name)
                    p = Tk()
                    p.config(bg="#292A2D")
                    p.withdraw()
                    messagebox.showinfo(
                        "Succes", "The Account details has been changed"
                    )
                    p.destroy()
                    self.window.destroy()
        with open(f"{self.real_username}decrypted.bin", "wb") as f:
            pickle.dump(value1, f)
        os.remove(f"{self.real_username}.bin.fenc")
        pyAesCrypt.encryptFile(
            f"{self.real_username}decrypted.bin",
            f"{self.real_username}.bin.fenc",
            self.hashed_password,
            bufferSize,
        )

    def save_email(
        self, new_email, old_email, recovery_password, new_recovery_password
    ):

        email_split = ""
        word = old_email.split()
        for i in word:
            for a in i:
                if i == "@":
                    break
                else:
                    email_split += i
        val = email_split[::-1]

        main_password = val + "/" + recovery_password  # static salt
        my_cursor.execute(
            "select salt,password from data_input where username =(?)",
            (self.real_username,),
        )
        a = my_cursor.fetchall()
        decrypted_string = ""
        for i in a:
            try:
                string = retreive_key(main_password, i[1], i[0])
            except:
                messagebox.showinfo(
                    "Error", "Some unknown error please try again later"
                )
                break

            for i in string:
                if i == "@":
                    break
                else:
                    decrypted_string += i
        value = decrypted_string + self.real_username
        email_split = ""
        word = new_email.split()
        for i in word:
            for a in i:
                if i == "@":
                    break
                else:
                    email_split += i
        val = email_split[::-1]
        main_password = val + "/" + new_recovery_password
        re_hash = hashlib.sha3_512(value.encode()).hexdigest()
        pyAesCrypt.decryptFile(
            f"{self.real_username}.bin.fenc",
            self.real_username + "decrypted.bin",
            re_hash,
            bufferSize,
        )

        re_hash_text1 = decrypted_string + self.real_username
        new_salt1 = decrypted_string + "@" + main_password
        re_hash_new1 = hashlib.sha3_512(re_hash_text1.encode()).hexdigest()
        re_encrypt, new_salt = create_key(main_password, new_salt1)
        my_cursor.execute(
            "update data_input set password = (?) where username = (?)",
            (re_encrypt, self.real_username),
        )

        # encrypting the new recovery password
        password = new_email + re_hash_new1
        message = new_recovery_password
        passwordSalt = secrets.token_bytes(512)
        key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
        iv = secrets.randbits(256)
        aes = pyaes.AESModeOfOperationCTR(key)
        encrypted_pass = aes.encrypt(message)
        print(encrypted_pass)
        my_cursor.execute(
            "update data_input set recovery_password = (?),,set salt_recovery=(?) where username = (?)",
            (encrypted_pass, passwordSalt, self.real_username),
        )

        os.remove(f"{self.real_username}.bin.fenc")
        my_cursor.execute(
            "update data_input set email_id = (?), set salt_recovery=(?),set salt = (?),set recovery_password = (?) where where username = (?)",
            (
                new_email,
                new_salt_rec,
                new_salt,
                recovery_password_encrypt,
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
            "Success", "Your email and password has been changed")
        ad.destroy()
        self.window.destroy()

    def change_email(self):
        my_cursor.execute(
            "select recovery_password,email_id,recovery_salt from data_input where username = (?)",
            (self.real_username,),
        )
        recovery_password_a = my_cursor.fetchall()
        print(recovery_password_a)
        for i in recovery_password_a:
            print(i[0])
            password = i[1] + self.hashed_password
            recovery_password = retreive_key(password, i[0], i[2])
            print(recovery_password)
            new_window = Toplevel()

            new_email_entry = Entry(new_window)

            new_recovery_password_entry = Entry(new_window)

            save = Button(
                new_window,
                text="Save",
                command=lambda: self.save_email(
                    str(new_email_entry.get()),
                    i[1],
                    recovery_password,
                    str(new_recovery_password_entry.get()),
                ),
            )

            new_img = tk_image.PhotoImage(image.open("user.png"))
            new_img_label = Label(new_window, image=new_img, bg="#292A2D")
            new_img_label.photo = new_img

            file_name_reentry = self.real_username + ".bin.fenc"

            width_window = 400
            height_window = 200
            screen_width = new_window.winfo_screenwidth()
            screen_height = new_window.winfo_screenheight()
            x = screen_width / 2 - width_window / 2
            y = screen_height / 2 - height_window / 2
            new_window.geometry("%dx%d+%d+%d" %
                                (width_window, height_window, x, y))
            new_window.title("Change Recovery details")
            new_window.geometry("300x300")
            new_window.config(bg="#292A2D")

            new_email = Label(new_window, text="New Email",
                              fg="white", bg="#292A2D")
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
            save.grid(row=3, column=0)

            new_img_label.place(x=110, y=50)
            new_email.place(x=10, y=70 + 50)
            new_email_password.place(x=10, y=100 + 50)
            new_email_entry.place(x=150 - 40, y=70 + 50)
            new_email_password_entry.place(x=150 - 40, y=100 + 50)
            save.place(x=150 - 40, y=200)

            new_email_password_entry.config(show="")

            new_email_password_entry.config(fg="grey")
            new_email_password_entry.insert(0, "New Email password")

            new_email_entry.config(fg="grey")
            new_email_entry.insert(0, "New Email")

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
            show_both_12 = Button(
                new_window,
                text="show",
                command=lambda: password_sec(
                    new_email_password_entry, show_both_12),
                fg="white",
                bg="#292A2D",
                highlightcolor="#292A2D",
                activebackground="#292A2D",
                activeforeground="white",
                relief=RAISED,
            )
            show_both_12.grid(row=0, column=5)
            show_both_12.place(x=250 - 15, y=100 + 50 - 5)


def create_key(password, message):
    password_key = password.encode()  # convert string to bytes
    salt = os.urandom(64)  # create a random 64 bit byte
    # PBKDF2 HMAC- it is a type of encryption-Password-Based Key Derivation Function 2,HMAC-hashed message
    # authentication code
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_512(),
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


def retreive_key(password, byte, de):
    password_key = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_512(),
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


def settings(real_username, hashed_password, window):
    settings_window = Tk()
    settings_window.resizable(False, False)

    width_window = 150
    height_window = 130
    screen_width = settings_window.winfo_screenwidth()
    screen_height = settings_window.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2

    settings_window.geometry("%dx%d+%d+%d" %
                             (width_window, height_window, x, y))

    settings_window.title("Settings")
    settings_window.config(bg="#292A2D")

    delete_object = Deletion(real_username, hashed_password, window)
    change_object = Change_details(real_username, hashed_password, window)

    check_for_updates = Button(
        settings_window,
        text="Check for updates",
        command=checkforupdates,
        fg="white",
        bg="#292A2D",
        width=20,
    )
    Delete_account_button = Button(
        settings_window,
        text="Delete main account",
        width=20,
        command=lambda: delete_object.delete_main_account(),
        fg="white",
        bg="#292A2D",
    )
    Delete_social_button = Button(
        settings_window,
        text="Delete sub  account",
        width=20,
        command=lambda: delete_object.delete_social_media_account(),
        fg="white",
        bg="#292A2D",
    )
    change_account_button = Button(
        settings_window,
        text="Change account",
        width=20,
        command=lambda: change_object.change_window_creation(),
        fg="white",
        bg="#292A2D",
    )
    change_email_button = Button(
        settings_window,
        text="Change recovery email",
        command=lambda: change_object.change_email(),
        fg="white",
        bg="#292A2D",
        width=20,
    )

    Delete_account_button.grid(row=1, column=1, columnspan=2)
    check_for_updates.grid(row=2, column=1, columnspan=2)
    Delete_social_button.grid(row=3, column=1, columnspan=2)
    change_account_button.grid(row=4, column=1, columnspan=2)
    change_email_button.grid(row=5, column=1, columnspan=2)
    if os.stat(f"{real_username}decrypted.bin").st_size == 0:
        Delete_social_button.config(state=DISABLED)
    else:
        Delete_social_button.config(state=NORMAL)
    settings_window.mainloop()


# forgot password function


def login_password():
    window = Tk()
    window.config(bg="#292A2D")
    window.resizable(False, False)

    window.title("Forgot Password")
    text = (
        "Please provide the recovery email  and recovery email password \n that you provided while creating an "
        "account "
    )
    text_label = Label(window, text=text, fg="white", bg="#292A2D")
    width_window = 400
    height_window = 400
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

    text_label.grid(row=0, column=0, columnspan=2)
    recover_email.grid(row=2, column=0)
    recover_password.grid(row=3, column=0)
    recover_email_entry.grid(row=2, column=1)
    recover_password_entry.grid(row=3, column=1)
    username_forgot_entry.grid(row=1, column=1)
    username_forgot.grid(row=1, column=0)

    username_forgot.place(x=50, y=70)
    recover_password.place(x=50, y=100)
    recover_email.place(x=50, y=130)
    username_forgot_entry.place(x=200, y=70)
    recover_password_entry.place(x=200, y=100)
    recover_email_entry.place(x=200, y=130)

    key = ""
    l = "abcdefghijklmnopqrstuvwxyz"
    for i in range(7):
        key += random.choice(l)

    running = False

    def generate_key1(file):
        pyAesCrypt.encryptFile(file, "otp.bin.fenc", key, bufferSize)
        os.unlink(file)
        messagebox.showinfo(
            "OTP", f"An OTP has been sent to  {str(recover_email_entry.get())}"
        )

    def change_password(email, password1, username12):
        root = Toplevel()
        new_img = tk_image.PhotoImage(image.open("user.png"))
        new_img_label = Label(root, image=new_img, bg="#292A2D")
        new_img_label.photo = new_img
        root.resizable(False, False)

        file_name_reentry = username12 + ".bin.fenc"

        width_window = 400
        height_window = 200
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        root.title("Change Password")
        root.geometry("300x300")
        root.config(bg="#292A2D")

        new_username = Label(root, text="New Username",
                             fg="white", bg="#292A2D")
        new_password = Label(root, text="New Password",
                             fg="white", bg="#292A2D")

        new_username_entry = Entry(root)
        new_password_entry = Entry(root, show="*")

        new_img_label.grid(row=0, column=1)
        new_username.grid(row=1, column=0)
        new_password.grid(row=2, column=0)
        new_username_entry.grid(row=1, column=1)
        new_password_entry.grid(row=2, column=1)

        new_img_label.place(x=110, y=50)
        new_username.place(x=10, y=70 + 50)
        new_password.place(x=10, y=100 + 50)
        new_username_entry.place(x=150 - 40, y=70 + 50)
        new_password_entry.place(x=150 - 40, y=100 + 50)

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
        show_both_12 = Button(
            root,
            text="show",
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
        my_cursor.execute(
            "select password,salt from data_input where email_id = (?)", (
                email,)
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
        try:
            string = retreive_key(main_pass, has, salt)
            for i in string:
                if i == "@":
                    break
                else:
                    decrypted_string += i
            value = decrypted_string + username12

            re_hash = hashlib.sha3_512(value.encode()).hexdigest()

            def change():
                pyAesCrypt.decryptFile(
                    file_name_reentry,
                    username12 + "decrypted.bin",
                    re_hash,
                    bufferSize,
                )

                re_hash_text = str(new_password_entry.get()) + str(
                    new_username_entry.get()
                )
                new_salt = str(new_password_entry.get()) + "@" + main_pass
                re_hash_new = hashlib.sha3_512(
                    re_hash_text.encode()).hexdigest()
                re_encrypt, new_salt = create_key(main_pass, new_salt)
                pyAesCrypt.encryptFile(
                    username12 + "decrypted.bin",
                    str(new_username_entry.get()) + ".bin.fenc",
                    re_hash_new,
                    bufferSize,
                )

                my_cursor.execute(
                    "update data_input set username = (?) where username = (?)",
                    (str(new_username_entry.get()), username12),
                )
                my_cursor.execute(
                    "update data_input set password = (?) where username = (?)",
                    (re_encrypt, username12),
                )

        except:
            p = Tk()
            p.withdraw()
            messagebox.showinfo("Error", "Wrong recovery password")
            p.destroy()

        change_button = Button(root, text="Change", command=change)
        change_button.grid(row=3, column=0, columnspan=1)
        change_button.place(x=130, y=100 + 100)

    def Verification(password, otp_entry, email, email_password, username12):
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
                    messagebox.showinfo(
                        "Error", "Incorrect OTP Please verify it again")
                    otp_entry.delete(0, END)
        else:
            messagebox.showinfo(
                "Error", "Please provide the OTP  send to your email")

    def forgot_password(OTP, email, username):
        try:
            global running
            running = True
            SUBJECT = "EMAIL verification for ONE-PASS-MANAGER"
            otp = f"Hey {username}! Your OTP for your ONE-PASS manager is {OTP}.Please use this to verify your email"
            msg = "Subject: {}\n\n{}".format(SUBJECT, otp)
            s = smtplib.SMTP("smtp.gmail.com", 587)
            s.starttls()
            s.login("rohithk6474@gmail.com", "Kedaram@123")
            s.sendmail("rohithk6474@gmail.com", email, msg)

        except:
            messagebox.showinfo(
                "Error", "Please Connect to the internet \n then retry")
            sys.exit()

    def main(key):
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
            a = Tk()
            a.withdraw()
            messagebox.showwarning("Warning", f"Username cannot be blank")
            a.destroy()

        elif recover_password_entry_verify == "Password":
            a = Tk()
            a.withdraw()
            messagebox.showwarning("Warning", f"Password cannot be blank")
            a.destroy()
        elif not os.path.exists(username_verify + ".bin.fenc"):
            a = Tk()
            a.withdraw()
            messagebox.showwarning(
                "Warning", f"Cannot find user {username_verify}")
            a.destroy()

        else:
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
            try:
                for i in values_fetch:

                    if i[0] == recover_email_entry_verify:
                        run = True
                    else:
                        run = False
                        roo1 = Tk()
                        roo1.withdraw()
                        messagebox.showerror("Error", "Wrong Recovey email")
                        roo1.destroy()
            except:
                pass

            if run:
                otp_entry = Entry(window)
                otp_entry.grid(row=6, column=1)
                otp_entry_button = Button(
                    window,
                    text="verify otp",
                    command=lambda: Verification(
                        key,
                        otp_entry.get(),
                        recover_email_entry_verify,
                        recover_password_entry_verify,
                        username_verify,
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
                generate_key1("otp.bin")
                forgot_password(
                    OTP, recover_email_entry_verify, username_verify)

    forgot_password_button = Button(
        window, text="verify", command=lambda: main(key), bg="#292A2D", fg="white"
    )
    forgot_password_button.grid(row=5, column=1)
    forgot_password_button.place(x=250, y=170)
    show_both_1 = Button(
        window,
        text="Show",
        command=lambda: password_sec(recover_password_entry, show_both_1),
        fg="white",
        bg="#292A2D",
        highlightcolor="#292A2D",
        activebackground="#292A2D",
        activeforeground="white",
        relief=RAISED,
    )

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


def add_account_window(username, window, hashed_password):
    d = window.winfo_children()
    no_accounts = 0
    try:
        for i in d:
            i.destroy()
    except:
        print("e")
    try:
        with open(username + "decrypted.bin", "rb") as f:
            account_fetch = pickle.load(f)
            no_accounts = len(account_fetch)
    except:
        account_fetch = []
        no_accounts = 0
    no_of_accounts = 0
    try:
        while no_of_accounts < 12:
            social_username = account_fetch[no_of_accounts][0]
            social_password = account_fetch[no_of_accounts][1]
            social_media = account_fetch[no_of_accounts][2]
            image_path_loc = account_fetch[no_of_accounts][3]
            username_label_widget = Label(
                window, text=f"Username: {social_username}", fg="white", bg="#292A2D"
            )
            password_label_widget = Label(
                window, text=f"Password: {social_password}", fg="white", bg="#292A2D"
            )
            social_media_label = Label(
                window, text=f"Account Name: {social_media}", fg="white", bg="#292A2D"
            )
            if image_path_loc:
                file = image.open(image_path_loc)
                # noinspection PyBroadException
                tkimage = tk_image.PhotoImage(file)

            else:
                tkimage = tk_image.PhotoImage(image.open("photo.png"))

            default_image_button = Button(
                window,
                image=tkimage,
                borderwidth="0",
                bg="#292A2D",
                command=lambda: change_icon(
                    default_image_button,
                    social_username,
                    username,
                    hashed_password,
                    window,
                ),
            )
            if no_of_accounts < 3:
                username_label_widget.grid(
                    row=2, column=0 + no_of_accounts, rowspan=1)
                password_label_widget.grid(
                    row=3, column=0 + no_of_accounts, rowspan=1)
                social_media_label.grid(
                    row=1, column=0 + no_of_accounts, rowspan=1)
                default_image_button.photo = tkimage
                default_image_button.grid(
                    row=0, column=0 + no_of_accounts, rowspan=1)
                default_image_button.place(x=40 + no_of_accounts * 250, y=10)
                username_label_widget.place(x=30 + no_of_accounts * 250, y=110)
                social_media_label.place(x=30 + no_of_accounts * 250, y=90)
                password_label_widget.place(x=30 + no_of_accounts * 250, y=130)

            elif 3 <= no_of_accounts < 6:
                dd = int(no_of_accounts % 3)
                username_label_widget.grid(row=2 + 1, column=0 + dd)
                password_label_widget.grid(row=3 + 1, column=0 + dd)
                social_media_label.grid(row=1 + 1, column=0 + dd)
                default_image_button.photo = tkimage
                default_image_button.grid(row=0 + 1, column=0 + dd)
                default_image_button.place(x=40 + dd * 250, y=170)
                username_label_widget.place(x=30 + dd * 250, y=250)
                social_media_label.place(x=30 + dd * 250, y=230)
                password_label_widget.place(x=30 + dd * 250, y=270)
            elif 6 <= no_of_accounts < 9:
                dd = int(no_of_accounts % 6)
                username_label_widget.grid(row=2 + 1, column=0 + dd)
                password_label_widget.grid(row=3 + 1, column=0 + dd)
                social_media_label.grid(row=1 + 1, column=0 + dd)
                default_image_button.photo = tkimage
                default_image_button.grid(row=0 + 1, column=0 + dd)
                default_image_button.place(x=40 + dd * 250, y=300)
                social_media_label.place(x=30 + dd * 250, y=380)
                username_label_widget.place(x=30 + dd * 250, y=400)
                password_label_widget.place(x=30 + dd * 250, y=420)
            no_of_accounts = no_of_accounts + 1
    except:
        pass

    image_add = tk_image.PhotoImage(image.open("add-button.png"))
    add_button_text = Label(
        window, fg="white", text="Add Account", bg="#292A2D")
    add_button = Button(
        window,
        image=image_add,
        bg="#292A2D",
        activebackground="#292A2D",
        border="0",
        compound="top",
        command=lambda: addaccount(username, hashed_password, window),
    )
    add_button.photo = image_add
    d = int(no_accounts % 4)
    add_button.grid(row=10, column=10)
    add_button_text.grid(row=11, column=10)

    add_button.place(x=719 + 50, y=410)
    add_button_text.place(x=710 + 50, y=480)
    if no_accounts >= 9:
        add_button.config(state=DISABLED)


def window_after(username, hash_password, password_new):
    # sidebar
    root = Tk()
    root.resizable(False, False)

    root.focus_set()
    global var
    global file
    status_name = False
    sidebar = Frame(
        root, width=10, bg="#292A2D", height=500, relief="sunken", borderwidth=1
    )
    sidebar.pack(expand=False, fill="both", side="left")
    file = None
    root.title("ONE-PASS")
    width_window = 1000
    height_window = 500
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2

    root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))

    def testing(root, mainarea, username, hash_password):
        button["state"] = DISABLED
        notes_buttons["state"] = NORMAL
        root.title("Passwords")
        emptyMenu = Menu(root)
        root.geometry("1000x500")
        mainarea.config(bg="#292A2D")
        root.config(menu=emptyMenu)

        list = mainarea.pack_slaves()
        for l in list:
            l.destroy()
        gameloop(username, hash_password, mainarea)

    def note_pad_sec():
        global status_name
        global password
        global var
        notes_buttons["state"] = DISABLED
        button["state"] = NORMAL
        try:
            list = mainarea.pack_slaves()
            for i in list:
                i.forget()
        except:
            pass
        if __name__ == "__main__":
            emptyMenu = Menu(root)
            root.config(menu=emptyMenu)

            list = mainarea.grid_slaves()
            for l in list:
                l.destroy()

            def newFile():
                global password
                root.title("Untitled - Notepad")
                TextArea.delete(1.0, END)

            def openFile():
                global password
                global file
                file = fd.askopenfilename(
                    defaultextension=".txt",
                    filetypes=[("All Files", "*.*"),
                               ("Text Documents", "*.txt")],
                )
                if file != None:
                    if file.endswith(".bin.fenc"):
                        password = str(
                            simpledialog.askstring(
                                title="Password Required",
                                prompt="Please provide the password",
                            )
                        )
                        if password == "":
                            messagebox.showerror(
                                "Error", "Password cannot be empty")
                        else:
                            new_file = os.path.splitext(file)[0]
                            b = os.path.basename(new_file)
                            new_d = os.path.basename(b)
                            filename = new_d + "decrypted.txt"
                            try:
                                pyAesCrypt.decryptFile(
                                    file, filename, password, bufferSize
                                )
                                root.title(os.path.basename(
                                    file) + " - Notepad")
                                TextArea.delete(1.0, END)
                                with open(filename, "r") as f:
                                    TextArea.insert(1.0, f.read())
                                    f.close()
                            except:
                                messagebox.showerror("Error", "Wrong password")

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
                        b = os.path.basename(new_file)
                        new_d = os.path.basename(b)
                        new_file_name = os.path.basename(b)
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
                global password
                global file
                if file == None:
                    result = messagebox.askyesno(
                        "Confirm", "Do you want to encrypt your file?"
                    )
                    if not result:
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
                    else:
                        application_window = Tk()
                        a = simpledialog.askstring(
                            "Input",
                            "What is  the password for the file?",
                            parent=application_window,
                        )
                        if a == "":
                            messagebox.showerror(
                                "Error", "Password cannot be empty")
                        else:
                            application_window.destroy()
                            file = fd.asksaveasfilename(
                                initialfile="Untitled.txt",
                                defaultextension=".txt",
                                filetypes=[("Text Documents", "*.txt")],
                            )
                            gmm = str(file)
                            password = "testing"
                            status_name = file
                            if file == "":
                                file = None

                            else:
                                # Save as a new file
                                with open(file, "w") as f:
                                    f.write(TextArea.get(1.0, END))
                                    f.close()
                                root.title(os.path.basename(
                                    file) + " - Notepad")
                                file = file
                            file_name = str(file)
                            f_encrypt = file_name + ".aes"
                            try:
                                pyAesCrypt.encryptFile(
                                    file_name, f_encrypt, a, 64 * 1024
                                )
                                os.remove(file)
                            except:
                                pass

            def save_file():
                global status_name
                if status_name:
                    with open(status_name, "w") as f:
                        f.write(TextArea.get(1.0, END))
                        f.close()
                else:
                    result = messagebox.askyesno(
                        "Confirm", "Do you want to encrypt your file?"
                    )
                    if result == False:
                        file = fd.asksaveasfilename(
                            initialfile="Untitled.txt",
                            defaultextension=".txt",
                            filetypes=[
                                ("All Files", "*.*"),
                                ("Text Documents", "*.txt"),
                            ],
                        )
                        gmm = str(file)
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
                    else:
                        file = fd.asksaveasfilename(
                            initialfile="Untitled.txt",
                            defaultextension=".txt",
                            filetypes=[
                                ("All Files", "*.*"),
                                ("Text Documents", "*.txt"),
                            ],
                        )
                        gmm = str(file)
                        password = str(
                            simpledialog.askstring(
                                title="Password", prompt="Please provide the password"
                            )
                        )
                        status_name = file
                        if file == "":
                            file = None

                        else:
                            # Save as a new file
                            with open(file, "w") as f:
                                f.write(TextArea.get(1.0, END))
                                f.close()
                            root.title(os.path.basename(file) + " - Notepad")
                            file = file
                        file_name = str(file)
                        try:
                            pyAesCrypt.encryptFile(
                                file_name, file_name + ".aes", password, 64 * 1024
                            )
                            os.remove(file)
                        except:
                            pass

            def quitApp():
                root.destroy()

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
            root.geometry("1000x500")
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
            MenuBar.config(bg="#292A2D", bd="0", activebackground="#292A2D")
            status_name = False
            root.config(bg="red", menu=MenuBar)
            # File Menu Starts

            FileMenu = Menu(MenuBar, tearoff=0)
            FileMenu.config(bg="#292A2D", bd="0", activebackground="#292A2D")

            # To open new file
            FileMenu.add_command(
                label="New",
                command=newFile,
                foreground="white",
                activebackground="#4B4C4F",
            )

            FileMenu.add_command(
                label="Open",
                command=openFile,
                foreground="white",
                activebackground="#4B4C4F",
            )
            # To save the current file
            FileMenu.add_command(
                label="Save",
                command=lambda: save_file(),
                foreground="white",
                activebackground="#4B4C4F",
            )
            FileMenu.add_command(
                label="Save As",
                command=lambda: save_as_File(),
                foreground="white",
                activebackground="#4B4C4F",
            )
            FileMenu.add_command(
                label="Rename",
                command=lambda: rename_file(),
                foreground="white",
                activebackground="#4B4C4F",
            )
            FileMenu.add_command(
                label="Exit",
                command=quitApp,
                foreground="white",
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

            try:
                f = TextArea.get()
                if f != "":
                    root.title("*untitled-Notepad")
                else:
                    pass
            except:
                root.title("Untitled-Notepad")
            root.bind("<Control-Key-f>", primary)
            root.bind("<Control-Key-h>", secondary)

            EditMenu = Menu(MenuBar, tearoff=0)
            EditMenu.config(bg="#292A2D", bd="0", activebackground="#292A2D")

            my_menu = Menu(mainarea, tearoff=0)
            my_menu.config(bg="#292A2D", bd="0", activebackground="#292A2D")
            my_menu.add_command(
                label="Highlight",
                command=highlight_text,
                foreground="white",
                activebackground="#4B4C4F",
            )
            my_menu.add_command(
                label="Copy",
                command=copy,
                foreground="white",
                activebackground="#4B4C4F",
            )
            my_menu.add_command(
                label="Cut", command=cut, foreground="white", activebackground="#4B4C4F"
            )
            my_menu.add_command(
                label="Paste",
                command=paste,
                foreground="white",
                activebackground="#4B4C4F",
            )
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
            submenu_size.config(bg="#292A2D", bd="0",
                                activebackground="#292A2D")

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
    pass_img = tk_image.PhotoImage(image.open("password.png"))
    notes_img = tk_image.PhotoImage(image.open("notes.png"))
    mainarea = Frame(root, bg="#292A2D", width=500, height=500)
    mainarea.pack(expand=True, fill="both", side="right")

    button = Button(
        sidebar,
        image=pass_img,
        text="Passwords",
        padx=14,
        compound="left",
        fg="white",
        bg="black",
        command=lambda: testing(root, mainarea, username, hash_password),
    )

    # profile sidebar functions and objects

    # fetching the email from database
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
    for i in my_cursor.fetchall():
        password = email_id + hash_password
        key = pbkdf2.PBKDF2(password, i[1]).read(32)
        aes = pyaes.AESModeOfOperationCTR(key)
        encrypted_pass = (aes.decrypt(i[0])).decode()
    print(password_new)
    profile_object = Profile_view(
        username, password_new, email_id, encrypted_pass, hash_password, mainarea
    )

    profile_button = Button(
        sidebar,
        text="Profile",
        command=lambda: profile_object.profile_window(mainarea, root),
        padx=35,
        fg="white",
        bg="black",
    )
    notes_buttons = Button(
        sidebar,
        image=notes_img,
        text="Notes",
        padx=20,
        compound="left",
        command=note_pad_sec,
        fg="white",
        bg="black",
    )

    button.grid(row=0, column=1)
    notes_buttons.grid(row=1, column=1)
    profile_button.grid(row=2, column=1)
    # profile_button.grid(row=2,column=1)
    settings_image = tk_image.PhotoImage(image.open("settings.png"))
    settings_button = Button(
        sidebar,
        activebackground="#292A2D",
        image=settings_image,
        fg="white",
        bg="#292A2D",
        border="0",
        command=lambda: settings(username, hash_password, mainarea),
        relief=FLAT,
        highlightthickness=0,
        activeforeground="white",
        bd=0,
        borderwidth=0,
    )
    settings_button.photo = settings_image
    settings_button.grid(row=10, column=1, columnspan=1)
    settings_button.place(x=30 + 50, y=440 + 20)

    root.mainloop()


def change_icon(button, usernam, users_username, hashed_password, window):
    file_name = users_username + "decrypted.bin"
    l = [(32, 32), (16, 16)]
    image_path = fd.askopenfilename(
        filetypes=[("image", "*.png"), ("image", "*.jpeg"),
                   ("image", "*.jpg")],
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
        path_im = image.open("photo.png")
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
                im = im.resize((100, 100))
                new_tk = tk_image.PhotoImage(im)
                button.config(image=new_tk)
                button.photo = new_tk
                add_account_window(users_username, window, hashed_password)
            else:
                messagebox.showerror(
                    "Error", "Please provide icon size of 32x32 or 16x16 "
                )
                im = image.open("photo.png")
                new_tk = tk_image.PhotoImage(im)
                button.config(image=new_tk)
                button.photo = new_tk
                image_path = fd.askopenfilename(
                    filetypes=[("image", "*.png")], title="Add icon"
                )

                try:
                    im = image.open(image_path)
                except:
                    im = image.open("photo.png")
                    new_tk = tk_image.PhotoImage(im)
                    button.config(image=new_tk)
                    button.photo = new_tk

    except:
        path_im = path_im.resize((100, 100))
        new_tk = tk_image.PhotoImage(path_im)
        button.config(image=new_tk)
        button.photo = new_tk


def addaccount(username, hashed_password, window):
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
    name_of_social = Label(
        root1, text="Name of the account", fg="white", bg="#292A2D")
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
            image_path = "photo.png"
            im = image.open(image_path)
            tkimage = tk_image.PhotoImage(im)
            add_icon_button.config(image=tkimage)
            add_icon_button.photo = tkimage

    new_id = tk_image.PhotoImage(image.open("photo.png"))
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
            a = Tk()
            a.withdraw()
            messagebox.showwarning("Warning", "Username cannot be empty")
            a.destroy()
        elif str(password_entry.get()) == "":
            a = Tk()
            a.withdraw()
            messagebox.showwarning("Warning", "Password cannot be empty")
            a.destroy()
        elif str(name_of_social_entry.get()) == "":
            a = Tk()
            a.withdraw()
            messagebox.showwarning(
                "Warning", "Name of the account cannot be empty")
            a.destroy()
        else:
            verifying = verify(
                username_window_entry.get(), name_of_social_entry.get(), username
            )

            if verifying:
                a = Toplevel()
                a.withdraw()
                messagebox.showerror("Error", "The account already exists")
                a.destroy()
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
                my_cursor.execute(
                    "select no_of_accounts from data_input where username = (?)",
                    (username,),
                )
                val = my_cursor.fetchall()
                real_accounts = 0
                for i in val:
                    real_accounts = int(i[0])
                real_accounts += +1
                my_cursor.execute(
                    "update data_input set no_of_accounts =(?) where username =(?)",
                    (real_accounts, username),
                )
                add_account_window(username, window, hashed_password)

    save_button = Button(root1, text="Save", command=save,
                         fg="white", bg="#292A2D")
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
                if user[0] == str(social_username) or user[2] == str(social_media):
                    return True
        except:
            return False


# noinspection PyTypeChecker


def gameloop(username, hashed_password, window):
    global image_path
    window.grid_propagate(0)

    exist = False
    add_account_window(username, window, hashed_password)


def get(window, name):
    global l
    for i in l:
        for a in i:
            if a == name:
                d = tk_image.PhotoImage(image.open(i[a]), master=window)
                return d


def handle_focus_in(entry, index):
    val = str(entry.get())
    if val == "Username" or val == "Email ID" or val == "New Email":
        entry.delete(0, END)
        entry.config(fg="#292A2D")
    if val == "Password" or val == "Email password" or val == "New Email password":
        entry.delete(0, END)
        entry.config(fg="#292A2D")
        entry.config(show="*")
    elif (
        index == 2
        and val == "Password"
        or index == 4
        and val == "Email password"
        or index == 2
        and val == "New Email password"
    ):
        entry.config(fg="#292A2D")
        state_entry = entry["show"]
        entry.config(show=state_entry)


def handle_focus_out(entry, val, index):
    a = entry.get()
    if a == "" and index == 2 or a == "" and index == 4:
        entry.delete(0, END)
        entry.config(fg="grey")
        entry.config(show="")
        entry.insert(0, val)
    elif a == "":
        entry.delete(0, END)
        entry.config(fg="grey")
        entry.insert(0, val)


def password_sec(entry, button):
    a = entry["show"]
    val = str(entry.get())
    if val == "Password" or val == "Email Password":
        entry.config(show="")

    else:
        if a == "*":
            entry.config(show="")

            button["text"] = "Hide"
        if a == "":
            entry.config(show="*")

            button["text"] = "Show"


def login(window):
    login_window = Tk()
    try:
        window.destroy()
    except:
        pass
    login_window.resizable(False, False)
    login_window.title("Login")
    width_window = 400
    height_window = 400
    login_window.focus_set()
    login_window.config(bg="#292A2D")
    screen_width = login_window.winfo_screenwidth()
    screen_height = login_window.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2
    login_window.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
    input_entry = Entry(login_window)
    pass_entry = Entry(login_window, show="*")

    forgot = Button(
        login_window,
        text="Forgot Password?",
        command=login_password,
        border="0",
        fg="white",
        bg="#292A2D",
        highlightcolor="#292A2D",
        activebackground="#292A2D",
        activeforeground="white",
        relief=RAISED,
        font="Verdana 8",
    )
    register_button = Button(
        login_window,
        text="Register",
        command=lambda: register(window, login_window),
        fg="white",
        bg="#292A2D",
        border="0",
        highlightcolor="#292A2D",
        activebackground="#292A2D",
        activeforeground="white",
        relief=RAISED,
        font="Verdana 8",
    )

    mod_label = Label(
        login_window, text="|", relief=SUNKEN, fg="white", bg="#292A2D", border="0"
    )

    def password_sec(entry, show_both_1):
        val = entry.get()
        if val != "Password":
            a = entry["show"]
            if a == "":
                entry.config(show="*")
                show_both_1["text"] = "Show"
            elif a == "*":
                entry.config(show="")
                show_both_1["text"] = "Hide"

    show_both_1 = Button(
        login_window,
        text="Show",
        command=lambda: password_sec(pass_entry, show_both_1),
        fg="white",
        bg="#292A2D",
        highlightcolor="#292A2D",
        activebackground="#292A2D",
        activeforeground="white",
        relief=RAISED,
        font="Verdana 8",
    )

    def login_checking_1(*event):
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
                root = Tk()
                root.withdraw()
                messagebox.showinfo("Success", "You have now logged in ")
                root.destroy()
                login_window.destroy()
                window_after(username, main_password, passw)
            else:
                pass

    but = Button(
        login_window,
        text="Login",
        command=login_checking_1,
        bg="black",
        fg="white",
        font="Verdana 8",
    )

    va = get(login_window, "1")
    my_label = Label(login_window, image=va, bg="#292A2D")
    but.grid(row=7, column=3)
    my_label.photo = va
    login_window.bind("<Return>", login_checking_1)
    input_entry.grid(row=2, column=3, ipady=40)
    pass_entry.grid(row=6, column=3)
    login_window.resizable(False, False)
    register_button.grid(row=7, column=4)
    forgot.grid(row=7, column=2)
    show_both_1.grid(row=6, column=4)

    input_entry.insert(0, "Username")
    input_entry.config(fg="grey")
    pass_entry.insert(0, "Password")
    pass_entry.config(fg="grey")
    pass_entry.config(show="")

    input_entry.place(x=100, y=200 - 50, height=30, width=200)
    pass_entry.place(x=100, y=230 - 50, height=30, width=200)

    show_both_1.place(x=300, y=230 - 44)
    register_button.place(x=220 + 10, y=270)

    but.place(x=100 + 80, y=220)

    forgot.place(x=100 + 10, y=270)
    mod_label.place(x=210 + 11, y=270)
    my_label.grid(row=0, column=2)
    my_label.place(x=135, y=10)

    def on_enter(event, button):

        button.configure(font="Verdana 8 underline")

    def on_leave(enter, button):
        button.configure(font="Verdana 8 normal")

    forgot.bind("<Enter>", lambda event, b="<Enter>", a=forgot: on_enter(b, a))
    forgot.bind("<Leave>", lambda event, c="<Enter>", a=forgot: on_leave(c, a))

    register_button.bind(
        "<Enter>", lambda event, b="<Enter>", a=register_button: on_enter(b, a)
    )
    register_button.bind(
        "<Leave>", lambda event, c="<Enter>", a=register_button: on_leave(c, a)
    )

    input_entry.bind(
        "<FocusIn>",
        lambda event, val_val=input_entry, index=1: handle_focus_in(
            val_val, index),
    )
    input_entry.bind(
        "<FocusOut>",
        lambda event, val_val=input_entry, val="Username", index=1: handle_focus_out(
            val_val, val, index
        ),
    )

    pass_entry.bind(
        "<FocusIn>",
        lambda event, val_val=pass_entry, index=2: handle_focus_in(
            val_val, index),
    )
    pass_entry.bind(
        "<FocusOut>",
        lambda event, val_val=pass_entry, val="Password", index=2: handle_focus_out(
            val_val, val, index
        ),
    )


def register(window, *a):
    login_window1 = Tk()
    login_window1.resizable(False, False)

    login_window1.config(bg="#292A2D")
    login_window1.focus_set()
    login_window1.grab_set()
    try:
        for i in a:
            i.destroy()
        window.destroy()

    except:
        pass
    login_window1.resizable(False, False)
    login_window1.title("Register")
    width_window = 400
    height_window = 400
    screen_width = login_window1.winfo_screenwidth()
    screen_height = login_window1.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2

    login_window1.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
    username = Label(
        login_window1,
        text="Username:",
        fg="white",
        bg="#292A2D",
        highlightcolor="#292A2D",
        activebackground="#292A2D",
    )
    password = Label(
        login_window1,
        text="password:",
        fg="white",
        bg="#292A2D",
        highlightcolor="#292A2D",
        activebackground="#292A2D",
    )
    email_id = Label(
        login_window1,
        text="Recovery Email :",
        fg="white",
        bg="#292A2D",
        highlightcolor="#292A2D",
        activebackground="#292A2D",
    )
    email_password = Label(
        login_window1,
        text="Recovery Email password",
        fg="white",
        bg="#292A2D",
        highlightcolor="#292A2D",
        activebackground="#292A2D",
    )
    username_entry = Entry(login_window1)
    password_entry = Entry(login_window1, show="*")
    email_id_entry = Entry(login_window1)
    email_password_entry = Entry(login_window1, show="*")
    width = login_window1.winfo_screenwidth()

    len1 = len(username["text"])
    len2 = len(password["text"])
    len3 = len(email_id["text"])
    len4 = len(email_password["text"])
    # putting the buttons and entries

    username_entry.insert(0, "Username")
    username_entry.config(fg="grey")
    password_entry.insert(0, "Password")
    password_entry.config(fg="grey")
    password_entry.config(show="")
    email_password_entry.config(show="")

    email_id_entry.config(fg="grey")
    email_id_entry.insert(0, "Email ID")
    email_password_entry.config(fg="grey")
    email_password_entry.insert(0, "Email password")
    username_entry.bind(
        "<FocusIn>",
        lambda event, val_val=username_entry, index=1: handle_focus_in(
            val_val, index),
    )
    username_entry.bind(
        "<FocusOut>",
        lambda event, val_val=username_entry, val="Username", index=1: handle_focus_out(
            val_val, val, index
        ),
    )

    password_entry.bind(
        "<FocusIn>",
        lambda event, val_val=password_entry, index=2: handle_focus_in(
            val_val, index),
    )
    password_entry.bind(
        "<FocusOut>",
        lambda event, val_val=password_entry, val="Password", index=2: handle_focus_out(
            val_val, val, index
        ),
    )

    email_id_entry.bind(
        "<FocusIn>",
        lambda event, val_val=email_id_entry, index=3: handle_focus_in(
            val_val, index),
    )
    email_id_entry.bind(
        "<FocusOut>",
        lambda event, val_val=email_id_entry, val="Email ID", index=3: handle_focus_out(
            val_val, val, index
        ),
    )

    email_password_entry.bind(
        "<FocusIn>",
        lambda event, val_val=email_password_entry, index=4: handle_focus_in(
            val_val, index
        ),
    )
    email_password_entry.bind(
        "<FocusOut>",
        lambda event, val_val=email_password_entry, val="Email password", index=4: handle_focus_out(
            val_val, val, index
        ),
    )

    username.grid(row=2, column=0)
    password.grid(row=3, column=0)
    email_id.grid(row=4, column=0)
    email_password.grid(row=5, column=0)
    username_entry.grid(row=2, column=1)
    password_entry.grid(row=3, column=1)
    email_id_entry.grid(row=4, column=1)
    email_password_entry.grid(row=5, column=1)

    username.place(x=0, y=150)
    password.place(x=0, y=180)
    email_id.place(x=0, y=250)
    email_password.place(x=0, y=280)
    username_entry.place(x=len4 * 10, y=150)
    password_entry.place(x=len4 * 10, y=180)
    email_id_entry.place(x=len4 * 10, y=250)
    email_password_entry.place(x=len4 * 10, y=280)

    show_both_1 = Button(
        login_window1,
        text="Show",
        command=lambda: password_sec(password_entry, show_both_1),
        fg="white",
        bg="#292A2D",
        highlightcolor="#292A2D",
        activebackground="#292A2D",
        activeforeground="white",
        relief=RAISED,
    )
    show_both_12 = Button(
        login_window1,
        text="show",
        command=lambda: password_sec(email_password_entry, show_both_12),
        fg="white",
        bg="#292A2D",
        highlightcolor="#292A2D",
        activebackground="#292A2D",
        activeforeground="white",
        relief=RAISED,
    )
    show_both_12.grid(row=5, column=2)
    show_both_1.grid(row=3, column=2)
    show_both_1.place(x=len4 * 10, y=210)
    show_both_12.place(x=len4 * 10, y=310)

    def register_saving():

        username_register = str(username_entry.get())
        password_register = str(password_entry.get())
        email_id_register = str(email_id_entry.get())
        email_password_register = str(email_password_entry.get())
        if username_register == "Username" or password_register == "Password":
            root2 = Tk()
            root2.withdraw()
            messagebox.showinfo("Fields Empty", "Fields cannot be empty")
            root2.destroy()
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
                    root2 = Tk()
                    root2.withdraw()
                    messagebox.showinfo(
                        "Error", "Username and email already exists")
                    root2.destroy()

                if not registering:
                    register_user.creation(login_window1)

            else:
                root2 = Tk()
                root2.withdraw()
                messagebox.showinfo(
                    "Error", "Please provide password greater than 6 characters"
                )
                root2.destroy()

    register_button = Button(
        login_window1,
        text="Register",
        command=register_saving,
        fg="white",
        bg="#292A2D",
        highlightcolor="#292A2D",
        activebackground="#292A2D",
        activeforeground="white",
        relief=RAISED,
    )
    register_button.grid(row=6, column=0)
    register_button.place(x=150, y=350)
    va = get(login_window1, "1")
    my_label = Label(login_window1, image=va, bg="#292A2D")
    my_label.photo = va
    my_label.place(x=120, y=10)


root.config(bg="#292A2D")
main = Label(
    root,
    text="Welcome to ONE-PASS",
    font=("Comic Sans MS", 16),
    fg="white",
    bg="#292A2D",
)
login_text = Label(
    root, text="Login   :", fg="white", bg="#292A2D", font=("Verdana", 15)
)
register_text = Label(
    root, text="Register: ", fg="white", bg="#292A2D", font=("Verdana", 15)
)
reg_button = Button(
    root,
    text="Register",
    command=lambda: register(root),
    font=("Verdana", 15),
    fg="white",
    bg="#292A2D",
    relief=RAISED,
    highlightthickness=0,
)
login_button = Button(
    root,
    text="login",
    command=lambda: login(root),
    font=("Verdana", 15),
    fg="white",
    bg="#292A2D",
    relief=RAISED,
    highlightthickness=0,
)

main.grid(row=0, column=1, columnspan=2)
login_button.grid(row=7, column=1, columnspan=2)
login_text.grid(row=6, column=1, columnspan=2)
register_text.grid(row=8, column=1, columnspan=2)
reg_button.grid(row=9, column=1, columnspan=2)

main.place(x=30, y=20)

login_text.place(x=40, y=110)
login_button.place(x=140, y=102)

register_text.place(x=40, y=200)
reg_button.place(x=140, y=200 - 8)

root.resizable(False, False)
root.mainloop()

""" to remove all decrypted files
the glob function returns a list of files ending with .decrypted.bin"""
list_file = glob.glob("*decrypted.bin")
for i in list_file:
    converting_str = str(i)
    try:
        os.remove(converting_str)
    except:
        pass
