import random
import smtplib
import sqlite3
import pyaes
import pbkdf2
import os
import secrets
import threading
import pyAesCrypt
import hashlib
import base64
import platform
import glob
import pickle as p
from tkscrolledframe import ScrolledFrame

from data.for_encryption import *
from data.update_checker import *

# tkinter modules
from PIL import Image as image
from PIL import ImageTk as tk_image
from tkinter import colorchooser
from tkinter import filedialog as fd
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import ttk
from tkinter import *
# for encryption and decryption
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# for updating the file

import string

bufferSize = 64 * 1024
if platform.system() == "Windows":
    l = os.path.dirname(os.path.realpath(__file__)).split("\\")
    dir_path = ''
    for i in l:
        if i != 'data':
            dir_path += i + '\\'
    path = dir_path + "images\\"
if platform.system() == 'Darwin':
    l = os.path.dirname(os.path.realpath(__file__)).split("/")
    dir_path = ''
    for i in l:
        if i != 'data':
            dir_path += i + '/'
    path = dir_path + "/images/"
if platform.system() == "Linux":
    l = os.path.dirname(os.path.realpath(__file__)).split("/")
    dir_path = ''
    for i in l:
        if i != 'data':
            dir_path += i + '/'
    path = dir_path + "/images/"
fa = None
status_name = ''

var = 0
file = None
# database
if not os.path.exists("DATABASE"):
    os.mkdir("DATABASE")
connection = sqlite3.connect("DATABASE\\users.db", isolation_level=None)
my_cursor = connection.cursor()
my_cursor.execute(
    "create table if not exists data_input (username varchar(100) primary key,email_id varchar(100),password  blob,"
    "salt blob, recovery_password varchar(100), salt_recovery blob) "
)


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
            if i in (0, 1):
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


def password_sec(entry, button):
    a = entry["show"]
    private_img = tk_image.PhotoImage(image.open(f"{path}private.png"))
    unhide_img = tk_image.PhotoImage(image.open(f"{path}eye.png"))
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


class SampleApp(Tk):
    def __init__(self):
        Tk.__init__(self)
        self.title("Password Manager")
        width_window = 1057
        height_window = 661

        self.config(bg="#292A2D")
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        self.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        self._frame = None
        self.switch_frame(Login_page)

    def switch_frame(self, frame_class, *args):
        global new_frame
        new_frame = frame_class(self, *args)
        if self._frame is not None:
            self._frame.destroy()
        self._frame = new_frame
        self._frame.config(width=1057, height=661)
        self._frame.place(x=0, y=0)


class Login_page(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        master.title('Login')
        self.config(bg='grey')

        fa = Login_page

        # canvas for showing lines
        image1 = tk_image.PhotoImage(image.open(f"{path}loginbg.jpg"))
        image1_label = Label(self, image=image1, bd=0)
        image1_label.image = image1
        image1_label.place(x=0, y=0)

        labelframe = LabelFrame(
            self, bg="#06090F", width=900, height=450, relief="solid"
        )
        labelframe.place(x=80, y=125)

        # canvas for showing lines
        my_canvas = Canvas(labelframe, bg="grey", width=1, height=440 + 2)
        my_canvas.place(x=490 - 50, y=0)
        my_canvas.create_line(500, 0, 490, 450, width=0, fill="grey")

        # all label text widgets

        create_text = Label(
            labelframe,
            fg="#CACBC7",
            bg="#06090F",
            font=("Yu Gothic Ui", 15),
            text="If you don't already have an account click\nthe button below to create your account.",
            justify=LEFT,
        )
        create_text.place(x=485, y=50, anchor="w")

        or_text = Label(
            labelframe, text="OR", fg="#CACBC7",
            bg="#06090F", font=("Yu Gothic Ui", 15)
        )
        or_text.place(x=655, y=195)

        forgot_text = Label(
            labelframe,
            fg="#CACBC7",
            bg="#06090F",
            text="Can't login to your account?",
            font=("Yu Gothic Ui", 15),
            justify=LEFT,
        )
        forgot_text.place(x=485, y=300, anchor="w")

        # ------------------Entry---------------------------
        self.input_entry = Entry(
            labelframe,
            width=20 + 5,
            fg="#CACBC7",
            bg="#06090F",
            relief=RAISED,
            selectforeground="white",
            bd=0,
            insertbackground="#CACBC7",
            font=("consolas", 15, "normal"),
        )

        self.pass_entry = Entry(
            labelframe,
            fg="#CACBC7",
            bg="#06090F",
            relief=RAISED,
            selectforeground="#CACBC7",
            bd=0,
            insertbackground="#CACBC7",
            font=("consolas", 15, "normal"),
        )

        self.pass_entry.icursor(0)
        self.input_entry.icursor(0)

        self.pass_entry.place(x=50 + 3, y=200 + 30)
        self.input_entry.place(x=50 + 3, y=150)
        # login label
        login_label = Label(
            labelframe,
            text="Login",
            fg="#CACBC7",
            bg="#06090F",
            font=("Cascadia Mono SemiBold", 20, "bold"),
        )
        login_label.place(x=50, y=70)

        # dot label

        Frame(labelframe, width=280, height=2,
              bg="#CACBC7").place(x=50 + 3, y=230 + 30)
        Frame(labelframe, width=280, height=2,
              bg="#CACBC7").place(x=50 + 3, y=150 + 30)

        # ------------------Button---------------------------

        forgot = Button(
            labelframe,
            text="FORGOT PASSWORD?",
            width=33,
            command=lambda: login_password(
                "Forgot Password", my_cursor),
            fg="white",
            bg="#405A9B",
            border="0",
            highlightcolor="white",
            activebackground="#405A9B",
            activeforeground="white",
            relief=RAISED,
            font=("Segoe UI Semibold", 15),
        )
        # command=lambda: register(window_after, object, window, self),

        register_button = Button(
            labelframe,
            text="CREATE ACCOUNT",
            width=33,
            fg="white",
            bg="orange",
            command=lambda: master.switch_frame(Register_page),
            border="0",
            highlightcolor="white",
            activebackground="orange",
            activeforeground="white",
            relief=RAISED,
            font=("Segoe UI Semibold", 15),
        )

        register_button.place(x=485 + 2, y=100)

        forgot.place(x=485, y=340)
        bar_label = Label(labelframe, text="|", bg="white",
                          fg="white", font=(100))

        bar_label.place(x=200, y=470 - 10 + 2)

        unhide_img = tk_image.PhotoImage(image.open(f"{path}eye.png"))
        show_both_1 = Button(
            labelframe,
            image=unhide_img,
            bg="#06090F",
            command=lambda: password_sec(self.pass_entry, show_both_1),
            highlightcolor="#06090F",
            activebackground="#06090F",
            activeforeground="#06090F",
            bd=0,
            relief=RAISED,
        )
        show_both_1.config(
            image=unhide_img,
        )
        show_both_1.photo = unhide_img

        self.input_entry.insert(END, "Username")
        self.input_entry.config(foreground="grey")
        self.pass_entry.insert(END, "Password")
        self.pass_entry.config(foreground="grey")
        self.pass_entry.config(show="")

        sub_button = Button(
            labelframe,
            bd=0,
            width=23,
            height=1,
            text="LOG IN",
            font=("Segoe UI SemiBold", 15),
            activeforeground="white",
            relief=SUNKEN,
            fg="white",
            bg="#C52522",
            activebackground="#C52522",
            command=lambda: self.login_checking_1(master),
        )
        sub_button.place(x=50 + 3, y=300 + 30)

        show_both_1.place(x=300, y=200 + 30 - 5)

        self.input_entry.bind(
            "<FocusIn>",
            lambda event, val_val=self.input_entry, index=1: handle_focus_in(
                val_val, index, 0),
        )
        self.input_entry.bind(
            "<FocusOut>",
            lambda event, val_val=self.input_entry, val="Username", index=1: handle_focus_out(
                val_val, val, index
            ),
        )

        self.pass_entry.bind(
            "<FocusIn>",
            lambda event, val_val=self.pass_entry, index=2: handle_focus_in(
                val_val, index, 0),
        )
        self.pass_entry.bind(
            "<FocusOut>",
            lambda event, val_val=self.pass_entry, val="Password", index=2: handle_focus_out(
                val_val, val, index
            ),
        )

    def login_checking_1(self, master, *event):
        self.username = str(self.input_entry.get())
        self.password = str(self.pass_entry.get())
        if self.username != "" or self.password != "":
            check, main_password, passw = self.login_checking()
            if check:
                root = Tk()
                root.withdraw()

                messagebox.showinfo(
                    "Success", "You have now logged in ")
                root.destroy()
                master.switch_frame(Gameloop, self.username, self.password)

            else:
                pass
        else:
            if username == "":
                messagebox.showwarning("Error", "Cannot blank have username")
            elif password == "":
                messagebox.showwarning(
                    "Error", "Cannot have blank password")

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


class Register_page(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        global fa
        fa = Register_page
        master.title("Register")
        self.config(bg='grey')
        image1 = tk_image.PhotoImage(image.open(f"{path}background.jpg"))

        image1_label = Label(self, bd=0, image=image1)
        image1_label.image = image1
        image1_label.place(x=0, y=0)
        iconimage = tk_image.PhotoImage(image.open(f"{path}member.png"))
        labelframe1 = LabelFrame(
            self,
            bg="#292A2D",
            width=550,
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
            font=("Yu Gothic Ui", 15),
        )
        password = Label(
            labelframe1,
            fg="#ebebeb",
            text="Password",
            bd=5,
            bg="#292A2D",
            font=("Yu Gothic Ui", 15),
        )
        email_id = Label(
            labelframe1,
            fg="#ebebeb",
            text="Recovery Email",
            bg="#292A2D",
            bd=5,
            font=("Yu Gothic Ui", 15),
        )
        email_password = Label(
            labelframe1,
            fg="#ebebeb",
            text="Recovery Password",
            bg="#292A2D",
            bd=5,
            font=("Yu Gothic Ui", 15),
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
            font=("segoe ui", 15, "normal"),
        )
        password_entry = Entry(
            labelframe1,
            show="*",
            fg="#ebebeb",
            bg="#292A2D",
            borderwidth=0,
            width=17,
            insertbackground="white",
            font=("segoe ui", 15, "normal"),
        )
        email_id_entry = Entry(
            labelframe1,
            borderwidth=0,
            fg="#ebebeb",
            bg="#292A2D",
            width=20,
            insertbackground="white",
            font=("segoe ui", 15, "normal"),
        )
        email_password_entry = Entry(
            labelframe1,
            borderwidth=0,
            fg="#ebebeb",
            bg="#292A2D",
            width=17,
            show="*",
            insertbackground="white",
            font=("segoe ui", 15, "normal"),
        )

        username_entry.place(x=230 - 20, y=170 + 18 + 40 + 4 - 2)
        password_entry.place(x=230 - 20, y=220 + 18 + 40 + 4 - 2)
        email_id_entry.place(x=230 - 20, y=270 + 18 + 40 + 4 - 2)
        email_password_entry.place(x=230 - 20, y=320 + 18 + 40 + 4 - 2)

        Frame(labelframe1, width=220, height=2, bg="#ebebeb").place(
            x=230 - 20, y=170 + 18 + 40 + 4 + 20 + 7 - 2
        )
        Frame(labelframe1, width=220, height=2, bg="#ebebeb").place(
            x=230 - 20, y=220 + 18 + 40 + 4 + 20 + 7 - 2
        )
        Frame(labelframe1, width=220, height=2, bg="#ebebeb").place(
            x=230 - 20, y=270 + 18 + 40 + 4 + 20 + 7 - 2
        )
        Frame(labelframe1, width=220, height=2, bg="#ebebeb").place(
            x=230 - 20, y=320 + 18 + 40 + 4 + 20 + 7 - 2
        )

        submit_but = Button(
            labelframe1,
            bd=0,
            width=20,
            height=2,
            text="R E G I S T E R",
            font=("consolas"),
            fg="#292A2D",
            activeforeground="#292A2D",
            bg="#994422",
            activebackground="#994422",
            command=lambda: register_saving(str(username_entry.get()), str(password_entry.get()), str(email_id_entry.get()),
                                            str(email_password_entry.get())))

        unhide_img = tk_image.PhotoImage(image.open(f"{path}eye.png"))

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
            command=lambda: password_sec(
                email_password_entry, show_both_12),
            fg="#292A2D",
            bg="#292A2D",
            bd=0,
            highlightcolor="#292A2D",
            activebackground="#292A2D",
            activeforeground="#292A2D",
            relief=RAISED,
        )
        show_both_12.image = unhide_img

        show_both_1.place(x=420 - 20, y=220 + 18 + 34)
        show_both_12.place(x=420 - 20, y=320 + 18 + 34)

        login_button = Button(
            labelframe1,
            text="L O G I N",
            width=20,
            height=2,
            font=("consolas"),
            fg="#292A2D",
            bg="#994422",
            activebackground="#994422",
            bd=0,
            relief=SUNKEN,
            command=lambda: master.switch_frame(Login_page),
        )
        login_button.place(x=30, y=470)

        submit_but.place(x=320, y=470)
        generate = Button(labelframe1,
                          text="Generate",
                          fg="#292A2D",
                          bg="#994422",
                          font=("consolas"),
                          activebackground="#994422",
                          bd=0,
                          relief=SUNKEN,
                          command=lambda: pass_generator(password_entry))
        generate.place(x=440, y=220 + 18 + 39)
        generate1 = Button(labelframe1,
                           text="Generate",
                           fg="#292A2D",
                           bg="#994422",
                           font=("consolas"),
                           activebackground="#994422",
                           bd=0,
                           relief=SUNKEN,
                           command=lambda: pass_generator(email_password_entry))
        generate1.place(x=440, y=320 + 18 + 40 + 4 - 2)

    def register_saving(self):
        submit_but.config(state=DISABLED)

        if username_register == "" or password_register == "":
            messagebox.showinfo("Fields Empty", "Fields cannot be empty")
        else:
            register_user = Register(
                self.username,
                self.password,
                self.email_id,
                self.email_password,
            )
            if register_user.check_pass_length():
                if register_user.check_password_integrity(password_register):
                    if register_user.email_exists():
                        registering = register_user.saving(my_cursor)
                        if registering:
                            messagebox.showinfo(
                                "Error", "Username or email is unavailable")
                            submit_but.config(state=NORMAL)
                        if not registering:
                            register_user.creation(self)

                    else:
                        root2 = Tk()
                        root2.withdraw()
                        messagebox.showinfo(
                            "Error", "Invalid Email"
                        )
                        submit_but.config(state=NORMAL)

                        root2.destroy()
                else:
                    root2 = Tk()
                    root2.withdraw()
                    messagebox.showinfo(
                        "Error", "Please provide a stronger password"
                    )
                    submit_but.config(state=NORMAL)
                    root2.destroy()

            else:
                root2 = Tk()
                root2.withdraw()
                messagebox.showinfo(
                    "Error", "Please provide password greater than 6 characters"
                )
                submit_but.config(state=NORMAL)
                root2.destroy()

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
        return self.email_id.endswith(("gmail.com", "yahho.com"))

    def check_pass_length(self):  # checking if the entered password is lesser than 5
        return len(self.password) >= 5

    """to create a file named user and to store his accounts and also add his details to the database"""

    def saving(self):

        my_cursor.execute("select username from data_input")
        values_username = my_cursor.fetchall()
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
            my_cursor.execute(
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


class Gameloop(Frame):
    def __init__(self, parent, username, password):
        Frame.__init__(self, parent)
        global var
        global file
        self.parent = parent
        status_name = False

        self.var = var
        self.file = file
        self.object = my_cursor
        self.status = status_name
        self.username = username
        self.password_new = password

        main_ic = tk_image.PhotoImage(image.open(f'{path}main_icon.png'))
        notes_img = tk_image.PhotoImage(image.open(f"{path}_notes.png"))
        new_button = tk_image.PhotoImage(image.open(f"{path}_new_but.jpg"))

        self.sidebar = Frame(
            self, width=5, bg="#292A2D", height=661, relief="sunken", borderwidth=1
        )
        self.sidebar_icon = Label(self.sidebar, image=main_ic, bg='#292A2D')
        self.sidebar_icon.image = main_ic
        self.mainarea = Frame(self, bg="#292A2D", width=1000, height=661)
        self.button = Button(
            self.sidebar,
            image=new_button,
            text='Passwords',
            bg='#292A2D',
            compound=CENTER,
            border=0,
            bd=0,
            borderwidth=0,
            highlightthickness=0,
            highlightcolor='#292A2D',
            command=lambda: self.testing(parent))

        self.sidebar.pack(expand=False, fill="both", side="left")
        self.mainarea.pack(expand=True, fill="both", side="right")

        self.object.execute(
            "select email_id,salt_recovery from data_input where username = (?)",
            (simple_encrypt(self.username),),
        )

        self.hash_password = hashlib.sha3_512(
            (self.password_new + self.username).encode()).hexdigest()
        email_id = ""

        for email in self.object.fetchall():
            self.email_id = simple_decrypt(email[0])

        email_split = ""
        decrypted_string = ""

        word = self.email_id.split()
        for i in word:
            for a in i:
                if i == "@":
                    break
                else:
                    email_split += i
        val = email_split[::-1]
        self.object.execute(
            "select recovery_password,salt_recovery from data_input where username = (?)",
            (simple_encrypt(self.username),),
        )
        encrypted_pass = ""
        d = self.object.fetchall()
        encrypt, salt = '', ''
        for i in d:
            salt = i[1]
            encrypt = i[0]
        password = self.email_id + self.hash_password
        key = pbkdf2.PBKDF2(password, salt).read(32)
        aes = pyaes.AESModeOfOperationCTR(key)
        self.encrypted_pass = aes.decrypt(encrypt)
        self.notes_buttons = Button(
            self.sidebar,
            image=new_button,
            text='Notes',
            bg='#292A2D',
            compound=CENTER,
            border=0,
            bd=0,
            borderwidth=0,
            highlightthickness=0,
            highlightcolor='#292A2D',
            command=lambda: self.notes(parent)

        )

        settings_image = tk_image.PhotoImage(
            image.open(f"{path}\\settings.png"))
        self.settings_button = Button(
            self.sidebar,
            activebackground="#292A2D",
            image=settings_image,
            fg="white",
            bg="#292A2D",
            border="0",
            relief=FLAT,
            highlightthickness=0,
            activeforeground="white",
            bd=0,
            borderwidth=0,
        )
        self.settings_button.image = settings_image
        # profile_object = Profile_view(
        #     self.username,
        #     self.password,
        #     self.email_id,
        #     self.encrypted_pass,
        #     self.hash_password,
        #     self.mainarea,
        #     self.button,
        #     self.notes_buttons,
        #     parent,
        #     self.object
        # )
        self.profile_button = Button(
            self.sidebar,
            image=new_button,
            text=f'Profile',
            bg='#292A2D',
            compound=CENTER,
            border=0,
            bd=0,
            borderwidth=0,
            highlightthickness=0,
            highlightcolor='#292A2D',


        )

        self.profile_button.photo = new_button
        self.settings_button.photo = settings_image

        self.button.grid(row=1, column=1)
        self.button.place(x=0, y=150 + 20)
        self.notes_buttons.grid(row=2, column=1)
        self.notes_buttons.place(x=0, y=140 + 20 + 20 + 17)
        self.profile_button.grid(row=3, column=1)
        self.profile_button.place(x=0, y=140 + 20 + 20 + 30 + 14)
        self.settings_button.grid(row=10, column=1, columnspan=1)
        self.settings_button.place(x=30 + 50 + 10, y=440 + 200 + 20)
        self.sidebar_icon.grid(row=0, column=0)
        self._frame = None

    def testing(self, master):
        self.button["state"] = DISABLED
        self.notes_buttons["state"] = NORMAL
        self.profile_button["state"] = NORMAL
        master.title("Passwords")
        emptyMenu = Menu(master)
        master.config(menu=emptyMenu)
        master.iconbitmap(f"{path}\\password.ico")
        self.switchframe(Password_display, master, self.username,
                         self.hash_password, self.object, self.password_new)

    def notes(self, master):
        self.button["state"] = NORMAL
        self.notes_buttons["state"] = DISABLED
        self.profile_button["state"] = NORMAL
        master.title("Passwords")
        emptyMenu = Menu(master)
        master.config(menu=emptyMenu)

        master.iconbitmap(f"{path}\\password.ico")
        self.switchframe(Note_pad, master)

    def switchframe(self, frame_class, master, *args):
        global new_frame
        new_frame = frame_class(master, self, self.notes_buttons,
                                self.button, self.profile_button, self.sidebar, *args)
        if self._frame is not None:
            self._frame.destroy()
        self._frame = new_frame
        self._frame.config(width=1057, height=661)
        self._frame.place(x=134, y=0)


class Note_pad(Frame):
    def __init__(self, main_window, master, notes_buttons, button, profile_button, sidebar):
        Frame.__init__(self, main_window)
        notes_buttons.config(state=DISABLED)
        button.config(state=NORMAL)
        profile_button.config(state=NORMAL)
        main_window.title("Untitled-Notepad")
        main_window.iconbitmap(f"{path}_notes.ico")
        self.config(bg='black')

        def newFile():
            main_window.title("Untitled - Notepad")
            TextArea.delete(1.0, END)

        def openFile():
            global file
            file = fd.askopenfilename(
                defaultextension=".txt",
                filetypes=[("All Files", "*.*"),
                           ("Text Documents", "*.txt")],
            )

            # check to if there is a file_name
            global status_name
            status_name = file
            if file == "":
                file = None
            else:
                main_window.title(os.path.basename(file) + " - Notepad")
                TextArea.delete(1.0, END)
                with open(file, "r") as f:
                    TextArea.insert(1.0, f.read())
                    f.close()

        def rename_file():
            global file
            if main_window.title() != "Untitled-Notepad":
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
                    main_window.title(a + file_extension + " - Notepad")
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
                    main_window.title(os.path.basename(file) + " - Notepad")
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
                    main_window.title(os.path.basename(file) + " - Notepad")

        def quitApp():
            try:
                main_window.destroy()
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
        main_window.iconbitmap(False, f"{path}_notes.ico")
        main_window.title("Untitled - Notepad")
        # Add TextArea
        font_main = ("freesansbold", 12)
        Scroll_y = Scrollbar(self, orient="vertical")
        Scroll_y.pack(side="right", fill=Y)
        TextArea = Text(
            self,
            font=font_main,
            fg="#292A2D",
            insertofftime=600,
            insertontime=600,
            insertbackground="#292A2D",
            undo=True,
            width=1057, height=661,
            yscrollcommand=Scroll_y.set,
        )

        Scroll_y.config(command=TextArea.yview)
        TextArea.pack(expand=True, fill=BOTH)

        # create a menubar
        MenuBar = Menu(main_window)
        MenuBar.config(bg="#292A2D", bd=0, activebackground="#292A2D")
        status_name = False
        main_window.config(bg="red", menu=MenuBar)
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
            lb = Label(self, text=var, anchor=E)
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
            replace_window = Toplevel(self)
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
            find_window = Toplevel(self)
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
            my_menu.tk_popup(e.x_main_window, e.y_main_window)

        main_window.bind("<Control-Key-f>", primary)
        main_window.bind("<Control-Key-h>", secondary)

        EditMenu = Menu(MenuBar, tearoff=0)
        EditMenu.config(
            bg="#292A2D", bd="0", relief="ridge", activebackground="#292A2D"
        )
        TextArea.bind("<Control-MouseWheel>", size_change)

        my_menu = Menu(
            self, tearoff=0, bd="0", borderwidth="0", background="#292A2D"
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
        submenu_size.add_command(
            label="31",
            command=lambda: change_size(31),
            foreground="white",
            activebackground="#4B4C4F",
        )
        submenu_size.add_command(
            label="32",
            command=lambda: change_size(32),
            foreground="white",
            activebackground="#4B4C4F",
        )
        submenu_size.add_command(
            label="33",
            command=lambda: change_size(33),
            foreground="white",
            activebackground="#4B4C4F",
        )
        submenu_size.add_command(
            label="34",
            command=lambda: change_size(34),
            foreground="white",
            activebackground="#4B4C4F",
        )
        submenu_size.add_command(
            label="35",
            command=lambda: change_size(35),
            foreground="white",
            activebackground="#4B4C4F",
        )
        submenu_size.add_command(
            label="36",
            command=lambda: change_size(36),
            foreground="white",
            activebackground="#4B4C4F",
        )
        submenu_size.add_command(
            label="37",
            command=lambda: change_size(37),
            foreground="white",
            activebackground="#4B4C4F",
        )
        submenu_size.add_command(
            label="38",
            command=lambda: change_size(38),
            foreground="white",
            activebackground="#4B4C4F",
        )
        submenu_size.add_command(
            label="39",
            command=lambda: change_size(39),
            foreground="white",
            activebackground="#4B4C4F",
        )
        submenu_size.add_command(
            label="40",
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
        main_window.bind("<Control-Key-s>", callback)
        main_window.bind("<Control-Shift-S>", second_callback)
        main_window.bind("<Control-Key-x>", cut)
        main_window.bind("<Control-Key-c>", copy)
        main_window.bind("<Control-Key-v>", paste)
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

        main_window.config(menu=MenuBar)


class Password_display(Frame):
    def __init__(self, main_window, master, notes_buttons, button, profile_button, sidebar, *args):
        self.main_window = main_window
        Frame.__init__(self, self.main_window)
        notes_buttons.config(state=NORMAL)
        button.config(state=DISABLED)
        profile_button.config(state=NORMAL)
        emptyMenu = Menu(self.main_window)
        self.main_window.config(menu=emptyMenu)
        # getting the username
        self.username = args[0]
        self.hashed_password = args[1]
        self.mainarea = master
        self.button = button
        self.object = args[2]
        self.password = args[3]
        bg_img = tk_image.PhotoImage(image.open(f"{path}log.jpg"))
        self.subbar = Frame(self, bg="black", width=120, height=1057, relief="sunken", borderwidth=2
                       )
        self.subbar.grid(row=0, column=0)
        self.subbar.grid_propagate(False)


        scrollbar = ScrolledFrame(self.subbar, width=120, height=661)

        scrollbar.pack(expand=1, fill=Y)
        # configure the canvas
        scrollbar.bind_arrow_keys(self.subbar)
        scrollbar.bind_scroll_wheel(self.subbar)
        scrollbar.focus_set()

        # creating another frame
        self.second_frame = scrollbar.display_widget(Frame)


        # add that new frame to a new window in the canvas
        image_new = tk_image.PhotoImage(image.open(f"{path}add-button.png"))
        bg_img = tk_image.PhotoImage(image.open(f"{path}log.jpg"))

        self.add_button = Button(
            self.second_frame,
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
            command=lambda: self.addaccount(),
        )
        self.add_button.photo = image_new
        values = []
        with open(f"{self.username}decrypted.bin", "rb") as f:
            try:
                values = p.load(f)
            except:
                pass
        length_list = len(values)
        self.add_button.grid(row=length_list, column=0)

        self.buttons_blit(
            bg_img
        )

    def buttons_blit(self, bg_image):
        global buttons_list
        global btn_nr
        new = []

        with open(f"{self.username}decrypted.bin", "rb") as f:
                val = p.load(f)
                for i in val:
                    new.append(i[2])
                d = {}
                for i in range(len(new)):
                    if val[i][3] == "":
                        button_img = tk_image.PhotoImage(
                            image.open(f"{path}photo.png"))
                    else:
                        button_img = tk_image.PhotoImage(image.open(val[i][3]))
                    d[
                        Button(
                            self.second_frame,
                            text=f"{new[i]}",
                            bg="#292A2D",
                            fg="white",
                            activeforeground="white",
                            activebackground="#292A2D",
                            width=120,
                            font=("Segoe UI Semibold", 9),
                            image=button_img,
                            compound="top",
                            command=lambda:self.show_account())

                    ] = [i, button_img]

                for i in d:
                    i.image = d[i][1]
                    i.grid(row=d[i][0], column=0)
                with open(f"{self.username}decrypted.bin", "rb") as f:
                    try:
                        values = p.load(f)
                    except:
                        values = []
                length_list = len(values)
                self.add_button.grid(row=length_list + 1, column=0)


    def verify(self):
        file_name = f"{self.username}decrypted.bin"
        with open(file_name, "rb") as f:
            try:
                test_values = p.load(f)
                for user in test_values:
                    if user[0] == str(self.username_window_entry.get()) and user[2] == str(self.name_of_social_entry.get()):
                        return True
            except:
                return False

    def save(self, *image_path):
        global exist
        if len(image_path) == 0:
            self.image_path = f'{path}photo.png'
        list_account = [
            str(self.username_window_entry.get()),
            str(self.password_entry.get()),
            str(self.name_of_social_entry.get()),
            self.image_path,
        ]
        if str(self.username_window_entry.get()) == "":
            messagebox.showwarning("Warning", "Username cannot be empty")
        elif str(self.password_entry.get()) == "":
            messagebox.showwarning("Warning", "Password cannot be empty")
        elif str(self.name_of_social_entry.get()) == "":
            messagebox.showwarning(
                "Warning", "Name of the account cannot be empty")
        else:
            verifying = self.verify()

            if verifying:
                messagebox.showerror("Error", "The account already exists")
            else:
                name_file = self.username + "decrypted.bin"
                with open(name_file, "rb") as f:
                    try:
                        line = p.load(f)
                    except:
                        line = []
                    line.append(list_account)
                    f.close()
                with open(name_file, "wb") as f1:
                    p.dump(line, f1)
                    f.close()
                os.remove(self.username + ".bin.fenc")
                pyAesCrypt.encryptFile(
                    name_file, f'{self.username}.bin.fenc', self.hashed_password, bufferSize
                )
                messagebox.showinfo("Success", "Your account has been saved")
                with open(f"{self.username}decrypted.bin", "rb") as f:
                    val = p.load(f)
                    self.add_button.grid(row=len(val) + 1, column=0)
                self.root1.destroy()
                self.main_window.switch_frame(
                    Gameloop, self.username, self.password)

    def addaccount(self):
        self.root1 = Toplevel()
        self.root1.geometry("400x300")
        self.root1.title("Add Account")
        self.root1.focus_set()
        self.root1.grab_set()
        self.root1.resizable(False, False)
        width_window = 400
        height_window = 400
        screen_width = self.root1.winfo_screenwidth()
        screen_height = self.root1.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        self.root1.config(bg="#292A2D")
        self.root1.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        name_of_social = Label(
            self.root1, text="Name of the account", fg="white", bg="#292A2D")
        username_window = Label(self.root1, text="Username:",
                                fg="white", bg="#292A2D")
        password_window = Label(self.root1, text="Password:",
                                fg="white", bg="#292A2D")
        self.username_window_entry = Entry(self.root1)
        self.password_entry = Entry(self.root1)
        self.name_of_social_entry = Entry(self.root1)

        self.password_entry.grid(row=2, column=2)
        self.username_window_entry.grid(row=1, column=2)
        password_window.grid(row=2, column=1)
        username_window.grid(row=1, column=1)
        self.name_of_social_entry.grid(row=0, column=2)
        name_of_social.grid(row=0, column=1)

        username_window.place(x=50, y=100 + 100)
        password_window.place(x=50, y=130 + 100)
        name_of_social.place(x=50, y=70 + 100)
        self.username_window_entry.place(x=200, y=100 + 100)
        self.password_entry.place(x=200, y=130 + 100)
        self.name_of_social_entry.place(x=200, y=70 + 100)

        def browsefunc(self):
            # try:
            #     self.image_path = fd.askopenfilename()
            #     im = image.open(self.image_path)
            #     tkimage = tk_image.PhotoImage(im)
            #     add_icon_button.config(image=tkimage)
            #     add_icon_button.photo = tkimage
            # except:
            self.image_path = f"{path}photo.png"
            im = image.open(self.image_path)
            tkimage = tk_image.PhotoImage(im)
            add_icon_button.config(image=tkimage)
            add_icon_button.photo = tkimage
            save_button.config(command=lambda: self.save(self.image_path))
        new_id = tk_image.PhotoImage(image.open(f"{path}photo.png"))
        add_icon_button = Button(
            self.root1,
            image=new_id,
            borderwidth="0",
            command=lambda: self.browsefunc(),
            border="0",
            highlightthickness="0",
            activebackground="#292A2D",
            bg="#292A2D",
        )
        add_icon_button.photo = new_id
        add_icon_button.grid(row=3, column=0)
        add_icon_button.place(x=125, y=200)

        save_button = Button(self.root1, text="Save", command=lambda: self.save(),
                             fg="white", bg="#292A2D")
        save_button.grid(row=4, column=1)
        save_button.place(x=250, y=170 + 100)
        add_icon_button.place(x=150, y=50)
        self.root1.mainloop()

    def show_account(self):
        global buttons_list
        change_object = Change_details(username, hashed_password, window,object)
        delete_object = Deletion(username, hashed_password, window,object)

        #creating a canvas to fix background image
        new_canvas = Canvas(
            self, width=1000 + 50, height=1057, bd="0", highlightthickness=0
        )
        new_canvas.place(x=120 + 20, y=0)
        new_canvas.create_image(0, 0, image=bg_img, anchor="nw")
        new_s = Frame(new_canvas, bg="#292A2D", width=500, height=400, bd=0)
        MainWindow = new_canvas.create_window(650 + 60, 600 - 60, window=new_s, anchor="se")
        def copy(value):
            pyperclip.copy(value)
            messagebox.showinfo("Copied","Copied!!!")
        with open(f"{username}decrypted.bin", "rb") as f:
            lists = p.load(f)
        dot_text = Label(new_s, text=":", bg="#292A2D", fg="white", font=(20))
        dot_text1 = Label(new_s, text=":", bg="#292A2D", fg="white", font=(20))
        dot_text2 = Label(new_s, text=":", bg="#292A2D", fg="white", font=(20))
        delete_account = Button(
              new_s,
              text="Delete Account",
             bg="#292A2D",
             fg="white",
             font=("Cascadia Mono SemiBold", 15),
             command=lambda: delete_object.delete_social_media_account(
                 password_button, False, lists[button][2]
             ),
         )

        ChangeAccount = Button(
             new_s,
             text="Change Details",
             bg="##292A2D",
             fg="white",
             font=("Cascadia Mono SemiBold", 15),
             command=lambda: change_object.change_window_creation(
                 lists[button][0], password_button
             ),
         )

        username_label = Label(
             new_s,
             text="Username",
             bg="##292A2D",
             fg="white",
             font=("Cascadia Mono SemiBold", 15),
         )
        password_label = Label(
             new_s,
             text="Password",
             bg="#292A2D",
             fg="white",
             font=("Cascadia Mono SemiBold", 15),
         )
        social_account = Label(
             new_s,
             text="Account Name",
             bg="#292A2D",
             fg="white",
             font=("Cascadia Mono SemiBold", 15),
         )

        username_text = Label(
             new_s,
             text=lists[button][0],
             bg="#292A2D",
             fg="white",
             font=("Cascadia Mono SemiBold", 15),
         )
        password_text = Label(
             new_s,
             text=lists[button][1],
             bg="#292A2D",
             fg="white",
             font=("Cascadia Mono SemiBold", 15),
         )
        social_account_text = Label(
             new_s,
             text=lists[button][2],
             bg="##292A2D",
             fg="white",
             font=("Cascadia Mono SemiBold", 15),
         )
        copy_but_password = Button(new_s,text="Copy Password", bg="##292A2D", fg="white", font=("Cascadia Mono SemiBold",9),command=lambda:copy(lists[button][1]))
        copy_but_username = Button(new_s,text="Copy Username", bg="##292A2D", fg="white", font=("Cascadia Mono SemiBold",9),command=lambda:copy(lists[button][0]))

        if lists[button][3] == "":
         img = tk_image.PhotoImage(image.open(f"{path}camera.png"))
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
             password_button,object
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
        copy_but_username.place(x=360, y=30)
        copy_but_password.place(x=360, y=80)

if __name__ == "__main__":

    app = SampleApp()
    app.mainloop()
""" to remove all decrypted files
the glob function returns a list of files ending with decrypted.bin"""
list_file = glob.glob("*decrypted.bin")
for i in list_file:
    try:
        os.remove(str(i))
    except:
        pass
