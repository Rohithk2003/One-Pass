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
from data.for_encryption import *
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

fa = None

var = 0
file = None
#database
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

    def switch_frame(self, frame_class,*args):
        global new_frame
        new_frame = frame_class(self,*args)
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
            font=("Cascadia Mono SemiBold", 15),
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

    def login_checking_1(self, master,*event):
        self.username = str(self.input_entry.get())
        self.password = str(self.pass_entry.get())
        login = self.login_checking()
        if self.username != "" or self.password != "":
            check, main_password, passw = self.login_checking()
            if check:
                    root = Tk()
                    root.withdraw()

                    messagebox.showinfo(
                        "Success", "You have now logged in ")
                    root.destroy()
                    master.switch_frame(Gameloop,self.username,self.password)

            else:
                pass
        else:
            if username == "":
                messagebox.showwarning("Error", "Cannot have username")
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

	    status_name = False

	    self.var = var
	    self.file = file
	    self.object = my_cursor
	    self.status = status_name
	    self.username = username
	    self.password_new = password

	    main_ic = tk_image.PhotoImage(image.open(f'{path}\\main_icon.png'))
	    notes_img = tk_image.PhotoImage(image.open(f"{path}\\_notes.png"))
	    new_button = tk_image.PhotoImage(image.open(f"{path}\\_new_but.jpg"))


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
	        command=lambda: self.bins(parent)

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

	def testing(self, master):
			self.button["state"] = DISABLED
			self.notes_buttons["state"] = NORMAL
			self.profile_button["state"] = NORMAL
			master.title("Passwords")
			emptyMenu = Menu(master)
			master.config(menu=emptyMenu)
			new_fa = Frame(self.mainarea, bg="#292A2D", width=1000, height=661)
			new_fa.pack(side=RIGHT,expand=True)
			master.iconbitmap(f"{path}\\password.ico")

	def bins(self,master):
			self.button["state"] = NORMAL
			self.notes_buttons["state"] = DISABLED
			self.profile_button["state"] = NORMAL
			master.title("Passwords")
			emptyMenu = Menu(master)
			master.config(menu=emptyMenu)
			new_fa = Frame(self.mainarea, bg="#292A2D", width=1000, height=661)
			new_fa.pack(side=RIGHT,expand=True)
			master.iconbitmap(f"{path}\\password.ico")
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
