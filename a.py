"------------------------------------importing modules------------------------------------"
import math
import pickle
import random
import smtplib
from tkinter import *
import glob
import mysql.connector
import pyAesCrypt
import pygame
from simplecrypt import encrypt
import os
import sys
from tkinter import messagebox
import os.path
import time
import atexit
import ctypes
import time
from cryptography.fernet import Fernet

"------------------------------------main tkinter window------------------------------------"

bufferSize = 64 * 1024
root = Tk()
pygame.init()  # main windows were the login screen and register screen goes
root.title("ONE-PASS")
root.configure(bg="black")
width_window = 300
height_window = 300
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = screen_width / 2 - width_window / 2
y = screen_height / 2 - height_window / 2
root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))

password = 0
username = 0
social_media = []
"------------------------------------loading images------------------------------------"
num_password_account = 5
facebook = pygame.image.load("facebook.png")
instagram = pygame.image.load("instagram.png")
google = pygame.image.load("google.png")
github = pygame.image.load("github.png")

# getting the size of the facebook image
fb_size = facebook.get_rect()


"------------------------------------ mysql database ------------------------------------"
my_database = mysql.connector.connect(
    host="localhost", user="root", password="rohithk123"
)
my_cursor = my_database.cursor()
my_cursor.execute("set autocommit=1")
try:
    my_cursor.execute("create database USERS")
    my_cursor.execute("use USERS")
except:
    my_cursor.execute("use USERS")
try:
    my_cursor.execute(
        "create table data_input (username varchar(100) primary key,email_id varchar(500) unique )"
    )
except:
    pass

"------------------------------------Colors------------------------------------"
black = (0, 0, 0)
white = (255, 255, 255)
red = (255, 0, 0)
blue = (0, 0, 255)
green = (0, 255, 0)
catch_error = True

social_media_user_text = ""
social_media_active = False

font = pygame.font.Font("freesansbold.ttf", 30)


def delete_file(file):
    os.remove(file)


def forgot_password(OTP, email):
    mailid = sys.argv[0]
    msg = OTP
    s = smtplib.SMTP("smtp.gmail.com", 587)
    s.starttls()
    s.login("rohithk652@gmail.com", "rohithk2003")
    s.sendmail("rohithk652@gmail.com", email, msg)


def text_object(text, font, color):
    textsurf = font.render(text, True, color)
    return textsurf, textsurf.get_rect()


def message_display_small(text, a, b, color, display):
    smalltext = pygame.font.Font("comic.ttf", 30)
    textsurf, textrect = text_object(text, smalltext, color)
    textrect.center = (int(a), int(b))
    display.blit(textsurf, textrect)


def fb_text(text, a, b, color, display):
    smalltext = pygame.font.Font("freesansbold.ttf", 30)
    textsurf, textrect = text_object(text, smalltext, color)
    textrect.center = (int(a), int(b))
    display.blit(textsurf, textrect)


# def button(social_media_name,username,password):
def login_password():
    window = Tk()
    window.title("Forgot Password")
    text = "Please provide the recovery email and recovery email password that you provided while creating an account"
    text_label = Label(window, text=text)
    recover_email = Label(window, text="Email")
    recover_password = Label(window, text="Password")
    recover_email_entry = Entry(window)
    recover_password_entry = Entry(window)
    text_label.grid(row=0, column=0, columnspan=2)
    recover_email.grid(row=1, column=0)
    recover_password.grid(row=2, column=0)
    recover_email_entry.grid(row=1, column=1)
    recover_password_entry.grid(row=2, column=1)
    key = Fernet.generate_key()
    otp_label = Label(window, text="OTP:")
    otp_entry = Entry(window)

    def generate_key():
        pyAesCrypt.encryptFile("otp.bin", "otp.bin.fenc", key, bufferSize)
        messagebox.showinfo("OTP", "2 minutes to verify otp send to email")
        os.remove("otp.txt")

    email = str(recover_email_entry.get())
    encrypted_data = f.encrypt()
    digits = "1234567890"
    OTP = ""
    for i in range(6):
        OTP += digits[math.floor(random.random() * 10)]
    l = list(OTP)
    f = open("otp.bin", "wb")
    pickle.dump(l, f)
    f.close()
    generate_key()
    Verification()
    forgot_password(OTP, email)


def login():
    login_window = Tk()
    width_window = 300
    height_window = 300
    screen_width = login_window.winfo_screenwidth()
    screen_height = login_window.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2
    login_window.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
    input_entry = Entry(login_window, text="Username:")
    login = Label(login_window, text="Username:")
    pass1 = Label(login_window, text="Password:")
    pass_entry = Entry(login_window, text="Password:", show="*")
    lbl = Label(login_window, text="Please enter your username and password:")
    forgot = Button(login_window, text="Forgot Password", command=login_password)

    def login_checking():
        testing = False
        password = str(pass_entry.get())
        username = str(input_entry.get())
        file_name = str(username)
        try:
            pyAesCrypt.decryptFile(
                file_name + ".bin.fenc",
                file_name + "decrypted" + ".bin",
                password,
                bufferSize,
            )
            f = open(file_name + "decrypted" + ".bin", "rb")
            logins = pickle.load(f)
            messagebox.showinfo("Success", "Success")
            testing = True
        except:
            testing = False
            root = Tk()
            root.withdraw()
            messagebox.showinfo("Error", "Wrong Password or Username")
            root.destroy()
        # if testing:
        #     d = pygame.display.set_mode((800, 600))
        #     gameloop(d, file_name, main_password)

    but = Button(login_window, text="Login", command=login_checking)
    login.grid(row=2, column=2)
    lbl.grid(row=0, column=2, columnspan=2)
    pass1.grid(row=6, column=2)
    input_entry.grid(row=2, column=3)
    pass_entry.grid(row=6, column=3)
    but.grid(row=8, column=3)
    root.destroy()
    login_window.resizable(False, False)

    forgot.grid(row=7, column=2)


def register():
    login_window1 = Tk()
    root.destroy()

    def register_saving():
        username_register = str(username_entry.get())
        password_register = str(password_entry.get())
        email_id_register = str(email_id_entry.get())
        email_password_register = str(email_password_entry.get())
        word = email_id_register.split()
        original = ""
        for p in word:
            for i in p:
                if i == "@":
                    break
                else:
                    original += i
        main1 = original + email_password_register
        cipher_text = encrypt(main1, password_register)
        d = str(cipher_text)
        cipher_text_deleted = d[1::]
        values_list = []
        values = {}
        values[username_register] = password_register
        values_list.append(values)
        try:
            my_cursor.execute(
                "insert into  data_input values (%s,%s)",
                (username_register, cipher_text_deleted),
            )
        except:
            messagebox.showerror("Error", "Username already exists")
        file_name = username_register + ".bin"
        print(values)
        f = open(file_name, "wb")
        pickle.dump(values_list, f)
        f.close()
        pyAesCrypt.encryptFile(
            file_name, file_name + ".fenc", password_register, bufferSize
        )
        os.remove(file_name)

    def hide_password(entry, row, column, row1, column1):
        entry.config(show="*")
        show_both_11 = Button(
            login_window1,
            text="show password",
            command=lambda: show_password(entry, row, column, row1, column1),
        )
        show_both_11.grid(row=row1, column=column1)

    def show_password(entry, row, column, row1, column1):
        entry.config(show="")
        show_both_11 = Button(
            login_window1,
            text="hide password",
            command=lambda: hide_password(entry, row, column, row1, column1),
        )
        show_both_11.grid(row=row1, column=column1)

    username = Label(login_window1, text="Username")
    password = Label(login_window1, text="password")
    email_id = Label(login_window1, text="Recovery Email :")
    email_password = Label(login_window1, text="Recovery Email password")
    username_entry = Entry(login_window1)
    password_entry = Entry(login_window1, show="*")
    email_id_entry = Entry(login_window1)
    email_password_entry = Entry(login_window1, show="*")
    width = login_window1.winfo_screenwidth()

    # register button
    register_button = Button(login_window1, text="Register", command=register_saving)

    # putting the buttons and entries
    username.grid(row=2, column=0)
    password.grid(row=3, column=0)
    email_id.grid(row=4, column=0)
    email_password.grid(row=5, column=0)
    username_entry.grid(row=2, column=1)
    password_entry.grid(row=3, column=1)
    email_id_entry.grid(row=4, column=1)
    email_password_entry.grid(row=5, column=1)
    show_both_1 = Button(
        login_window1,
        text="show password",
        command=lambda: show_password(password_entry, 3, 1, 3, 2),
    )
    show_both_2 = Button(
        login_window1,
        text="show password",
        command=lambda: show_password(email_password_entry, 5, 1, 5, 2),
    )
    show_both_1.grid(row=3, column=2)
    show_both_2.grid(row=5, column=2)

    register_button.grid(row=6, column=0)


main = Label(root, text="Welcome to ONE-PASS manager")
login_text = Label(root, text="Do you already have an account")
register_text = Label(root, text='If you don"t have an account please register')
reg_button = Button(root, text="Register", command=register)
login_button = Button(root, text="login", command=login)  # added login button

main.grid(row=0, column=1, columnspan=2)
login_button.grid(row=7, column=1, columnspan=2)
login_text.grid(row=6, column=1, columnspan=2)
register_text.grid(row=8, column=1, columnspan=2)
reg_button.grid(row=9, column=1, columnspan=2)
root.resizable(False, False)
root.mainloop()
list = glob.glob("*decrypted.bin")
print(list)
for i in list:
    atexit.register(delete_file, i)
