"------------------------------------importing modules------------------------------------"
import math
import pickle
import random
import smtplib
from tkinter import *
import glob
import pyAesCrypt
import mysql.connector
import pygame
from simplecrypt import encrypt,decrypt
import os
import sys
from tkinter import messagebox
import os.path
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
my_cursor.execute("create database if not exists  USERS")
my_cursor.execute("use USERS")
my_cursor.execute(
    "create table if not exists data_input (username varchar(100) primary key,email_id varchar(100),password varchar(500))"
)
"******************************Colors******************************"
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
    try:
        os.remove(file)
    except:
        return 'error'


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
    text = "Please provide the recovery email  and recovery email password \n that you provided while creating an account"
    text_label = Label(window, text=text)
    username_forgot = Label(window, text="Username")
    recover_email = Label(window, text="Email")
    recover_password = Label(window, text="Password")
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
    key = ""
    l = "abcdefghijklmnopqrstuvwxyz"
    for i in range(7):
        key += random.choice(l)

    running = False

    def generate_key1(file):
        pyAesCrypt.encryptFile(file, "otp.bin.fenc", key, bufferSize)
        messagebox.showinfo("OTP", "2 minutes to verify otp send to email")
        os.remove(file)

    def change_password(email, password1, username12):
        root = Tk()
        root.title("Change Password")
        new_username = Label(root, text="New Username")
        new_password = Label(root, text="New Password")
        new_username_entry = Entry(root)
        new_password_entry = Entry(root)
        new_username.grid(row=1, column=0)
        new_password.grid(row=2, column=0)
        file_name_reentry = username12 + ".bin.fenc"
        new_username_entry.grid(row=1, column=1)
        new_password_entry.grid(row=2, column=1)
        my_cursor.execute(
            "select password from data_input where email_id = (%s)", (email,)
        )
        values_password = my_cursor.fetchall()
        password_decrypt = ""
        for i in email:
            if i == "@":
                break
            else:
                password_decrypt += i
        password_decrypt += password1
        for i in values_password:
            for op in i:
                pass_value = bytes(op,'utf-8')
                decrypted_string = decrypt(password_decrypt, pass_value)
                pyAesCrypt.decryptFile(
                    file_name_reentry,
                    username12 + ".bin",
                    decrypted_string,
                    bufferSize,
                )
                os.remove(file_name_reentry)
                f = open(username12 + ".bin", "r")
                list_b = pickle.load(f)
                list_b.pop(0)
                pol = {}
                pol[str(new_username_entry.get())] = str(new_password_entry.get())
                list_b.append(pol)
                pickle.dump(list_b, f)
                f.close()
                my_cursor.execute(
                    "delete from data_input where username=(%s)", (username12)
                )
                re_encrypt = encrypt(
                    password_decrypt, str(new_password_entry.get())
                )
                pyAesCrypt.encryptFile(
                    username12 + ".bin",
                    new_username + ".bin.fenc",
                    str(new_password_entry.get()),
                    bufferSize,
                )
                my_cursor.execute(
                    "insert into data_input values(%s,%s,%s)",
                    (str(new_username.get()), email, re_encrypt),
                )

    def Verification(password, otp_entry, email, email_password, username12):
        ot = str(otp_entry)
        pyAesCrypt.decryptFile(
            "otp.bin.fenc", "otp_decyrpted.bin", password, bufferSize
        )
        f11 = open("otp_decyrpted.bin", "rb")
        list = pickle.load(f11)
        str_value = ""
        for i in list:
            str_value += str(i)
        if str_value == ot:
            roo1 = Tk()
            roo1.withdraw()
            messagebox.showinfo("Success", "OTP is verified")
            roo1.destroy()
            f11.close()
            os.remove("otp_decyrpted.bin")
            os.remove("otp.bin.fenc")
            change_password(email, email_password, username12)

    def forgot_password(OTP, email, username):
        global running
        running = True
        mailid = sys.argv[0]
        SUBJECT = "OTP verification"
        otp = (
            "Hey"
            + username
            + " "
            + "! Your otp for ONE-PASS is  "
            + " "
            + OTP
            + " "
            + "This OTP will expire in 2 minutes"
        )
        msg = "Subject: {}\n\n{}".format(SUBJECT, otp)
        s = smtplib.SMTP("smtp.gmail.com", 587)
        s.starttls()
        s.login("rohithk652@gmail.com", "rohithk2003")
        s.sendmail("rohithk652@gmail.com", email, msg)

    def main(key):
        run = False
        global running
        username_verify = str(username_forgot_entry.get())
        recover_email_entry_verify = str(recover_email_entry.get())
        recover_password_entry_verify = str(recover_password_entry.get())
        if (
            username_verify == ""
            and recover_email_entry_verify == ""
            and recover_password_entry_verify == ""
        ):
            roo21 = Tk()
            roo21.withdraw()
            messagebox.showinfo(
                "Error",
                "please provide required information to \n change your password",
            )
            roo21.destroy()
        verify_password = ""
        otp_label = Label(window, text="OTP:")
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
        )
        otp_entry_button.grid(row=8, column=1)
        for i in recover_email_entry_verify:
            if i == "@":
                break
            else:
                verify_password += i
        verify_password += recover_password_entry_verify
        try:
            my_cursor.execute(
                "select email_id from data_input where username = (%s)",
                (username_verify,),
            )
            values_fetch = my_cursor.fetchall()
            for i in values_fetch:
                for a in i:
                    if a == recover_email_entry_verify:
                        run = True
                    else:
                        run = False
                        roo1 = Tk()
                        roo1.withdraw()
                        messagebox.showerror("Error", "Wrong Recovey email")
                        roo1.destroy()
        except:
            roo1 = Tk()
            roo1.withdraw()
            messagebox.showerror("Error", "No user exist with the provided username")
            roo1.destroy()
        if run:
            digits = "1234567890"
            OTP = ""
            for i in range(6):
                OTP += random.choice(digits)
            l = list(OTP)
            f = open("otp.bin", "wb")
            pickle.dump(l, f)
            f.close()
            generate_key1("otp.bin")
            forgot_password(OTP, recover_email_entry_verify, username_verify)
            Verification(
                key,
                str(otp_entry.get()),
                recover_email_entry_verify,
                recover_password_entry_verify,
                username_verify,
            )

    forgot_password_button = Button(window, text="verify", command=lambda: main(key))
    forgot_password_button.grid(row=5, column=1)


def button(social_media, username, password):
    file_name = str(username) + social_media + ".bin.fenc"
    if os.path.exists(file_name):
        root = Tk()
        width_window = 300
        height_window = 300
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))

        line = pickle.load(f1)
        title1 = social_media + "Account"
        root.title(title1)
        first = line[0]
        second = line[1]
        text12 = social_media + "Username:"
        text22 = social_media + "Password:"
        a1_text = Label(root, text=first)
        a2_text = Label(root, text=second)
        a1_text.grid(row=0, column=1)
        a2_text.grid(row=1, column=1)
        fwq = Label(root, text=text12)
        f12 = Label(root, text=text22)
        fwq.grid(row=0, column=0)
        f12.grid(row=1, column=0)

        def _delete_window():
            try:
                root.destroy()
            except:
                pass

        def back1():
            pygame.init()
            root.destroy()
            d = pygame.display.set_mode((800, 600))
            gameloop(d, str(username), password)

        def _destroy(event):
            f1.close()
            if os.path.exists(str(username) + "_facebook" + "decrypted" + ".bin"):
                os.remove(str(username) + "_facebook" + "decrypted" + ".bin")
            if os.path.exist(str(username) + "decrypted.bin"):
                os.remove(str(username) + "decrypted.bin")
            else:
                pass

        # def remote():

        #     usr = "rohithkrishnan2003@gmail.com"
        #     pwd = "Batman@1234"

        #     driver = webdriver.Chrome(ChromeDriverManager().install())
        #     driver.get("https://www.facebook.com/")
        #     print("Opened facebook")
        #     sleep(1)

        #     username_box = driver.find_element_by_id("email")
        #     username_box.send_keys(usr)
        #     print("Email Id entered")
        #     sleep(1)

        #     password_box = driver.find_element_by_id("pass")
        #     password_box.send_keys(pwd)
        #     print("Password entered")

        #     login_box = driver.find_element_by_id("u_0_b")
        #     login_box.click()

        #     print("Done")
        #     input("Press anything to quit")
        #     driver.quit()

        # root.protocol("WM_DELETE_WINDOW", _delete_window)
        # root.bind("<Destroy>", _destroy)

        back = Button(root, text="Go back!", command=back1, width=10)
        back.grid(row=3, column=0, columnspan=2)
        # remote_login = Button(root, text="Facebook", command=remote, width=10)
        # remote_login.grid(row=4, column=0, columnspan=2)

    else:
        second = Tk()
        width_window = 300
        height_window = 300
        screen_width = second.winfo_screenwidth()
        screen_height = second.winfo_screenheight()
        second.title("Facebook Login")
        username1 = Label(second, text="Facebook_Username:")
        password1 = Label(second, text="Facebook_Password:")
        username1_entry = Entry(second)
        password1_entry = Entry(second, show="*")
        login_text1 = "Please provide Facebook account and password"
        login_text = Label(second, text=login_text1)
        username1.grid(row=2, column=0)
        password1.grid(row=3, column=0)
        username1_entry.grid(row=2, column=1)
        password1_entry.grid(row=3, column=1, columnspan=2)
        username_list = []

        def save():
            c = username1_entry.get()
            fb_username = str(username)
            fb_password = password1_entry.get()
            a = fb_username + "_facebook"
            b = str(fb_password)
            fb_account_cipher = password
            username_list.append(str(c))
            username_list.append(b)
            f = open(a + ".bin", "wb")
            pickle.dump(username_list, f)
            f.close()
            pyAesCrypt.encryptFile(
                a + ".bin", a + ".bin.fenc", fb_account_cipher, bufferSize
            )
            os.remove(a + ".bin")

        saving = Button(second, text="Save", command=save)
        saving.grid(row=4, column=1)


def gameloop(a, username, password):
    quitting = True
    while quitting:
        a.fill((255, 255, 255))
        for e in pygame.event.get():
            if e.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
                quit()
                break
        mouse = pygame.mouse.get_pressed()
        mouse_pos = pygame.mouse.get_pos()
        a.blit(facebook, (20, 20))
        message_display_small(
            "Facebook",
            45 + facebook.get_width() - 100 + 10,
            25 + facebook.get_height() + 10,
            black,
            a,
        )
        if (
            mouse[0] == 1
            and 20 < mouse_pos[0] < 20 + facebook.get_width()
            and 20 < mouse_pos[1] < 20 + facebook.get_height()
        ):
            quitting = False
            pygame.quit()
            button("facebook", username, password)
            break
        pygame.display.update()


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
        main_password = password
        try:
            pyAesCrypt.decryptFile(
                file_name + ".bin.fenc",
                file_name + "decrypted" + ".bin",
                password,
                bufferSize,
            )
            f = open(file_name + "decrypted" + ".bin", "rb")
            logins = pickle.load(f)
            roo1 = Tk()
            roo1.withdraw()
            messagebox.showinfo("Success", "Success")
            roo1.destroy()
            testing = True
        except:
            testing = False
            root = Tk()
            root.withdraw()
            messagebox.showinfo("Error", "Wrong Password or Username")
            root.destroy()
        if testing:
            d = pygame.display.set_mode((800, 600))
            gameloop(d, file_name, main_password)

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
                "insert into  data_input values (%s,%s,%s)",
                (
                    username_register,
                    email_id_register,
                    cipher_text_deleted,
                ),
            )
        except:
            roo1 = Tk()
            roo1.withdraw()
            messagebox.showerror("Error", "Username already exists")
            roo1.destroy()
        file_name = username_register + ".bin"
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
for i in list:
    atexit.register(delete_file, i)
try:
    atexit.register(delete_file, "opt_decrypted.bin")
    atexit.register(delete_file, "otp.bin.fenc")
except:
    pass
