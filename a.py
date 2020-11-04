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
import os
import sys
from tkinter import messagebox
import os.path
import atexit
import ctypes
import time
from tkinter.ttk import *
from cryptography.fernet import Fernet
from datetime import datetime
from geopy.geocoders import Nominatim
import geocoder
import socket
import pytz
from time import gmtime, strftime
from Text import *
import hashlib
import base64
from passlib.hash import pbkdf2_sha256
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
geolocator = Nominatim(user_agent="geoapiExercises")
"------------------------------------main tkinter window------------------------------------"

bufferSize = 64 * 1024
root = Tk()
pygame.init()  # main windows were the login screen and register screen goes
root.title("ONE-PASS-MANAGER")
root.config(bg="black")
root23 = Style()
root23.theme_use("alt")
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
my_cursor.execute("create database if not exists  USERS DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci")
my_cursor.execute("use USERS")
my_cursor.execute("create table if not exists data_input (username varchar(100) primary key,email_id varchar(100),password  blob,salt blob)")

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
def create_key(password,message):
    password_key = password.encode()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=999999,backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password_key))
    message_encrypt = message.encode()
    f = Fernet(key)
    encyrpted = f.encrypt(message_encrypt)
    return encyrpted,salt
def retreive_key(password,byte,de):
    password_key = password.encode()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=de,iterations=999999,backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password_key))
    f = Fernet(key)
    decrypted = f.decrypt(byte)
    return decrypted
def delete_file(file):
    try:
        os.remove(file)
    except:
        return "error"


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
        os.unlink(file)
        messagebox.showinfo("OTP", "2 minutes to verify otp send to email")

    def change_password(email, password1, username12):
        root = Tk()
        root.title("Change Password")
        new_username = Label(root, text="New Username")
        new_password = Label(root, text="New Password")
        new_username_entry = Entry(root)
        new_password_entry = Entry(root,show='*')
        new_username.grid(row=1, column=0)
        new_password.grid(row=2, column=0)
        file_name_reentry = username12 + ".bin.fenc"
        new_username_entry.grid(row=1, column=1)
        new_password_entry.grid(row=2, column=1)
        my_cursor.execute(
            "select password,salt from data_input where email_id = (%s)", (email,)
        )
        values_password = my_cursor.fetchall()
        password_decrypt = ""
        for i in email:
            if i == "@":
                break
            else:
                password_decrypt += i
        password_decrypt += password1
        has = 0
        salt = 0
        decrypted_string = ''
        for i in values_password:
                has = i[0]
                salt = i[1]
            
        try:
            string = retreive_key(password_decrypt,has,salt)
            for i in string:
                if i == '@':
                    break
                else:
                    decrypted_string += i
        except:
            messagebox.showinfo('Error','Wrong Recovery email password')
        re_hash = pbkdf2_sha256.hash(decrypted_string)
        def change():
                        pyAesCrypt.decryptFile(
                            file_name_reentry,
                            username12 + ".bin",
                            re_hash,
                            bufferSize,
                        )
                        f = open(username12 + ".bin", "r")
                        line = pickle.load(f)
                        for i in line:
                            if i[0] == username12:
                                i[1] = str(new_password_entry.get())
                        os.remove(username12 + ".bin")
                        f = open(username12 + ".bin", "r")
                        pickle.dump(line,f)
                        f.close()
                        my_cursor.execute("delete from data_input where username=(%s)", (username12,))
                        new_salt = str(new_password_entry.get()) + "@" + password_decrypt
                        re_hash_new = pbkdf2_sha256.hash(str(new_password_entry.get()))
                        re_encrypt,new_salt = create_key(password_decrypt, re_hash_new)
                        pyAesCrypt.encryptFile(
                            username12 + ".bin",
                            str(new_username_entry.get()) + ".bin.fenc",
                            re_hash_new,
                            bufferSize,
                        )
                        my_cursor.execute(
                            "insert into data_input values(%s,%s,%s,%s)",
                            (str(new_username_entry.get()), email, re_encrypt,new_salt),
                        )
                        if os.path.exists(str(new_username_entry.get()) + '.bin.fenc'):
                                            os.remove(username12 +'.bin')
                                            os.remove(file_name_reentry)
        change_button = Button(root,text='Change',command=change)
        change_button.grid(row=3,column=0,columnspan=1)
    def Verification(password, otp_entry, email, email_password, username12):
        ot = str(otp_entry)
        if ot !='':
            pyAesCrypt.decryptFile(
                "otp.bin.fenc", "otp_decyrpted.bin", password, bufferSize
            )
            f11 = open("otp_decyrpted.bin", "rb")
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
                messagebox.showinfo('Error',"Incorrect OTP Please verify it again")
                otp_entry.delete(0,END)
        else:
            messagebox.showinfo('Error','Please provide the OTP  send to your email')
    def forgot_password(OTP, email, username):
        try:
            global running
            running = True
            SUBJECT = "OTP verification for ONE-PASS-MANAGER"
            otp = ('Hey ' + username + ' Your one time password is ' + OTP)
            msg = "Subject: {}\n\n{}".format(SUBJECT, otp)
            s = smtplib.SMTP("smtp.gmail.com", 587)
            s.starttls()
            s.login("rohithk652@gmail.com", "rohithk2003")
            s.sendmail("rohithk652@gmail.com", email, msg)
        except:
            messagebox.showinfo("Error", "Please Connect to the internet \n then retry")
            sys.exit()

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
            OTP_secure =  phashlib.sha512(OTP.encode()).hexdigest()
            l = list(OTP_secure)
            f = open("otp.bin", "wb")
            pickle.dump(l, f)
            f.close()
            generate_key1("otp.bin")
            forgot_password(OTP_secure, recover_email_entry_verify, username_verify)


    forgot_password_button = Button(window, text="verify", command=lambda: main(key))
    forgot_password_button.grid(row=5, column=1)


def button(social_media, username, password):
    file_name = str(username) + 'decrypted.bin'
    if os.path.exists(file_name):
        root = Tk()
        width_window = 300
        height_window = 300
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        f1 = open(file_name,'rb')
        line = pickle.load(f1)
        title1 = social_media + "Account"
        root.title(title1)
        req = []
        length = len(line)
        for i in range(1,length):
            if i[2] == social_media:
                req.append(i)
            else:
                messagebox.showinfo('Error','No ' + social_media + ' Account exist \nPlease create a facebook account')
        social_media_active_username = req[0][0]
        social_media_active_password = req[0][1]
        text,text1 = 'username','password'
        social_media_active_label = Label(root,text=social_media_active_username)
        social_media_active_pass_label = Label(root,text=social_media_active_password)
        display_text = 'Your' + social_media + 'account is'
        display_text.grid(row=0, column=0,columnspan=1)
        text.grid(row=1,column=0)
        text1.grid(row=2,column=0)
        social_media_active_label.grid(row=1,column=1)
        social_media_active_pass_label.grid(row=2,column=1)
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
        title = social_media + "Login"
        second.title(title)
        login_text1 = "Please provide " + social_media + " account and password"
        text_social = social_media + "Username:"
        text_pass_social = social_media + 'Password:'

        username1 = Label(second, text=text_social)
        password1 = Label(second, text=text_pass_social)
        username1_entry = Entry(second)
        password1_entry = Entry(second, show="*")
        login_text = Label(second, text=login_text1)
        username1.grid(row=2, column=0)
        password1.grid(row=3, column=0)
        username1_entry.grid(row=2, column=1)
        password1_entry.grid(row=3, column=1, columnspan=2)
        username_list = []

        def save():
            username_social_media = str(username1_entry.get())
            password_social_media = str(password1_entry.get())
            l = str(username) + 'decrypted.bin'
            f = open(l,'rb')
            line = pickle.load(f)
            list = [username_social_media, password_social_media,social_media]
            line.append(list)
            f.close()
            os.remove(str(username) + 'decrypted.bin')
            f = open(str(username) + 'decrypted.bin','wb')
            pickle.dump(line,f)
            f.close()
            root = Tk()
            root.withdraw()
            messagebox.showinfo('Success','Your account has been saved')
            root.destroy()
            win = pygame.display.set_mode((800,600))
            gameloop(win,username,password)
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
        text_facebook = Testing("Facebook",45 + facebook.get_width() - 100 + 10,25 + facebook.get_height() + 10,a,'comic.ttf',30,black)
        text_facebook.object()
        text_facebook.blit()

        if (
            mouse[0] == 1
            and 20 < mouse_pos[0] < 20 + facebook.get_width()
            and 20 < mouse_pos[1] < 20 + facebook.get_height()
        ):
            quitting = False
            pygame.quit()
            button("Facebook", username, password)
            break
        pygame.display.update()


def login():
    login_window = Tk()
    width_window = 300
    sending = False
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
    Style().theme_use("alt")

    def login_checking():
        sending = False
        testing = False
        password = str(pass_entry.get())
        username = str(input_entry.get())
        my_cursor.execute(
            "select email_id from data_input where username = (%s)", (username,)
        )
        l = my_cursor.fetchall()
        email_sending = ""
        for i in l:
                    email_sending = i[0]
        file_name = str(username)
        for_hashing_both = password + username
        main_password = hashlib.sha512(for_hashing_both.encode()).hexdigest()
        try:
            pyAesCrypt.decryptFile(
                    file_name + ".bin.fenc",
                    file_name + "decrypted" + ".bin",
                    main_password,
                    bufferSize,
                )
            testing = True
            sending = True
        except:
             testing = False
             root = Tk()
             root.withdraw()
             messagebox.showinfo("Error", "Wrong Password or Username")
             root.destroy()
        if testing:
            d = pygame.display.set_mode((800, 600))
            gameloop(d, str(username), main_password)
        if sending:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            g = geocoder.ip("me")
            ip1 = g.latlng
            location = geolocator.reverse(ip1, exactly_one=True)
            address = location.raw["address"]
            city = address.get("city", "")
            country = address.get("country", "")
            time_now = strftime("%H:%M:%S", gmtime())
            date = datetime.today().strftime("%Y-%m-%d")
            SUBJECT = "ONE-PASS login on " + " " + date
            otp = (
                "Hey"
                + " "
                + username
                + "!"
                + "\n"
                + "It looks like someone logged into your account from a device"
                + " "
                + hostname
                + " "
                + "on "
                + date
                + " at "
                + time_now
                + "."
                + " The login took place somewhere near "
                + city
                + ","
                + country
                + "(IP="
                + ip_address
                + ")."
                + "If this was you,please disregard this email.No further action is needed \nif it wasn't you please change your password"
                + "\n"
                + "Thanks,\nONE-PASS"
            )
            msg = "Subject: {}\n\n{}".format(SUBJECT, otp)
            s = smtplib.SMTP("smtp.gmail.com", 587)
            s.starttls()
            s.login("rohithk652@gmail.com", "rohithk2003")
            s.sendmail("rohithk652@gmail.com", email_sending, msg)


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
        checking = True
        replica = True
        if len(password_register) < 5 or len(email_password_register) < 5:
            win = Tk()
            win.withdraw()
            messagebox.showinfo("Error","Please provide a valid password greeter than 7 characters.")
            win.destroy()
            checking = False
        if checking:
            word = email_id_register.split()
            original = ""
            for p in word:
                for i in p:
                    if i == "@":
                        break
                    else:
                        original += i
            main1 = original + email_password_register
            static_salt_password = password_register +"@" + main1
            cipher_text,salt_for_decryption = create_key(main1,static_salt_password)
            try:
                my_cursor.execute("insert into  data_input values (%s,%s,%s,%s)",(username_register,email_id_register,cipher_text,salt_for_decryption))
            except:
                 roo1 = Tk()
                 roo1.withdraw()
                 messagebox.showerror("Error", "Username already exists")
                 roo1.destroy()
                 replica = False
            if replica:
                login_window1.destroy()
                for_hashing = password_register + username_register
                hash_pass = 
                file_name = username_register + ".bin"
                list = [[username_register,password_register]]
                f = open(file_name, "wb")
                pickle.dump(list,f)
                f.close()
                pyAesCrypt.encryptFile(
                    file_name, file_name + ".fenc", hash_pass, bufferSize
                )
                os.remove(file_name)
                windows = Tk()
                windows.withdraw()
                messagebox.showinfo('Success','Your account has been created')
                windows.destroy()
                d = pygame.display.set_mode((800,600))
                gameloop(d,username_register,password_register)
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
