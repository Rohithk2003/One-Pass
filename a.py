"------------------------------------importing modules------------------------------------"
import math
import pickle
import random
import smtplib
from tkinter import *
import glob
import pyAesCrypt
import mysql.connector
import os
import sys
from tkinter import messagebox
import os.path
import atexit
from tkinter.ttk import *
from tkinter.filedialog import *
from tkinter import Frame, Menu
from tkinter import colorchooser
from tkinter import simpledialog
from tkinter import *
from cryptography.fernet import Fernet
from datetime import datetime
from geopy.geocoders import Nominatim
import geocoder
import socket
from time import gmtime, strftime
import hashlib
import base64
from passlib.hash import pbkdf2_sha256
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import ImageTk,Image
from tkinter import filedialog

geolocator = Nominatim(user_agent="geoapiExercises")
"------------------------------------main tkinter window------------------------------------"

bufferSize = 64 * 1024
root = Tk()
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




"------------------------------------ mysql database ------------------------------------"
my_database = mysql.connector.connect(
    host="localhost", user="root", password="rohithk123"
)
my_cursor = my_database.cursor()
my_cursor.execute("set autocommit=1")
my_cursor.execute(
    "create database if not exists  USERS DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci"
)
my_cursor.execute("use USERS")
my_cursor.execute(
    "create table if not exists data_input (username varchar(100) primary key,email_id varchar(100),password  blob,salt blob,no_of_accounts int(120))"
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


class Login:
     def __init__(self,username,password):
         self.username = str(username)
         self.password = str(password)
     def login_checking(self):
             file_name = str(self.username)
             for_hashing_both = self.password + self.username
             main_password =  hashlib.sha512(for_hashing_both.encode()).hexdigest()
             pyAesCrypt.decryptFile(file_name+'.bin.fenc',file_name +'decrypted.bin',main_password,bufferSize)
             return True,main_password
     def windows(self,main_password,window):
        window.destroy()
        window_after(self.username, self.password)
     def verification(self,cursor):
        cursor.execute(
            "select email_id from data_input where username = (%s)", ( self.username,)
        )
        l = my_cursor.fetchall()
        email_sending = ""
        for i in l:
            email_sending = i[0]
        try:
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
            otp = ("Hey"+ " "+ self.username+ "!" + "\n" + "It looks like someone logged into your account from a device"+ " " + hostname + " " + "on "+ date+ " at " + time_now + "."+ " The login took place somewhere near "+ city
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

        except:
            pass


class Register:
    def __init__(self, username, password, email_id, email_password):
        self.username = str(username)
        self.password = str(password)
        self.email_id = str(email_id)
        self.email_password = str(email_password)

    def check_pass_length(self):
        if len(self.password) < 5 or len(self.email_password) < 5:
            return False
        else:
            return True

    def saving(self,object):
        checking = True
        my_cursor.execute("select username from data_input")
        values_username = my_cursor.fetchall()
        for i in values_username:
               for usernames in i :
                    if usernames == self.username:
                        return True



        email_split = ""
        word =self.email_id.split()
        for i in word:
            for a in i:
                if i == "@":
                    break
                else:
                    email_split += i
        main_password = email_split + self.email_password
        static_salt_password = self.password + "@" + main_password
        cipher_text, salt_for_decryption = create_key(
            main_password, static_salt_password
        )
        object.execute(
            "insert into data_input values (%s, %s, %s, %s, 0)",
            (self.username, self.email_id, cipher_text, salt_for_decryption),
        )
        return False

    def creation(self):
        for_hashing = self.password + self.username
        hash_pass = hashlib.sha512(for_hashing.encode()).hexdigest()
        print(hash_pass)
        file_name = self.username + ".bin"
        f = open(file_name, "wb")
        f.close()
        pyAesCrypt.encryptFile(
            file_name, file_name + ".fenc", hash_pass, bufferSize
        )
        os.remove(file_name)
        windows = Tk()
        windows.withdraw()
        messagebox.showinfo("Success", "Your account has been created")
        windows.destroy()
        window_after(self.username, self.password)
        pyAesCrypt.decryptFile(file_name + ".fenc", file_name, hash_pass, bufferSize)


def create_key(password, message):
    password_key = password.encode()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=999999,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_key))
    message_encrypt = message.encode()
    f = Fernet(key)
    encyrpted = f.encrypt(message_encrypt)
    return encyrpted, salt


def retreive_key(password, byte, de):
    password_key = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=de,
        iterations=999999,
        backend=default_backend(),
    )
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
        new_password_entry = Entry(root, show="*")
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
        decrypted_string = ""
        for i in values_password:
            has = i[0]
            salt = i[1]

        try:
            string = retreive_key(password_decrypt, has, salt)
            for i in string:
                if i == "@":
                    break
                else:
                    decrypted_string += i
        except:
            messagebox.showinfo("Error", "Wrong Recovery email password")
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
            pickle.dump(line, f)
            f.close()
            my_cursor.execute(
                "delete from data_input where username=(%s)", (username12,)
            )
            new_salt = str(new_password_entry.get()) + "@" + password_decrypt
            re_hash_new = pbkdf2_sha256.hash(str(new_password_entry.get()))
            re_encrypt, new_salt = create_key(password_decrypt, re_hash_new)
            pyAesCrypt.encryptFile(
                username12 + ".bin",
                str(new_username_entry.get()) + ".bin.fenc",
                re_hash_new,
                bufferSize,
            )
            my_cursor.execute("select no_of_accounts from data_input where username = (%s)",(str(new_username_entry.get())))
            no = my_cursor.fetchall()
            value = 0
            for i in no:
                value = i[0]
            my_cursor.execute(
                "insert into data_input values(%s,%s,%s,%s,%s)",
                (str(new_username_entry.get()), email, re_encrypt, new_salt,value),
            )
            if os.path.exists(str(new_username_entry.get()) + ".bin.fenc"):
                os.remove(username12 + ".bin")
                os.remove(file_name_reentry)

        change_button = Button(root, text="Change", command=change)
        change_button.grid(row=3, column=0, columnspan=1)

    def Verification(password, otp_entry, email, email_password, username12):
        ot = str(otp_entry)
        if ot != "":
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
                messagebox.showinfo("Error", "Incorrect OTP Please verify it again")
                otp_entry.delete(0, END)
        else:
            messagebox.showinfo("Error", "Please provide the OTP  send to your email")

    def forgot_password(OTP, email, username):
        try:
            global running
            running = True
            SUBJECT = "OTP verification for ONE-PASS-MANAGER"
            otp = "Hey " + username + " Your one time password is " + OTP
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
            OTP_secure = hashlib.sha512(OTP.encode()).hexdigest()
            l = list(OTP_secure)
            f = open("otp.bin", "wb")
            pickle.dump(l, f)
            f.close()
            generate_key1("otp.bin")
            forgot_password(OTP, recover_email_entry_verify, username_verify)

    forgot_password_button = Button(window, text="verify", command=lambda: main(key))
    forgot_password_button.grid(row=5, column=1)


def window_after(username,password):
    # sidebar
    root = Tk()
    status_name = False
    sidebar = Frame(root, width=500, bg='#0d0d0d', height=500, relief='sunken', borderwidth=2)
    sidebar.pack(expand=False, fill='both', side='left')
    def testing():
        root.title('Passwords')
        emptyMenu = Menu(root)
        mainarea.config(bg='white')
        root.config(menu=emptyMenu)
        list = mainarea.pack_slaves()
        for l in list:
                    l.destroy()
        image_add = ImageTk.PhotoImage(Image.open('add-button.png'))
        a = Label(mainarea,image=image_add,borderwidth='0')
        a.photo = image_add  
        a.grid(row=6, column=2)

        # gameloop(username,password,mainarea)
    def ap():
        global status_name
        if __name__ == '__main__':
            emptyMenu = Menu(root)
            root.config(menu=emptyMenu)

            list = mainarea.grid_slaves()
            for l in list:
                    l.destroy()
            file = 0
            def newFile():
                global file
                root.title("Untitled - Notepad")
                file = None
                TextArea.delete(1.0, END)


            def openFile():
                global file
                file = askopenfilename(defaultextension=".txt",
                                    filetypes=[("All Files", "*.*"),
                                                ("Text Documents", "*.txt")])
                # check to if there is a file_name
                global status_name
                status_name = file
                if file == "":
                    file = None
                else:
                    root.title(os.path.basename(file) + " - Notepad")
                    TextArea.delete(1.0, END)
                    f = open(file, "r")
                    TextArea.insert(1.0, f.read())
                    f.close()


            def save_as_File(file):
                if file == None:
                    result = messagebox.askyesno('Confirm','Do you want to encrypt your file?')
                    if not result:
                        file = asksaveasfilename(initialfile = 'Untitled.txt', defaultextension=".txt",
                                        filetypes=[("All Files", "*.*"),
                                                    ("Text Documents", "*.txt")])
                        gmm = str(file)
                        password = 'testing'
                        status_name = file
                        if file =="":
                            file = None

                        else:
                            #Save as a new file
                            f = open(file, "w")
                            f.write(TextArea.get(1.0, END))
                            f.close()
                            root.title(os.path.basename(file) + " - Notepad")
                            file = file
                    else:
                        application_window = Tk()

                        a = simpledialog.askstring("Input", "What is  the password?",
                                    parent=application_window)
                        application_window.destroy()
                        file = asksaveasfilename(initialfile = 'Untitled.txt', defaultextension=".txt",
                                            filetypes=[("Text Documents", "*.txt")])
                        gmm = str(file)
                        password = 'testing'
                        status_name = file
                        if file =="":
                            file = None

                        else:
                                #Save as a new file
                                f = open(file, "w")
                                f.write(TextArea.get(1.0, END))
                                f.close()
                                root.title(os.path.basename(file) + " - Notepad")
                                file = file
                        file_name = str(file)
                        f_encrypt = file_name + '.aes'
                        try:
                                pyAesCrypt.encryptFile(file_name, f_encrypt,password,64*1024)
                                os.remove(file)
                        except:
                                pass
            def save_file():
                    global status_name
                    if status_name:
                        f = open(status_name, "w")
                        f.write(TextArea.get(1.0, END))
                        f.close()
                    else:
                        result = messagebox.askyesno('Confirm','Do you want to encrypt your file?')
                        if result == False:
                            file = asksaveasfilename(initialfile = 'Untitled.txt', defaultextension=".txt",
                                        filetypes=[("All Files", "*.*"),
                                                        ("Text Documents", "*.txt")])
                            gmm = str(file)
                            status_name = file
                            if file =="":
                                file = None


                            else:
                                #Save as a new file
                                f = open(file, "w")
                                status_name = True
                                f.write(TextArea.get(1.0, END))
                                f.close()
                                root.title(os.path.basename(file) + " - Notepad")
                        else:
                            file = asksaveasfilename(initialfile = 'Untitled.txt', defaultextension=".txt",
                                            filetypes=[('All Files', "*.*"),("Text Documents", "*.txt")])
                            gmm = str(file)
                            password = 'testing'
                            status_name = file
                            if file =="":
                                file = None

                            else:
                                #Save as a new file
                                f = open(file, "w")
                                f.write(TextArea.get(1.0, END))
                                f.close()
                                root.title(os.path.basename(file) + " - Notepad")
                                file = file
                            file_name = str(file)
                            f_encrypt = file_name + '.aes'
                            try:
                                pyAesCrypt.encryptFile(file_name, f_encrypt,password,64*1024)
                                os.remove(file)
                            except:
                                pass
            def quitApp():
                root.destroy()

            def cut():
                TextArea.event_generate(("<Control-Key-x>"))

            def copy():
                TextArea.event_generate(("<Control-Key-c>"))

            def paste():
                TextArea.event_generate(("<Control-Key-v>"))

            def about():
                messagebox.showinfo("Notepad", "Notepad by Rohithk")

            #Basic tkinter setup
            root.geometry('700x600')
            root.title("Untitled - Notepad")
            root.config(bg = '#0d0d0d')
            #Add TextArea

            font_main = ('freesansbold',12)
            TextArea = Text(mainarea, font=font_main,fg='white',bg='#0d0d0d',insertofftime=600,insertontime=600,insertbackground='black')
            file = None
            TextArea.pack(expand=True, fill=BOTH)
            # Lets create a menubar
            MenuBar = Menu(root)
            status_name = False
            #File Menu Starts
            FileMenu = Menu(MenuBar, tearoff=0)
            # To open new file
            FileMenu.add_command(label="New", command=newFile)

            FileMenu.add_command(label="Open", command = openFile)

            # To save the current file
            FileMenu.add_command(label = "Save", command = lambda: save_file())

            FileMenu.add_command(label = "Save As", command = lambda: save_as_File(file))
            FileMenu.add_separator()
            FileMenu.add_command(label = "Exit", command = quitApp)
            MenuBar.add_cascade(label = "File", menu=FileMenu)
            # File Menu ends
            def select_font(font):
                                size = TextArea['font']
                                word = ''
                                num = ''
                                for i in size:
                                    if i in '1234567890':
                                        num += i
                                word = int(num)
                                new_font_size = (font,word)
                                TextArea.config(font = new_font_size)
            def change_size(size):
                                original_font = font_main[0]
                                new_font = (original_font,size)
                                TextArea.config(font=new_font)

            def change_color():
                my_color = colorchooser.askcolor()[1]
                TextArea.config(fg = my_color)
            def bg_color():
                my_color = colorchooser.askcolor()[1]
                TextArea.config(bg = my_color)
            # Edit Menu Starts
            EditMenu = Menu(MenuBar, tearoff=0)
            #To give a feature of cut, copy and paste
            submenu =   Menu(EditMenu, tearoff=0)
            submenu_size = Menu(EditMenu, tearoff=0)
            submenu.add_command(label='MS Sans Serif',command=lambda :select_font('MS Sans Serif'))
            submenu.add_command(label='Arial',command=lambda :select_font("Arial"))
            submenu.add_command(label="Bahnschrift",command=lambda :select_font("Bahnschrift"))
            submenu.add_command(label="Cambria",command=lambda :select_font("Cambria"))
            submenu.add_command(label="Consolas",command=lambda :select_font("Consolas"))
            submenu.add_command(label="Courier",command=lambda :select_font("Courier"))
            submenu.add_command(label="Century",command=lambda :select_font("Century"))
            submenu.add_command(label="Calibri",command=lambda :select_font("Calibri"))
            submenu.add_command(label="Yu Gothic",command=lambda :select_font("Yu Gothic"))
            submenu.add_command(label="Times New Roman",command=lambda :select_font(a))
            submenu.add_command(label="Sylfaen",command=lambda :select_font(a))
            submenu.add_command(label="Nirmala UI",command=lambda :select_font("Nirmala UI"))
            submenu.add_command(label="Ebrima",command=lambda :select_font("Ebrima"))
            submenu.add_command(label="Comic Sans MS",command=lambda :select_font("Comic Sans MS"))
            submenu.add_command(label="Microsoft PhagsPa",command=lambda :select_font("Microsoft PhagsPa"))
            submenu.add_command(label="Lucida  Console",command=lambda :select_font("Lucida Console"))
            submenu.add_command(label="Franklin Gothic Medium",command=lambda :select_font("Franklin Gothic Medium"))
            submenu.add_command(label="Cascadia Code",command=lambda :select_font("Cascadia Code"))

            list_size_range = [x for x in range(10,31)]
            a = len(list_size_range)
            for i in range(a):
                submenu_size.add_command(label = list_size_range[i],command=lambda:change_size(list_size_range[i]))
            EditMenu.add_command(label='Text Color',command=change_color)
            EditMenu.add_command(label = "Cut", command=cut)
            EditMenu.add_command(label = "Background Color", command=bg_color)
            EditMenu.add_command(label = "Copy", command=copy)
            EditMenu.add_command(label = "Paste", command=paste)
            EditMenu.add_cascade(label = "Font",menu=submenu)
            EditMenu.add_cascade(label = "Size",menu=submenu_size)
            MenuBar.add_cascade(label="Edit", menu = EditMenu)
            def callback(event):
                        save_file()
            def second_callback(event):
                    file = None
                    save_as_File(file)
                    #To Open already existing file
            root.bind('<Control-Key-s>',callback)
            root.bind('<Control-Shift-S>',second_callback)

            # Help Menu Starts
            HelpMenu = Menu(MenuBar, tearoff=0)
            HelpMenu.add_command(label = "About Notepad", command=about)
            MenuBar.add_cascade(label="Help", menu=HelpMenu)

            # Help Menu Ends

            root.config(menu=MenuBar)

            #Adding Scrollbar using rules from Tkinter lecture no 22
            Scroll = Scrollbar(TextArea,orient="vertical")
            Scroll.pack(side='right',fill = Y)


    # main content area
    mainarea = Frame(root, bg='#0d0d0d', width=500, height=500)
    mainarea.pack(expand=True, fill='both', side='right')
    button  = Button(sidebar,text='Passwords',command=testing ,width=20)
    b = Button(sidebar,text='Notes',command=ap,width=20)
    button.grid(row=0,column=1)
    b.grid(row=1,column=1,columnspan=1)
    root.mainloop()

def button(social_media, username, password):
    file_name = str(username) + "decrypted.bin"
    social_media_exists = None
    try:
        f = open(file_name, "rb")
        line = pickle.load(f)
        for i in line:
            if i[2] == social_media:
                social_media_exists = True
    except:
        social_media_exists = False
    if social_media_exists:
        root = Tk()
        width_window = 300
        height_window = 300
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        f1 = open(file_name, "rb")
        line = pickle.load(f1)
        title1 = social_media + "Account"
        root.title(title1)
        req = []
        length = len(line)
        social_media_username = ""
        social_media_password = ""
        for i in line:
            if i[2] == social_media:
                social_media_username = i[0]
                social_media_password = i[1]
        print(social_media_password)
        print(social_media_username)
        social_media_active_label = Label(root, text=social_media_username)
        social_media_active_pass_label = Label(root, text=social_media_password)
        display_text = "Your" + social_media + "account is"
        display_text_label = Label(root, text=display_text)
        display_text_label.grid(row=0, column=0, columnspan=1)
        text_label = Label(root, text="Username:")
        text1_label = Label(root, text="Password:")
        text_label.grid(row=1, column=0)
        text1_label.grid(row=2, column=0)
        social_media_active_label.grid(row=1, column=1)
        social_media_active_pass_label.grid(row=2, column=1)

        def _delete_window():
            try:
                root.destroy()
            except:
                pass

        def back1():
            root.destroy()
            gameloop( str(username), password)

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

    elif social_media_exists == False:
        second = Tk()
        width_window = 300
        height_window = 300
        screen_width = second.winfo_screenwidth()
        screen_height = second.winfo_screenheight()
        title = social_media + "Login"
        second.title(title)
        login_text1 = "Please provide " + social_media + " account and password"
        text_social = social_media + "Username:"
        text_pass_social = social_media + "Password:"

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
            l = str(username) + "decrypted.bin"
            f = open(l, "wb")
            list = []
            line = []
            list.append(username_social_media)
            list.append(password_social_media)
            list.append(social_media)
            line.append(list)
            pickle.dump(line, f)
            print(line)
            f.close()
            os.remove(str(username) + ".bin.fenc")
            pyAesCrypt.encryptFile(
                file_name, str(username) + ".bin.fenc", password, bufferSize
            )
            root = Tk()
            root.withdraw()
            messagebox.showinfo("Success", "Your account has been saved")
            root.destroy()

        saving = Button(second, text="Save", command=save)
        saving.grid(row=4, column=1)


def gameloop(username, password,window):
    image_add = ImageTk.PhotoImage(Image.open('add-button.png'))
    def change():
        pass

    def addaccount():
        window.destroy()
        root1 = Tk()
        name_of_social = Label(root1,text='Name of the social media').grid(row=0,column=1)
        name_of_social_entry = Entry(root1).grid(row=0,column=2)
        username_window = Label(root1,text='Usename:').grid(row=1,column=1)
        password_window = Label(root1,text='Password:').grid(row=2,column=1)
        username_window_entry = Entry(root1).grid(row=1,column=2)
        password_entry = Entry(root1).grid(row=2,column=2)
        new_id = ImageTk.PhotoImage(Image.open('add-button.png'))
        def browsefunc():
                path = filedialog.askopenfilename()
                im = Image.open(path)
                tkimage = ImageTk.PhotoImage(im)
                add_icon_button.config(image=tkimage)
                add_icon_button.image = tkimage


        add_icon_button = Button(root1,image= new_id,borderwidth='0',command=browsefunc)
        add_icon_button.grid(row=0,column=0,rowspan=3)
        def save():
            list = [str(username_window_entry.get()),str(password_entry.get()),str(name_of_social_entry.get())]
            f = open(username+'decrypted.bin','wb')
            pickle.dump()
        save_button = Button(root1,text='Save',command=save)
        # new_image = ImageTk.PhotoImage(Image.open('facebook.png'))
        # add_icon_button.config(image=new_image)
        root.mainloop()
    file = open(str(username) +'decrypted.bin','rb')
    line = file.read()
    word = line.split()
    def account_existing():
        pass
    if len(word) == 0:
        add_button = Button(window,image = image_add,borderwidth='0',command=addaccount)
        add_label = Label(window,text='Add account').grid(row=1, column=1)
        add_button.grid(row=0,column=1)
    else:
        value_to_be = len(word)
        if value_to_be > 4:
                    add_button = Button(window,image = image_add,border='0',command= account_existing())
                    add_button.grid(row=0,column=1,padx=10+100*value_to_be,pady=20+50)
        elif value_to_be > 8:
                    add_button = Button(window,image = image_add,border='0',command=  account_existing())
                    add_button.grid(row=0,column=1,padx=10+100*value_to_be,pady=20+100)
    padx=10
    pady=100


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

    def login_checking():
        password = str(pass_entry.get())
        username = str(input_entry.get())
        login = Login(username,password)
        check,main_password = login.login_checking()
        print(check)
        if check:
            root = Tk()
            root.withdraw()
            messagebox.showinfo('Succes','You have now logged in ')
            root.destroy()
            login.windows(main_password,login_window)
            login.verification(my_cursor)


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
    def register_saving():
        username_register = str(username_entry.get())
        password_register = str(password_entry.get())
        email_id_register = str(email_id_entry.get())
        email_password_register = str(email_password_entry.get())
        register_user = Register(
            username_register,
            password_register,
            email_id_register,
            email_password_register,
        )
        checking = register_user.check_pass_length()
        if checking ==  True:
            registering = register_user.saving(my_cursor)
            print(registering)
            if  registering:
                root = Tk()
                root.withdraw()
                messagebox.showinfo("Error", "Username and email already exists")
                root.destroy()
            if not registering :

                register_user.creation()

        else:
            messagebox.showinfo(
                "Error", "Please provide password greater than 6 characters"
            )
    register_button = Button(login_window1, text="Register", command=register_saving)
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
