# all required modules
import base64
import glob
import hashlib
import os
import os.path
import pickle
import random
import smtplib
import sqlite3
from tkinter import *
# tkinter modules
from tkinter import colorchooser
from tkinter import filedialog as fd
from tkinter import messagebox
from tkinter import simpledialog
from tkinter.ttk import *

from PIL import Image as image
from PIL import ImageTk as tk_image
# for encryption and decryption
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from passlib.hash import pbkdf2_sha256
import pyAesCrypt
from update_check import isUpToDate
from update_check import update

# main window
bufferSize = 64 * 1024
root = Tk()
root.title("ONE-PASS")
#bug fix
width_window = 300
height_window = 300
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = screen_width / 2 - width_window / 2
y = screen_height / 2 - height_window / 2
root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))

# database connection
connection = sqlite3.connect('users.db', isolation_level=None)
my_cursor = connection.cursor()

my_cursor.execute(
    "create table if not exists data_input (username varchar(100) primary key,email_id varchar(100),password  blob,"
    "salt blob,no_of_accounts int(120) default 0) "
)


# global values
catch_error = True
social_media_user_text = ""
social_media_active = False
image_path = ''
exist = False
cutting_value = False
file = 0

#version file
if os.path.exists('version.txt'):
    pass
else:
    with open('version.txt','w') as f:
        f.write('0.5.0')

# for handling login


class Login:
    def __init__(self, username, password):
        self.username = str(username)
        self.password = str(password)

    def login_checking(self):
        if self.username == '' or self.username == ' ':
            root_error = Tk()
            root_error.withdraw()
            messagebox.showerror('Error', 'Cannot have blank username ')
            root_error.destroy()
        elif self.password == '' or self.password == ' ':
            root_error = Tk()
            root_error.withdraw()
            messagebox.showerror('Error', 'Password cannot be empty ')
            root_error.destroy()

        else:
            for_hashing_both = self.password + self.username
            main_password = hashlib.sha512(
                for_hashing_both.encode()).hexdigest()

            try:
                pyAesCrypt.decryptFile(
                    self.username + ".bin.fenc",
                    self.username + "decrypted.bin",
                    main_password,
                    bufferSize,
                )
            except OSError:
                root_error = Tk()
                root_error.withdraw()
                messagebox.showerror(
                    "Error",
                    f"No user exist with  the username {self.username}, Please register or provide the correct username",
                )
                root_error.destroy()
                return False, main_password
            except ValueError:
                root = Tk()
                root.withdraw()
                messagebox.showerror(
                    "Error",
                    f"Wrong password for {self.username}",
                )
                root.destroy()
                return False, main_password
            return True, main_password

    def windows(self, main_password, window, cursor):
        window_after(self.username, main_password)




def checkforupdates( ):
    if isUpToDate('a.py', 'https://github.com/Rohithk2003/One-Pass/blob/master/a.py') and isUpToDate('version.txt','https://raw.githubusercontent.com/Rohithk2003/One-Pass/master/version.txt'):
        result = messagebox.askyesno(
            'Update Available', 'Do you want to update the app?')
        if result == True:
            try:
                messagebox.showinfo(
                    "Updating", 'Please wait while the software is being updated')
                update(
                    a.py, 'https://github.com/Rohithk2003/One-Pass/blob/master/a.py')
                messagebox.showinfo(
                    "Updated", 'The software has been updated please restart to take effect')
            except:
                messagebox.showerror(
                    'No internet Available', 'Please connect to the internet')

        else:
            quit()
    else:
        messagebox.showinfo('Update', 'No update is currently available')


class Register:
    def __init__(self, username, password, email_id, email_password):
        self.username = str(username)
        self.password = str(password)
        self.email_id = str(email_id)
        self.email_password = str(email_password)

    def check_pass_length(self):
        return len(self.password) >= 5 and len(self.email_password) >= 5

    def saving(self, object):
        my_cursor.execute("select username from data_input")
        values_username = my_cursor.fetchall()
        for i in values_username:
            for usernames in i:
                if usernames == self.username:
                    return True

        email_split = ""
        word = self.email_id.split()
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
            "insert into data_input values (?,?,?,?, 0)",
            (self.username, self.email_id, cipher_text, salt_for_decryption),
        )
        return False

    def creation(self,window):
        try:
            window.destroy()
        except:
            pass
        for_hashing = self.password + self.username
        hash_pass = hashlib.sha512(for_hashing.encode()).hexdigest()
        file_name = self.username + ".bin"
        decrypted_file = self.username + 'decrypted.bin'
        with open(file_name, "wb") as f:
            f.close()
        pyAesCrypt.encryptFile(file_name, file_name +
                               ".fenc", hash_pass, bufferSize)
        os.remove(file_name)
        windows = Tk()
        windows.withdraw()
        messagebox.showinfo("Success", "Your account has been created")
        windows.destroy()
        pyAesCrypt.decryptFile(
            file_name + ".fenc", f'{self.username}decrypted.bin', hash_pass, bufferSize)
        window_after(self.username, hash_pass)


# for hashing-encryting and decrypting password and for (forgot_password)
def create_key(password, message):
    password_key = password.encode()
    salt = os.urandom(64)
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
    encrypted = f.encrypt(message_encrypt)
    return encrypted, salt

def delete_social_media_account(real_username,hashed_password):
        with open(real_username+'decrypted.bin','rb') as f:
            try:
                ls = pickle.load(f)
                application_window = Tk()
                application_window.withdraw()
                ask = simpledialog.askstring(
                                "Delete Account", "What is the name of the account to be deleted?", parent=application_window
                            )
                application_window.destroy()
                if ask:
                    result = messagebox.askyesorno('Confirm','Are you sure that you want to delete your account')
                    if result == True:
                        val = simpledialog.askstring('Delete account',f'Please type {real_username}-{ask} to successfully delete your account')
                        if val == f'{real_username}-{ask}':
                            with open(f'{real_username}decrypted.bin','rb') as f:
                                values = pickle.load(f)
                                for i in values:
                                    if i[0] == ask:
                                        inde = values.index(i)
                                        values.pop(inde)
                            try:
                                os.remove(f'{real_username}decrypted.bin')
                            except:
                                pass
                            with open(f'{real_username}decrypted.bin','wb') as f:
                                pickle.dump(values,f)
                                f.close()
                            try:
                                pyAesCrypt.encryptFile(f'{real_username}decrypted.bin',f'{real_username}.bin.fenc',hashed_password,bufferSize)
                                os.remove(f'{real_username}decrypted.bin')
                            except:
                                pass
                            quit()
                        else:
                            quit()
                    else:
                        quit()
                else:
                    quit()
            except:
                messagebox.showerror('Error','You have not  created a account please create one')
        
def delete_main_account(username):
        answer = messagebox.askyesno('Delete Account','Are you sure you want to delete you account')
        if answer == True:
            result = simpledialog.askstring('Delete Account',f'Please type {username}-CONFIRM to delete your account')
            if result == f'{username}-CONFIRM':
                try:
                    os.remove(username+'decrypted.bin')
                    os.remove(username+'.bin.fenc')

                    my_cursor.execute('delete from data_input where username = (?)',(username,))
                    messagebox.showinfo('Account deletion','Success your account has been deleted. See you!!')
                    quit()
                except:
                    pass
            else:
                quit()
        else:
            quit()
def settings(real_username,hashed_password):
    settings_window =Tk()
    check_for_updates = Button(settings_window,text='Check for updates',command=checkforupdates )
    check_for_updates.pack()
    Delete_account_button = Button(settings_window,text='Delete main account',command=lambda:delete_main_account(real_username))
    Delete_social_button = Button(settings_window,text='Delete sub  account',command=lambda:delete_social_media_account(real_username,hashed_password))
    Delete_account_button.pack()
    Delete_social_button.pack()
    settings_window.mainloop()

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
    return decrypted.decode('utf-8')

# forgot password function


def login_password():
    window = Tk()
    window.title("Forgot Password")
    text = "Please provide the recovery email  and recovery email password \n that you provided while creating an " \
           "account "
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
        messagebox.showinfo(
            "OTP", f"An OTP has been sent to your {recover_email_entry}")

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

        main_pass = password_decrypt + password1
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
        # messagebox.showinfo("Error", "Wrong Recovery email password")
        re_hash = hashlib.sha512(value.encode()).hexdigest()

        def change():
            pyAesCrypt.decryptFile(
                file_name_reentry,
                username12 + ".bin",
                re_hash,
                bufferSize,
            )
            with open(username12 + ".bin", "rb") as f:
                try:
                    line = pickle.load(f)

                except:
                    line = []
                f.close()
            os.remove(username12 + ".bin")
            with open(username12 + ".bin", "wb") as f:
                pickle.dump(line, f)
                f.close()
            my_cursor.execute(
                "delete from data_input where username = (?)", (username12,)
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
            new_username_entry_get = str(new_username_entry.get())
            my_cursor.execute(
                "select no_of_accounts from data_input where username = (?)",
                (new_username_entry_get,),
            )
            no = my_cursor.fetchall()
            value = 0
            for i in no:
                value = i[0]
            my_cursor.execute(
                "insert into data_input values(?,?,?,?,?)",
                (str(new_username_entry.get()), email, re_encrypt, new_salt, value),
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
            SUBJECT = "OTP verification for ONE-PASS-MANAGER"
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
            roo1 = Tk()
            roo1.withdraw()
            messagebox.showerror(
                "Error", "No user exist with the provided username")
            roo1.destroy()
        if run:
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
            forgot_password(OTP, recover_email_entry_verify, username_verify)

    forgot_password_button = Button(
        window, text="verify", command=lambda: main(key))
    forgot_password_button.grid(row=5, column=1)


var = 0


def testing(root, mainarea, username, hash_password):
    root.title("Passwords")
    emptyMenu = Menu(root)
    root.geometry('1000x500')
    mainarea.config(bg="white")
    root.config(menu=emptyMenu)

    list = mainarea.pack_slaves()
    for l in list:
        l.destroy()
    gameloop(username, hash_password, mainarea)


def window_after(username, hash_password):
    # sidebar
    root = Tk()
    global var
    global file
    root.geometry('1000x500')
    status_name = False
    sidebar = Frame(
        root, width=500, bg="#0d0d0d", height=500, relief="sunken", borderwidth=2
    )
    sidebar.pack(expand=False, fill="both", side="left")
    file = None

    def ap():
        global status_name
        global password
        global var
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
                    if file.endswith('.bin.fenc'):
                        password = str(simpledialog.askstring(title="Test",
                                                              prompt="Please provide the password"))
                        new_file = os.path.splitext(file)[0]
                        b = os.path.basename(new_file)
                        new_d = os.path.basename(b)
                        filename = new_d + 'decrypted.txt'
                        try:
                            pyAesCrypt.decryptFile(
                                file, filename, password, bufferSize)
                            root.title(os.path.basename(file) + " - Notepad")
                            TextArea.delete(1.0, END)
                            with open(filename, "r") as f:
                                TextArea.insert(1.0, f.read())
                                f.close()
                        except:
                            messagebox.showerror('Error', 'Wrong password')

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
                if root.title()!='Untitled-Notepad':
                    application_window = Tk()
                    application_window.withdraw()
                    a = simpledialog.askstring(
                        "Input", "What is new file name?", parent=application_window
                    )
                    application_window.destroy()
                    print(root.title())
                    if file != None or file != 0 :
                        new_file, file_extension = os.path.splitext(file)
                        b = os.path.basename(new_file)
                        new_d = os.path.basename(b)
                        new_file_name = os.path.basename(b)
                        print(file)
                        f = open(file, 'r')
                        dir = os.path.dirname(file)
                        values = f.read()
                        f.close()
                        os.remove(file)
                        file = (dir) + '/' + a + file_extension
                        with open(file, "w") as f:
                            f.write(values)
                            f.close()
                        TextArea.delete(1.0, END)
                        with open(file, 'r') as f:
                            TextArea.insert(1.0, f.read())
                            f.close()
                        root.title(a + file_extension + " - Notepad")
                    else:
                        messagebox.showinfo('Rename','Please save your file before renaming it')
                        save_as_File()
                else:
                        messagebox.showinfo('Rename','Please save your file before renaming it')
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
                            "Input", "What is  the password for the file?", parent=application_window
                        )
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
                            root.title(os.path.basename(file) + " - Notepad")
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
                        password = str(simpledialog.askstring(title="Password",
                                                              prompt="Please provide the password"))
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
                                file_name, file_name + '.aes', password, 64 * 1024
                            )
                            os.remove(file)
                        except:
                            pass

            def quitApp():
                root.destroy()

            def cut(*event):
                global cutting_value
                if TextArea.selection_get():
                    # grabbing selected text from text area
                    cutting_value = TextArea.selection_get()
                    TextArea.delete("sel.first", 'sel.last')

            def copy(*event):
                global cutting_value
                if TextArea.selection_get():
                    # grabbing selected text from text area
                    cutting_value = TextArea.selection_get()

            def paste(*event):
                if cutting_value:
                    postion = TextArea.index(INSERT)
                    TextArea.insert(postion, cutting_value)

            def about():
                messagebox.showinfo("Notepad", "Notepad by Rohithk-25-11-2020")

            # Basic tkinter setup
            root.geometry("1000x500")
            root.title("Untitled - Notepad")
            root.config(bg="#0d0d0d")
            # Add TextArea
            root.resizable(0, 0)
            font_main = ("freesansbold", 12)
            Scroll_y = Scrollbar(mainarea, orient="vertical")
            Scroll_y.pack(side="right", fill=Y)
            TextArea = Text(
                mainarea,
                font=font_main,
                fg="black",
                insertofftime=600,
                insertontime=600,
                insertbackground="black",
                undo=True,
                yscrollcommand=Scroll_y.set
            )

            Scroll_y.config(command=TextArea.yview)
            TextArea.pack(expand=True, fill=BOTH)

            # create a menubar
            MenuBar = Menu(root)
            status_name = False
            # File Menu Starts
            FileMenu = Menu(MenuBar, tearoff=0)
            # To open new file
            FileMenu.add_command(label="New", command=newFile)

            FileMenu.add_command(label="Open", command=openFile)
            # To save the current file
            FileMenu.add_command(label="Save", command=lambda: save_file())
            FileMenu.add_command(
                label="Save As", command=lambda: save_as_File())
            FileMenu.add_command(label="Rename", command=lambda: rename_file())
            FileMenu.add_separator()
            FileMenu.add_command(label="Exit", command=quitApp)
            MenuBar.add_cascade(label="File", menu=FileMenu)

            # File Menu ends
            def select_font(font):
                size = TextArea["font"]
                num = ''
                for i in size:
                    if i in '1234567890':
                        num += i
                real_size = int(num)
                new_font_size = (font, real_size)
                TextArea.config(font=new_font_size)

            def change_size(size):
                global var
                lb = Label(mainarea, text=var, anchor=E)
                lb.pack(fill=X, side=TOP)
                var = len(str(TextArea.get("1.0", 'end-1c')))
                lb.config(text=var)

                def update(event):
                    var = len(str(TextArea.get("1.0", 'end-1c')))
                    lb.config(text=var)
                TextArea.bind('<KeyPress>', update)
                TextArea.bind("<KeyRelease>", update)
                original_font = TextArea["font"]
                find_font = ''
                var = ''
                for i in original_font:
                    if i == ' ' or i.isalpha():
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
                    "start", bg="yellow", fg="black")
                try:
                    TextArea.tag_add("start", "sel.first", "sel.last")
                except TclError:
                    pass

            def secondary(*event):
                replace_window = Toplevel(mainarea)
                replace_window.focus_set()
                replace_window.grab_set()
                replace_window.title('Replace')
                replace_entry = Entry(replace_window)
                find_entry_new = Entry(replace_window)
                find_entry_new.grid(row=0, column=0)
                replace_button = Button(replace_window, text='Replace',
                                        command=lambda: replacenfind(find_entry_new.get(), replace_window,
                                                                     str(replace_entry.get())))
                replace_button.grid(row=1, column=1)
                replace_entry.grid(row=1, column=0)

            def primary(*event):
                find_window = Toplevel(mainarea)
                find_window.geometry('100x50')
                find_window.focus_set()
                find_window.grab_set()
                find_window.title('Find')
                find_entry = Entry(find_window)
                find_button = Button(find_window, text='Find', command=lambda: find(
                    find_entry.get(), find_window))
                find_entry.pack()
                find_button.pack(side='right')

            def replacenfind(value, window, replace_value):
                text_find = str(value)
                index = '1.0'
                TextArea.tag_remove('found', '1.0', END)
                if value:
                    while 1:
                        index = TextArea.search(
                            text_find, index, nocase=1, stopindex=END)
                        if not index:
                            break
                        lastidx = '% s+% dc' % (index, len(text_find))
                        TextArea.delete(index, lastidx)
                        TextArea.insert(index, replace_value)
                        lastidx = '% s+% dc' % (index, len(replace_value))
                        TextArea.tag_add('found', index, lastidx)
                        index = lastidx
                    TextArea.tag_config('found', foreground='blue')
                window.focus_set()

            def find(value, window):
                text_find = str(value)
                index = '1.0'
                TextArea.tag_remove('found', '1.0', END)
                if value:
                    while 1:
                        index = TextArea.search(
                            text_find, index, nocase=1, stopindex=END)
                        if not index:
                            break
                        lastidx = '% s+% dc' % (index, len(text_find))
                        TextArea.tag_add('found', index, lastidx)
                        index = lastidx
                    TextArea.tag_config('found', foreground='red')
                window.focus_set()

            def popup_menu(e):
                my_menu.tk_popup(e.x_root, e.y_root)

            try:
                f = TextArea.get()
                if f != '':
                    root.title('*untitled-Notepad')
                else:
                    pass
            except:
                root.title('Untitled-Notepad')
            root.bind('<Control-Key-f>', primary)
            root.bind('<Control-Key-h>', secondary)

            EditMenu = Menu(MenuBar, tearoff=0)
            my_menu = Menu(mainarea, tearoff=0)
            my_menu.add_command(label='Highlight', command=highlight_text)
            my_menu.add_command(label='Copy', command=copy)
            my_menu.add_command(label='Cut', command=cut)
            my_menu.add_command(label='Paste', command=paste)
            mainarea.focus_set()
            a = root.focus_get()
            if a.winfo_class() == 'Frame':
                root.bind('<Button-3>', popup_menu)
            # To give a feature of cut, copy and paste
            highlight_text_button = Button(
                MenuBar, text='highlight', command=highlight_text)
            highlight_text_button.grid(row=0, column=5, sticky=W)
            submenu = Menu(EditMenu, tearoff=0)
            submenu_size = Menu(EditMenu, tearoff=0)
            submenu.add_command(
                label="MS Sans Serif", command=lambda: select_font("MS Sans Serif")
            )
            submenu.add_command(
                label="Arial", command=lambda: select_font("Arial"))
            submenu.add_command(
                label="Bahnschrift", command=lambda: select_font("Bahnschrift")
            )
            submenu.add_command(
                label="Cambria", command=lambda: select_font("Cambria"))
            submenu.add_command(
                label="Consolas", command=lambda: select_font("Consolas")
            )
            submenu.add_command(
                label="Courier", command=lambda: select_font("Courier"))
            submenu.add_command(
                label="Century", command=lambda: select_font("Century"))
            submenu.add_command(
                label="Calibri", command=lambda: select_font("Calibri"))
            submenu.add_command(
                label="Yu Gothic", command=lambda: select_font("Yu Gothic")
            )
            submenu.add_command(label="Times New Roman",
                                command=lambda: select_font("Times New Roman"))
            submenu.add_command(
                label="Sylfaen", command=lambda: select_font("Sylfaen"))
            submenu.add_command(
                label="Nirmala UI", command=lambda: select_font("Nirmala UI")
            )
            submenu.add_command(
                label="Ebrima", command=lambda: select_font("Ebrima"))
            submenu.add_command(
                label="Comic Sans MS", command=lambda: select_font("Comic Sans MS")
            )
            submenu.add_command(
                label="Microsoft PhagsPa",
                command=lambda: select_font("Microsoft PhagsPa"),
            )
            submenu.add_command(
                label="Lucida  Console", command=lambda: select_font("Lucida Console")
            )
            submenu.add_command(
                label="Franklin Gothic Medium",
                command=lambda: select_font("Franklin Gothic Medium"),
            )
            submenu.add_command(
                label="Cascadia Code", command=lambda: select_font("Cascadia Code")
            )
            submenu_size.add_command(
                label='6', command=lambda: change_size(6), )
            submenu_size.add_command(
                label='7', command=lambda: change_size(7), )
            submenu_size.add_command(
                label='8', command=lambda: change_size(8), )
            submenu_size.add_command(
                label='9', command=lambda: change_size(9), )
            submenu_size.add_command(
                label='10', command=lambda: change_size(10), )
            submenu_size.add_command(
                label='11', command=lambda: change_size(11), )
            submenu_size.add_command(
                label='12', command=lambda: change_size(12), )
            submenu_size.add_command(
                label='13', command=lambda: change_size(13), )
            submenu_size.add_command(
                label='14', command=lambda: change_size(14), )
            submenu_size.add_command(
                label='15', command=lambda: change_size(15), )
            submenu_size.add_command(
                label='16', command=lambda: change_size(16), )
            submenu_size.add_command(
                label='17', command=lambda: change_size(17), )
            submenu_size.add_command(
                label='18', command=lambda: change_size(18), )
            submenu_size.add_command(
                label='19', command=lambda: change_size(19), )
            submenu_size.add_command(
                label='20', command=lambda: change_size(20), )
            submenu_size.add_command(
                label='21', command=lambda: change_size(21), )
            submenu_size.add_command(
                label='22', command=lambda: change_size(22), )
            submenu_size.add_command(
                label='23', command=lambda: change_size(23), )
            submenu_size.add_command(
                label='24', command=lambda: change_size(24), )
            submenu_size.add_command(
                label='25', command=lambda: change_size(25), )
            submenu_size.add_command(
                label='26', command=lambda: change_size(26), )
            submenu_size.add_command(
                label='27', command=lambda: change_size(27), )
            submenu_size.add_command(
                label='28', command=lambda: change_size(28), )
            submenu_size.add_command(
                label='29', command=lambda: change_size(29), )
            submenu_size.add_command(
                label='30', command=lambda: change_size(30), )

            EditMenu.add_command(label="Text Color", command=change_color)
            EditMenu.add_command(label="Background Color", command=bg_color)
            EditMenu.add_command(label="Cut", command=cut,
                                 accelerator='(Ctrl+x)')
            EditMenu.add_command(label="Copy", command=copy,
                                 accelerator='(Ctrl+c)')
            EditMenu.add_command(
                label="Paste", command=paste, accelerator='(Ctrl+v)')
            EditMenu.add_command(
                label="Find", command=primary, accelerator='(Ctrl+f)')
            EditMenu.add_command(
                label="Replace", command=secondary, accelerator='(Ctrl+h)')
            EditMenu.add_command(
                label="Undo", command=TextArea.edit_undo, accelerator='(Ctrl+z)')
            EditMenu.add_command(
                label="Redo", command=TextArea.edit_redo, accelerator='(Ctrl+y)')
            EditMenu.add_cascade(label="Font", menu=submenu)
            EditMenu.add_cascade(label="Size", menu=submenu_size)
            MenuBar.add_cascade(label="Edit", menu=EditMenu)

            def callback(event):
                save_file()

            def second_callback(event):
                file = None
                save_as_File(file)
                # To Open already existing file

            # bindings
            root.bind("<Control-Key-s>", callback)
            root.bind("<Control-Shift-S>", second_callback)
            root.bind('<Control-Key-x>', cut)
            root.bind('<Control-Key-c>', copy)
            root.bind('<Control-Key-v>', paste)
            # Help Menu Starts
            HelpMenu = Menu(MenuBar, tearoff=0)
            HelpMenu.add_command(label="About Notepad", command=about)
            MenuBar.add_cascade(label="Help", menu=HelpMenu)

            # Help Menu Ends
            MenuBar.pack_propagate(0)
            sidebar.pack_propagate(0)
            root.config(menu=MenuBar)

    # main content area
    mainarea = Frame(root, bg="#0d0d0d", width=500, height=500)
    mainarea.pack(expand=True, fill="both", side="right")
    button = Button(sidebar, text="Passwords", width=20, command=lambda: testing(
        root, mainarea, username, hash_password))
    b = Button(sidebar, text="Notes", command=ap, width=20)
    button.grid(row=0, column=1)
    b.grid(row=1, column=1, columnspan=1)
    file = username + '.cfg'
    settings_button = Button(sidebar, text="Settings",  width=20,command=lambda:settings(username,hash_password))
    settings_button.grid(row=10, column=1, columnspan=1)
    root.mainloop()


def gameloop(username, hashed_password, window):
    global image_path
    window.grid_propagate(0)

    file_name = username + 'decrypted.bin'
    my_cursor.execute(
        'select no_of_accounts from data_input where username = (?)', (username,))
    no_accounts = my_cursor.fetchall()
    add = 0
    for i in no_accounts:
        add = int(i[0])
    exist = False


    def addaccount():
        root1 = Toplevel()
        name_of_social = Label(root1, text="Name of the social media")
        name_of_social.grid(row=0, column=1)
        name_of_social_entry = Entry(root1)
        name_of_social_entry.grid(row=0, column=2)
        username_window = Label(root1, text="Usename:")
        username_window.grid(row=1, column=1)
        password_window = Label(root1, text="Password:")
        password_window.grid(row=2, column=1)
        username_window_entry = Entry(root1)
        username_window_entry.grid(row=1, column=2)
        password_entry = Entry(root1)
        password_entry.grid(row=2, column=2)
        image_path = ''

        def browsefunc():
            global image_path
            try:
                image_path = fd.askopenfilename()
                im = image.open(image_path)
                tkimage = tk_image.PhotoImage(im)
                add_icon_button.config(image=tkimage)
                add_icon_button.photo = tkimage
            except:
                pass

        new_id = tk_image.PhotoImage(image.open("add-button.png"))
        add_icon_button = Button(
            root1, image=new_id, borderwidth="0", command=browsefunc)
        add_icon_button.photo = new_id
        add_icon_button.grid(row=0, column=0, rowspan=3)

        def save():
            global image_path
            global exist
            list_account = [str(username_window_entry.get()), str(
                password_entry.get()), str(name_of_social_entry.get()), image_path]

            verifying = verify(username_window_entry.get(),
                               name_of_social_entry.get())
            if verifying:
                messagebox.showerror('Error', 'The account already exists')

            elif not exist:
                name_file = username + "decrypted.bin"
                with open(name_file, "rb") as f:
                    try:
                        line = pickle.load(f)
                    except:
                        line = []
                    line.append(list_account)
                    f.close()
                with open(name_file, 'wb') as f1:
                    pickle.dump(line, f1)
                    f.close()
                os.remove(username + '.bin.fenc')
                pyAesCrypt.encryptFile(
                    name_file, username + '.bin.fenc', hashed_password, bufferSize)
                messagebox.showinfo('Success', 'Your account has been saved')
                my_cursor.execute(
                    'select no_of_accounts from data_input where username = (?)', (username,))
                val = my_cursor.fetchall()
                to_append = 0
                for i in val:
                    real_accounts = int(i[0])
                    to_append = real_accounts + 1
                my_cursor.execute('update data_input set no_of_accounts =(?) where username =(?)',
                                  (to_append, username))
            elif not verifying:
                messagebox.showerror(
                    'Error', 'Account with the username already exist')

        save_button = Button(root1, text="Save", command=save)
        save_button.grid(row=4, column=1)
        root1.mainloop()


    def change_icon(button, usernam, users_username):
        file_name = users_username + 'decrypted.bin'
        l = [(32, 32), (16, 16)]
        image_path = fd.askopenfilename(filetypes=[("image", "*.png"), ("image", "*.jpeg"), ("image", "*.jpg")],
                                        title='Add icon')
        f = open(file_name, 'rb')
        pad = pickle.load(f)
        path = ''
        for i in pad:
            if i[0] == usernam:
                path = i[3]
        if path == '':
            path_im = image.open('photo.png')
        else:
            path_im = image.open(path)

        try:
            im = image.open(image_path)
            if im:
                if im.size in l:
                    for i in pad:
                        if i[0] == usernam:
                            print(i[0])
                            print(usernam)
                            i[3] = image_path
                    f.close()
                    with open(file_name, 'wb') as f1:
                        pickle.dump(pad, f1)
                        f1.close()
                    os.remove(users_username + '.bin.fenc')
                    pyAesCrypt.encryptFile(
                        file_name, users_username + '.bin.fenc', hashed_password, bufferSize)
                    new_tk = tk_image.PhotoImage(im)
                    button.config(image=new_tk)
                    button.photo = new_tk
                else:
                    messagebox.showerror(
                        'Error', 'Please provide icon size of 32x32 or 16x16')
                    im = image.open('photo.png')
                    new_tk = tk_image.PhotoImage(im)
                    button.config(image=new_tk)
                    button.photo = new_tk
                    image_path = fd.askopenfilename(
                        filetypes=[("image", "*.png")], title='Add icon')

                    try:
                        im = image.open(image_path)
                    except:
                        im = image.open('photo.png')
                        new_tk = tk_image.PhotoImage(im)
                        button.config(image=new_tk)
                        button.photo = new_tk

        except:
            new_tk = tk_image.PhotoImage(path_im)
            button.config(image=new_tk)
            button.photo = new_tk



    def verify(social_username, social_media):
        try:
            with open(file_name, 'r') as f:
                test_values = pickle.load(f)
                for user in test_values:
                    if user[0] == str(social_username) or user[2] == str(social_media):
                        return True
        except:
            return False

    for num in no_accounts:
        add = int(num[0])
    try:
        with open(username + 'decrypted.bin', 'rb') as f:
            account_fetch = pickle.load(f)
    except:
        account_fetch = []

    i = 0
    try:
        while i < 12:
                social_username = account_fetch[i][0]
                social_password = account_fetch[i][1]
                social_media = account_fetch[i][2]
                image_path_loc = account_fetch[i][3]
                username_label_widget = Label(
                    window, text=f'Username: {social_username}')
                password_label_widget = Label(
                    window, text=f'Password: {social_password}')
                social_media_label = Label(
                    window, text=f'Account Name: {social_media}')
                if image_path_loc:
                    try:
                        tkimage = tk_image.PhotoImage(image.open(image_path_loc))
                    except:
                        tkimage = tk_image.PhotoImage(image.open('photo.png'))
                else:
                    tkimage = tk_image.PhotoImage(image.open('photo.png'))
                default_image_button = Button(window, image=tkimage, borderwidth='0',
                                            command=lambda: change_icon(default_image_button, social_username, username))
                if i <3 :
                    username_label_widget.grid(row=2, column=0 + i,rowspan=1)
                    password_label_widget.grid(row=3, column=0 + i,rowspan=1)
                    social_media_label.grid(row=1, column=0 + i,rowspan=1)
                    default_image_button.photo = tkimage
                    default_image_button.grid(row=0, column=0 + i,rowspan=1)
                    default_image_button.place(x=40+i*250,y= 10)
                    username_label_widget.place(x = 30+i*250,y=110)
                    social_media_label.place(x=30+i*250,y=90)
                    password_label_widget.place(x = 30+i*250,y=130)

                elif i>=3 and i <6:
                    dd = int(i%3) 
                    print(dd)
                    username_label_widget.grid( row=2 +1, column=0 + dd)
                    password_label_widget.grid(row=3 + 1, column=0 + dd)
                    social_media_label.grid(row=1 + 1, column=0 + dd)
                    default_image_button.photo = tkimage
                    default_image_button.grid(row=0 + 1, column=0 + dd)
                    default_image_button.place(x=40+dd*250,y= 170)
                    username_label_widget.place(x = 30+dd*250,y=250)
                    social_media_label.place(x=30+dd*250,y=230)
                    password_label_widget.place(x = 30+dd*250,y=270)
                elif 6 <= i < 9:
                    dd = int(i%6 ) 
                    print('how many')
                    username_label_widget.grid( row=2 +1, column=0 + dd)
                    password_label_widget.grid(row=3 + 1, column=0 + dd)
                    social_media_label.grid(row=1 + 1, column=0 + dd)
                    default_image_button.photo = tkimage
                    default_image_button.grid(row=0 + 1, column=0 + dd)
                    default_image_button.place(x=40+dd*250,y= 300)
                    social_media_label.place(x=30+dd*250,y=380)
                    username_label_widget.place(x = 30+dd*250,y=400)
                    password_label_widget.place(x = 30+dd*250,y=420)
                i = i+1
    except:
        pass
    image_add = tk_image.PhotoImage(image.open('add-button.png'))

    if add < 3:
        image_add = tk_image.PhotoImage(image.open('add-button.png'))
        add_button_text = Label(window, text='Add Account')
        add_button = Button(
            window,  image=image_add, border="0", compound='top', command=addaccount
        )
        add_button_text.grid(row=2, column=0 + add)
        add_button.photo = image_add
        add_button.place(x=40+add*250,y= 10)
        add_button.grid(row=1, column=0 + add)
    elif 3 <= add < 6:
        image_add = tk_image.PhotoImage(image.open('add-button.png'))
        add_button_text = Label(window, text='Add Account')
        add_button = Button(
            window,  image=image_add, border="0", compound='top', command=addaccount
        )

        add_button.photo = image_add
        d = int(add%4)
        add_button_text.grid(row=5, column=0 + d)
        add_button.grid(row=1 + 3, column=0+d )
        add_button.place(x=40+add*250,y= 300)
    elif add>=6 and add < 9:
        print('hmm')
        image_add = tk_image.PhotoImage(image.open('add-button.png'))
        add_button_text = Label(window, text='Add Account')
        add_button = Button(
            window,  image=image_add, border="0", compound='top', command=addaccount
        )
        add_button.photo = image_add
        d = int(add//4)
        add_button_text.grid(row=3, column=0 + d)
        add_button.grid(row=2, column=0 + d)
        add_button.place(x=40+d*250,y= 300)
        add_button_text.place(x = 20+d*250,y = 340)


    # except:
    #     pass


def login():
    login_window = Tk()

    login_window.title('Login')
    width_window = 400
    height_window = 400
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
    forgot = Button(login_window, text="Forgot Password",
                    command=login_password)
    register_button = Button(
        login_window, text='Register', command= register)

    def password_sec(entry, show_both_1):
        a = entry['show']
        if a == "":
            entry.config(show="*")
            show_both_1['text'] = 'Hide password'
        elif a == '*':
            entry.config(show="")
            show_both_1['text'] = 'Show password'

    show_both_1 = Button(
        login_window,
        text="show password",
        command=lambda: password_sec(pass_entry, show_both_1),
    )

    def login_checking_1():
        my_cursor.execute(
            "select email_id from data_input where username = (?)", (str(input_entry.get()),))
        val_list = my_cursor.fetchall()
        password = str(pass_entry.get())
        username = str(input_entry.get())
        login = Login(username, password)
        if username!='' or password!='':
            check, main_password = login.login_checking()
            if check:
                root = Tk()
                root.withdraw()
                messagebox.showinfo("Succes", "You have now logged in ")
                root.destroy()
                login_window.destroy()
                login.windows(main_password, login_window, my_cursor)
            else:
                pass

    but = Button(login_window, text="Login", command=login_checking_1)
    but.grid(row=7, column=3)

    login.grid(row=2, column=2)
    lbl.grid(row=0, column=2, columnspan=2)
    pass1.grid(row=6, column=2)
    input_entry.grid(row=2, column=3)
    pass_entry.grid(row=6, column=3)
    root.destroy()
    login_window.resizable(False, False)
    register_button.grid(row=7, column=4)
    forgot.grid(row=7, column=2)
    show_both_1.grid(row=6, column=4)


def register(window):
    login_window1 = Tk()
    window.destroy()
    login_window1.resizable(False, False)
    login_window1.title("Register")
    width_window = 400
    height_window = 400
    screen_width = login_window1.winfo_screenwidth()
    screen_height = login_window1.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2

    login_window1.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
    username = Label(login_window1, text="Username:")
    password = Label(login_window1, text="password:")
    email_id = Label(login_window1, text="Recovery Email :")
    email_password = Label(login_window1, text="Recovery Email password")
    username_entry = Entry(login_window1)
    password_entry = Entry(login_window1, show="*")
    email_id_entry = Entry(login_window1)
    email_password_entry = Entry(login_window1, show="*")
    width = login_window1.winfo_screenwidth()
    len1=len(username['text'])
    len2=len(password['text'])
    len3=len(email_id['text'])
    len4=len(email_password['text'])
    # putting the buttons and entries
    username.grid(row=2, column=0)
    password.grid(row=3, column=0)
    email_id.grid(row=4, column=0)
    email_password.grid(row=5, column=0)
    username_entry.grid(row=2, column=1)
    password_entry.grid(row=3, column=1)
    email_id_entry.grid(row=4, column=1)
    email_password_entry.grid(row=5, column=1)
    username.place(x =0,y=150)
    password.place(x =0,y=180)
    email_id.place(x =0,y=250)
    email_password.place(x =0,y=280)
    username_entry.place(x=len4*10,y=150)
    password_entry.place(x=len4*10,y=180)
    email_id_entry.place(x=len4*10,y=250)
    email_password_entry.place(x=len4*10,y=280)
    register_text= Label(login_window1,text='Register',font=('helvetica',30),underline=True)
    register_text.place(x=120,y=50)
    def password_sec(entry, button):
        a = entry['show']
        if a == "":
            entry.config(show="*")
            button['text'] = 'Hide'
        elif a == '*':
            entry.config(show="")
            button['text'] = 'Show'

    show_both_1 = Button(
        login_window1,
        text="show",
        command=lambda: password_sec(password_entry, show_both_1),
    )
    show_both_12 = Button(
        login_window1,
        text="show",
        command=lambda: password_sec(email_password_entry, show_both_12),
    )
    show_both_12.grid(row=5, column=2)
    show_both_1.grid(row=3, column=2)
    show_both_1.place(x=len4*10,y=210)
    show_both_12.place(x=len4*10,y=310)
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
        if checking:
            registering = register_user.saving(my_cursor)
            if registering:
                root2 = Tk()
                root.withdraw()
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
        login_window1, text="Register", command=register_saving)
    register_button.grid(row=6, column=0)
    register_button.place(x=150,y=350)

main = Label(root, text="Welcome to ONE-PASS")
login_text = Label(root, text="Login:")
register_text = Label(
    root, text='Register: ')
reg_button = Button(root, text="Register", command=lambda:register(root))
login_button = Button(root, text="login", command=login  )# added login button

main.grid(row=0, column=1, columnspan=2)
login_button.grid(row=7, column=1, columnspan=2)
login_text.grid(row=6, column=1, columnspan=2)
register_text.grid(row=8, column=1, columnspan=2)
reg_button.grid(row=9, column=1, columnspan=2)
main.place(x=40,y=40)
login_text.place(x=40,y=78)
login_button.place(x=140,y=70)
register_text.place(x=40,y=128)
reg_button.place(x=140,y=120)
root.resizable(False, False)
root.mainloop()

list_file = glob.glob("*decrypted.bin")
for i in list_file:
    converting_str = str(i)
    try:
        os.remove(converting_str)
    except:
        pass
#testing