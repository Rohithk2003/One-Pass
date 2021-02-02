import base64
import os
import random
import string
import threading
from tkinter import *
from tkinter import messagebox

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

alphabet = string.ascii_lowercase
upper_alpha = string.ascii_uppercase
key = 6


# password generator


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


def pass_generator(entry):
    import pyperclip
    de = Toplevel()
    de.focus_set()
    width_window = 400
    height_window = 200
    screen_width = de.winfo_screenwidth()
    screen_height = de.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2

    de.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
    de.title("Generate Password")
    de.config(background='black')
    Label(de, foreground='white', background='black', font=(
        'Segoe UI', 10), text="Length:").place(x=100, y=60)
    Label(de, foreground='white', background='black', font=(
        'Segoe UI', 10), text="Strength:").place(x=100, y=100)
    length = Scale(de, length=174, from_=6, to=15, sliderrelief=FLAT, highlightcolor='black', troughcolor='black',
                   resolution=1, orient='horizontal')
    length.place(x=160, y=60)

    def pd(value):
        ok.config(command=lambda: threading.Thread(
            target=display, args=(length.get(), value)).start())

    var = StringVar()
    d = Radiobutton(de, text='Strong', variable=var, tristatevalue=0,
                    value='HIGH', command=lambda p='HIGH': pd(p))
    d.place(x=160, y=100)
    d1 = Radiobutton(de, text='Medium', variable=var, tristatevalue=0,
                     value='MEDIUM', command=lambda p='MEDIUM': pd(p))
    d1.place(x=220, y=100)
    d2 = Radiobutton(de, text='Low', variable=var, tristatevalue=0,
                     value='LOW', command=lambda p='LOW': pd(p))
    d2.place(x=290, y=100)
    de.grab_set()
    ok = Button(de, text="Generate", fg='white', bg='black')
    ok.place(x=160, y=130)

    def quitting(entry, value):
        entry.delete(0, END)
        entry.insert('0', value)
        de.destroy()

    def copy_clip(msg):
        pyperclip.copy(msg)
        a = Tk()
        a.withdraw()
        messagebox.showinfo(
            "Copied", "Password has been copied to your clipboard")
        a.destroy()
        de.grab_set()

    def display(length, strength):
        if length == '' or strength == '':
            messagebox.showerror("Error", "Please fill the details")

        try:
            if int(length) > 5:
                if int(length) <= 15:
                    try:
                        a = string.ascii_lowercase
                        d = string.ascii_uppercase
                        spec = '@#$%*!_?\/)([]}{'
                        numbers = "0123456789"
                        password = ""
                        if strength == 'HIGH':
                            letters = a + d + spec + numbers
                            password = "".join(random.sample(letters, length))
                        elif strength == "MEDIUM":
                            letters = a + spec + numbers
                            password = "".join(random.sample(letters, length))
                        else:
                            letters = a + numbers
                            password = "".join(random.sample(letters, length))

                        new_label = Entry(
                            de, foreground='green', font=('Segoe UI', 12))
                        new_label.place(x=160, y=155)
                        new_label.insert(0, password)
                        copy = Button(de, text="Copy", font=(
                            'Segoe UI', 10), command=lambda: copy_clip(password))
                        copy.place(x=100, y=153)
                        ok = Button(de, text='Save', font=(
                            'Segoe UI', 10), command=lambda: quitting(entry, password))
                        ok.place(x=350, y=97)
                    except:
                        pass
                else:

                    messagebox.showerror(
                        "Error", "Password length must be less than 19")

                    de.grab_set()
            else:

                messagebox.showerror(
                    "Error", "Password length must be greater than 5")
                de.focus_set()
                de.grab_set()
        except:
            pass


def simple_encrypt(message):
    a = ''
    for i in message:
        if i in alphabet or i in upper_alpha:
            position = alphabet.find(i)
            news = (position + key) % 26
            a += alphabet[news]
        else:
            a += i
    l = []
    for i in range(key):
        if len(l) == 0:
            l.append((base64.urlsafe_b64encode(a.encode())).decode())
        else:
            l[0] = (base64.urlsafe_b64encode(l[0].encode())).decode()
    return l[0]


def simple_decrypt(message):
    a = ''
    l = []
    for i in range(key):
        if len(l) == 0:
            l.append((base64.urlsafe_b64decode(message.encode())).decode())
        else:
            l[0] = (base64.urlsafe_b64decode(l[0].encode())).decode()
    msg = l[0]
    for i in msg:
        if i in alphabet or i in upper_alpha:
            position = alphabet.find(i)
            news = (position - key) % 26
            a += alphabet[news]
        else:
            a += i
    return a


def create_key(password, message):
    password_key = password.encode()  # convert string to bytes
    salt = os.urandom(64)  # create a random 64 bit byte
    # PBKDF2 HMAC- it is a type of algorithm-Password-Based Key Derivation Function 2,HMAC-hashed message
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
