import mysql.connector as m
import glob
import json
import pickle as p
from mysql.connector.constants import CharacterSet
import pyperclip
from tkscrolledframe import ScrolledFrame
from tkinter import tix
import platform
import threading
import os
# tkinter modules
from PIL import Image as image
from PIL import ImageTk as tk_image
from tkinter import filedialog as fd
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import ttk
from tkinter import *
import time
bufferSize = 64 * 1024
running = True

al = False

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
running = True
al = False
number = 1
master = Tk()
username = 'rohith'
password = 'rohithk123'
username = username
master.title("hello")
password = password
master.config(bg="#121212")
width_window = 1057
height_window = 661
screen_width = master.winfo_screenwidth()
screen_height = master.winfo_screenheight()
x = screen_width / 2 - width_window / 2
y = screen_height / 2 - height_window / 2

master.geometry("%dx%d+%d+%d" %
                         (width_window, height_window, x, y))


# def alpha():
#     global running, al
#     if str(enter_alpha['text']) == 'Enter Alphanumeric pin':
#         running = False
#         al = True
#         enter_alpha.config(text="Enter Number pin")
#         threading.Thread(target=for_alpha).start()
#     elif enter_alpha['text'] == 'Enter Number pin':
#         running = True
#         al = False
#         enter_alpha.config(text="Enter Alphanumeric pin")
#         threading.Thread(target=getting).start()


# def for_alpha():
#     global running, al
#     while al:

#         try:
#             if ent.get():
#                 if len(ent.get()) >= 4:
#                     a = ent.get()[:4]
#                     ent.delete(4, END)
#         except:
#             pass


# def getting():
#     global running, al
#     while running:
#         try:

#             if ent.get():
#                 int(ent.get())
#                 if len(ent.get()) >= 4:
#                     a = ent.get()[:4]

#                     ent.delete(4, END)
#         except ValueError:
#             a = str(ent.get())
#             d = list(map(str, a))
#             f = 0
#             for i in d:
#                 if i.isalpha():
#                     f = d.index(i)
#             ent.delete(f, END)


width_window = 1057
lab = Label(master, text='Provide  a security pin', bg='#121212',
            fg='white', font=("Segoe Ui", 15))
lab.place(x=width_window/2-60-5-10-10, y=100)
lab1 = Label(master, text='This 4 digit  pin is used for further security\nYou cannot recover it.\nIf you lost the pin you may have to reset your account password.',
             bg='#121212', fg='white', justify='center', font=("Segoe Ui", 15))
pintext = Label(master, text="PIN:", bg='#121212', fg='white',
                justify='center', font=("Segoe Ui", 15))
pintext.place(x=width_window/2-130-5-30-10-10, y=248)
lab1.place(x=width_window/2-190-5-60-10, y=150)

ent = Entry(master, width=20, font=("Segoe Ui", 15))
ent.place(x=width_window/2-40-5-5-30-10-10, y=250)
enter_alpha = Button(master, text='Enter Alphanumeric pin', fg="#2A7BCF",
                     activeforeground="#2A7BCF",
                     bg="#121212", 
                     activebackground="#121212",  bd=0, borderwidth=0, font=("Consolas", 14, UNDERLINE))
enter_alpha.place(x=width_window/2+200-30-10-10, y=250)
# adding the check box button
var = IntVar()
check = Checkbutton(master, text="I understand that this security code cannot be recovered once it is lost", font=("Segoe Ui", 14), bg='#121212', fg='white',
                    justify='center', variable=var, activebackground="#121212", activeforeground='white', selectcolor='black')
check.place(x=240-10, y=300)

# t1 = threading.Thread(target=getting)

# t1.start()

# adding the entry widget


# def pin_save():
#     print(var.get())
#     if ent.get():
#         if var.get() == 1:
#             running, al = False, False
#             pin = str(ent.get())
#             values = {}
#             hash_value = hashlib.sha512(
#                 pin.encode()).hexdigest()
#             values[hashlib.sha512(
#                 username.encode()).hexdigest()] = str(hash_value)

#             if os.path.exists("pin.json") and os.stat("pin.json").st_size != 0:
#                 with open("pin.json", "r") as f:
#                     data = json.load(f)
#                 data[hashlib.sha512(
#                     username.encode()).hexdigest()] = str(hash_value)
#                 with open("pin.json", 'w') as f:
#                     json.dump(data, f)
#             else:
#                 with open('pin.json', 'w') as f:
#                     json.dump(values, f)
#             main_pass = username + str(pin)
#             static_salt_password = simple_encrypt(password)
#             cipher_text, salt_for_decryption = create_key(
#                 main_pass, static_salt_password
#             )
#             my_cursor.execute("insert into userspin values(%s,%s,%s)",
#                               (username, cipher_text, salt_for_decryption))
#             if os.path.exists("settings.json") and os.stat("settings.json").st_size != 0:
#                 with open("settings.json", "r") as f:
#                     value = json.load(f)
#                 value[username] = 0
#                 with open("settings.json", 'w') as f:
#                     json.dump(value, f)
#             else:
#                 value = {}
#                 value[username] = 0
#                 with open("settings.json", 'w') as f:
#                     json.dump(value, f)
#             a = Tk()
#             a.withdraw()
#             messagebox.showinfo(
#                 'Saved', "PIN has been successfully registered")
#             a.destroy()
#             master.switch_frame(
#                 main_window, username, password)
#         else:
#             messagebox.showinfo('Error', 'Checkbox is not ticked')
#     else:
#         messagebox.showinfo('Error', 'Please provide a pin')


# adding the save button
save = Button(master, text="S A V E", fg="#292A2D",
              activeforeground="#292A2D",
              bg="#994422", 
              activebackground="#994422", height=1, width=10, bd=0, borderwidth=0, font=("Consolas", 14))
save.place(x=width_window/2-30-5-10-10, y=350)
master.mainloop()