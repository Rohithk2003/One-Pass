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
if number == 1:
    root = Tk()
    new_img = tk_image.PhotoImage(image.open(f"{path}member.png"))
    new_img_label = Label(root, image=new_img, bg="#121212")
    new_img_label.photo = new_img
    root.resizable(False, False)
    file_name_reentry = 'kiren' + ".bin.aes"
    running = running
    al = al
    width_window = 1057

    def alpha():
        global running,al
        if str(enter_alpha['text']) == 'Enter Alphanumeric \npin':
            running = False
            al = True
            enter_alpha.config(text="Enter Number \npin")
            threading.Thread(target=for_alpha).start()
        elif enter_alpha['text'] == 'Enter Number \npin':
            running = True
            al = False
            enter_alpha.config(text="Enter Alphanumeric \npin")
            threading.Thread(target=getting).start()

    def for_alpha():
        global al
        while al:
            try:
                if ent.get():
                    if len(ent.get()) >= 4:
                        a = ent.get()[:4]
                        ent.delete(4, END)
            except:
                pass

    def getting():

        while running:
            try:
                if ent.get():
                    int(ent.get())
                    if len(ent.get()) >= 4:
                        a = ent.get()[:4]

                        ent.delete(4, END)
            except ValueError:
                a = str(ent.get())
                d = list(map(str, a))
                f = 0
                for i in d:
                    if i.isalpha():
                        f = d.index(i)
                ent.delete(f, END)

    enter_alpha = Button(root, text='Enter Alphanumeric \npin', fg="#2A7BCF",
                         activeforeground="#2A7BCF",
                         bg="#121212", command=alpha,
                         activebackground="#121212",  bd=0, borderwidth=0, font=("Consolas", 14, UNDERLINE))
    enter_alpha.place(x=150, y=300)
    # adding the check box button

    t1 = threading.Thread(target=getting)

    width_window = 400
    height_window = 400
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2
    root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
    root.title("Change Details")
    root.config(bg="#121212")

    new_username = Label(root, text="New Username", font=("Segoe Ui", 13),
                         fg="white", bg="#121212")
    new_password = Label(root, text="New Password", font=("Segoe Ui", 13),
                         fg="white", bg="#121212")
    new_pin = Label(root, text="PIN:", font=("Segoe Ui", 13),
                    fg="white", bg="#121212")
    ent = Entry(root)
    new_username_entry = Entry(root)
    new_password_entry = Entry(root, show="*")

    new_img_label.place(x=130, y=0)
    new_username.place(x=50, y=200-50)
    new_password.place(x=50, y=250-50)
    new_pin.place(x=50, y=300-50)
    ent.place(x=200, y=250)
    new_username_entry.place(x=200, y=203-50)
    new_password_entry.place(x=200, y=250 + 3-50)

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

    unhide_img = tk_image.PhotoImage(image.open(f"{path}eye.png"))

    show_both_12 = Button(
        root,
        image=unhide_img,
        bd=0,
        command=lambda: password_sec(new_password_entry, show_both_12),
        fg="white",
        bg="#121212",
        highlightcolor="#121212",
        activebackground="#121212",
        activeforeground="white",
        relief=RAISED,
    )
    show_both_12.place(x=340, y=245-50)

    save = Button(root, text='Save!', font=("Segoe Ui", 13), fg='white', bg="#121212", command=lambda: change(
        root, object, email, password1, username12, str(
            new_password_entry.get()), str(new_username_entry.get()),
        original_password, main_pass))
    save.place(x=50, y=300)
    t1.start()

    root.mainloop()

else:
    pass
