import mysql.connector as m
import glob
import pickle as p
from mysql.connector.constants import CharacterSet
import pyperclip
from tkscrolledframe import ScrolledFrame
from data.checkupdates import *
from data.secure import *
from data.forgot_password import *
# tkinter modules
from PIL import Image as image
from PIL import ImageTk as tk_image
from tkinter import filedialog as fd
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import ttk
from tkinter import *
from tkhtmlview import HTMLLabel
from tkinter import tix
username = 'rohith'
master = Tk()
width_window = 1057
height_window = 661
master.focus_force()
master.config(bg="#292A2D")
screen_width = master.winfo_screenwidth()
screen_height = master.winfo_screenheight()
x = screen_width / 2 - width_window / 2
y = screen_height / 2 - height_window / 2
master.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
running = True
al = False
username = username
master.title("Pin")
master.config(bg="#121212")
running = running
al = al
width_window = 1057

def alpha():
    if str(enter_alpha['text']) == 'Enter Alphanumeric pin':
        running = False
        al = True
        enter_alpha.config(text="Enter Number pin")
        threading.Thread(target=for_alpha).start()
    elif enter_alpha['text'] == 'Enter Number pin':
        running = True
        al = False
        enter_alpha.config(text="Enter Alphanumeric pin")
        threading.Thread(target=getting).start()

def for_alpha():
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

lab = Label(master, text='Verify the security pin', bg='#121212',
            fg='white', font=("Segoe Ui", 20))
lab.place(x=width_window / 2 - 60 - 5 - 45, y=160)

ent = Entry(master, width=20, font=("Segoe Ui", 15))
ent.place(x=width_window / 2 - 40 - 5 - 5 - 30 - 10, y=250)
enter_alpha = Button(master, text='Enter Alphanumeric pin', fg="#2A7BCF",
                        activeforeground="#2A7BCF",
                        bg="#121212", command=alpha,
                        activebackground="#121212", bd=0, borderwidth=0, font=("Consolas", 14, UNDERLINE))
enter_alpha.place(x=width_window / 2 + 200 - 30 - 10, y=250)
# adding the check box button

t1 = threading.Thread(target=getting)

# adding the save button

forgot_pass = Button(master, text='Forgot Password?', fg="#2A7BCF",
                        activeforeground="#2A7BCF",
                        bg="#121212", command=lambda: login_password("Forgot Password", my_cursor, 1),
                        activebackground="#121212", bd=0, borderwidth=0, font=("Consolas", 14, UNDERLINE))

forgot_pass.place(x=550, y=300+30)
save = Button(master, text="S A V E", fg="#292A2D",
                activeforeground="#292A2D",
                bg="#994422",
                activebackground="#994422", height=1, width=10, bd=0, borderwidth=0, font=("Consolas", 14))
save.place(x=width_window / 2 - 30 - 5 - 100, y=300+30)
master.mainloop()