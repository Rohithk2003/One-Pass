import mysql.connector as m
import glob
import pickle as p
from mysql.connector.constants import CharacterSet
import pyperclip
from tkscrolledframe import ScrolledFrame
from tkinter import tix
import platform
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

window = Tk()
window.config(bg="#1E1E1E")
window.resizable(False, False)
window.focus_force()
window.title('sdsa')

width_window = 450
height_window = 400
screen_width = window.winfo_screenwidth()
screen_height = window.winfo_screenheight()
x = screen_width / 2 - width_window / 2
y = screen_height / 2 - height_window / 2
window.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))

logo_image = tk_image.PhotoImage(image.open(f"{path}change_pass.png"))
main_label = Label(window, fg='white', font=(
    "Yu Gothic Ui", 20), text="Change Password", compound='right', image=logo_image, bg="#1E1E1E")
main_label.photo = logo_image
main_label.place(x=70, y=50)

username_forgot = Label(window, text="Username:",
                        fg="white",
                        bg="#1E1E1E",
                        font=("Yu Gothic Ui", 15), )
recover_email = Label(window, text="Recovery Email:",
                      fg="white",
                      bg="#1E1E1E",
                      font=("Yu Gothic Ui", 15), )
recover_password = Label(window, text="Recovery Password:", fg="white",
                         bg="#1E1E1E",
                         font=("Yu Gothic Ui", 15), )
recover_email_entry = Entry(window,
                            width=13,
                            bg="#1E1E1E",
                            foreground="white",
                            border=0,
                            bd=0,
                            fg='white',
                            font=("consolas", 15, "normal"),
                            insertbackground="white", )
recover_password_entry = Entry(window,
                               width=13,
                               bg="#1E1E1E",
                               foreground="white",
                               fg='white',
                               border=0,
                               bd=0,
                               font=("consolas", 15, "normal"),
                               insertbackground="white", )
username_forgot_entry = Entry(window,
                              width=13,
                              bg="#1E1E1E",
                              border=0,
                              bd=0,
                              fg='white',

                              font=("consolas", 15, "normal"),
                              foreground="white",
                              insertbackground="white", )

username_forgot.place(x=0, y=70 + 100 + 3)
recover_password.place(x=0, y=130 + 100 + 30 + 3)
recover_email.place(x=0, y=100 + 100 + 15 + 3)
username_forgot_entry.place(x=250, y=70 + 100 + 5)
recover_password_entry.place(x=250, y=130 + 100 + 30 + 5)
recover_email_entry.place(x=250, y=100 + 100 + 15 + 5)
Frame(window, width=150, height=2, bg="white").place(
    x=250, y=70 + 100 + 10 + 16 + 5
)
Frame(window, width=150, height=2, bg="white").place(
    x=250, y=130 + 100 + 10 + 16 + 30 + 5
)
Frame(window, width=150, height=2, bg="white").place(
    x=250, y=100 + 100 + 10 + 16 + 15 + 5
)
window.mainloop()
