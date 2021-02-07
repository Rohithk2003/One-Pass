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
settings_window = Toplevel()
settings_window.resizable(False, False)
settings_window.focus_force()

width_window = 500
height_window = 300
screen_width = settings_window.winfo_screenwidth()
screen_height = settings_window.winfo_screenheight()
x = screen_width / 2 - width_window / 2
y = screen_height / 2 - height_window / 2

settings_window.geometry("%dx%d+%d+%d" %
                         (width_window, height_window, x, y))

settings_window.title("Settings")
settings_window.config(bg="#1E1E1E")
v = IntVar()
# delete_object = Deletion(handler, real_username, original_password,
#                          hashed_password, window, my_cursor, master_main)
# change_object = Change_details(master_main,
#                                real_username, original_password, hashed_password, my_cursor)


# def write_value(value):
#     d = {real_username: value}
#     with open("settings.json", 'w') as f:
#         json.dump(value, f)


keepmeloggedin = Radiobutton(settings_window, bg="#1E1E1E", foreground='green', fg='white', selectcolor='green', font=("Segoe Ui", 13), activebackground="#1E1E1E",
                             activeforeground='white',
                             text="Keep Me Logged In",
                             padx=20,
                             variable=v, value=1)
log_label = Button(
    settings_window,
    text="Log out",
    width=20,
    font=("Segoe Ui", 13),
    fg="white",
    activebackground="#1E1E1E",
    activeforeground="white",
    bg="#1E1E1E",

    command=lambda: log_out(settings_window, window, master_main),
)

Delete_account_button = Button(
    settings_window,
    text="Delete main account",
    command=lambda: delete_object.delete_main_account(
        master_main, settings_window),
    font=("Segoe Ui", 13),
    width=20,
    fg="white",
    activeforeground="white",
    activebackground="#1E1E1E",
    bg="#1E1E1E",

)
Delete_social_button = Button(
    settings_window,
    text="Delete passwords",
    command=lambda: delete_object.delete_social_media_account(
        password_button, True
    ),
    font=("Segoe Ui", 13),
    fg="white",
    width=20,
    activeforeground="white",
    activebackground="#1E1E1E",
    bg="#1E1E1E",

)
change_account_button = Button(
    settings_window,
    text="Change Details",
    command=lambda: login_password("Change Details", my_cursor),
    font=("Segoe Ui", 13),
    fg="white",
    activebackground="#1E1E1E",
    activeforeground="white",
    width=20,
    bg="#1E1E1E",

)
change_email_button = Button(
    settings_window,
    text="Change recovery email",
    command=lambda: change_object.change_email(),
    font=("Segoe Ui", 13),
    fg="white",
    activebackground="#1E1E1E",
    activeforeground="white",
    width=20,
    justify='center',
    anchor='center',
    bg="#1E1E1E",
)
# text label
Label(settings_window, text="Settings", font=("consolas", 30),
      fg='green', bg='#1E1E1E').place(x=160, y=0)

Delete_account_button.place(x=30, y=70)
keepmeloggedin.place(x=245, y=70)
Delete_social_button.place(x=30, y=150)
change_account_button.place(x=270, y=150)
change_email_button.place(x=30, y=230)
log_label.place(x=270, y=230)

# if os.stat(f"{real_username}decrypted.bin").st_size == 0:
#     Delete_social_button.config(state=DISABLED)
# else:
#     Delete_social_button.config(state=NORMAL)
settings_window.mainloop()
