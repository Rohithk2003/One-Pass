
from tkinter.ttk import *
from tkinter import *

from PIL import ImageTk as tk_image
from PIL import Image as image
import platform
import os
#finding the os so tha  the images are displayed properly
if platform.system() == "Windows":
    path = "images\\"
if platform.system() == 'Darwin':
    dir_path = os.getcwd()
    path = dir_path + "/images/"



def handle_focus_in(entry, index, *number):
    val = str(entry.get())
    if val == "Username" or val == "Email ID" or val == "New Email":
        entry.delete(0, END)
        entry.config(foreground="black")
    if val == "Password" or val == "Email password" or val == "New Email password":
        entry.delete(0, END)
        entry.config(foreground="black")
        entry.config(show="*")
    elif (
            index == 2
            and val == "Password"
            or index == 4
            and val == "Email password"
            or index == 2
            and val == "New Email password"
    ):
        entry.config(foreground="white")
        state_entry = entry["show"]
        entry.config(show=state_entry)
    try:
        for i in number:
            if i in (0, 1):
                entry.config(foreground="white")

    except:
        pass


def password_sec(entry, button):
    a = entry["show"]
    private_img = tk_image.PhotoImage(image.open(f"{path}private.png"))
    unhide_img = tk_image.PhotoImage(image.open(f"{path}eye.png"))
    val = str(entry.get())
    if val == "Password" or val == "Email Password":
        entry.config(show="")
    else:
        if a == "*":
            entry.config(show="")
            button.config(image=private_img)
            button.photo = private_img
            button.image = private_img
        if a == "":
            entry.config(show="*")
            button.config(image=unhide_img)
            button.photo = unhide_img
            button.image = unhide_img


def handle_focus_out(entry, val, index):
    a = entry.get()
    if a == "" and index == 2 or a == "" and index == 4:
        entry.delete(0, END)
        entry.config(foreground="grey")
        entry.config(show="")
        entry.insert(0, val)
    elif a == "":
        entry.delete(0, END)
        entry.config(foreground="grey")
        entry.insert(0, val)
