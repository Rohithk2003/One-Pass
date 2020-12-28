# all required modules
import glob
import os.path
import sqlite3

import os
import platform

from data import *

from tkinter.ttk import *
from tkinter import *
from PIL import ImageTk as tk_image
from PIL import Image as image

# for updating the file

# main window
bufferSize = 64 * 1024

# database connection
if not os.path.exists("DATABASE"):
    os.mkdir("DATABASE")
connection = sqlite3.connect("DATABASE\\users.db", isolation_level=None)
my_cursor = connection.cursor()
my_cursor.execute(
    "create table if not exists data_input (username varchar(500) primary key,email_id varchar(500),password  blob,"
    "salt blob, recovery_password varchar(500), salt_recovery blob) "
)

path = ''
#finding the os so tha  the images are displayed properly
if platform.system() == "Windows":
    dir_path = os.path.dirname(os.path.realpath(__file__))
    path = dir_path+"\images\\"
if platform.system() == 'Darwin':
    dir_path = os.path.dirname(os.path.realpath(__file__))
    path = dir_path + "/images/"
# for image loading
l = [{"1": f"{path}member.png"}]

# global values
catch_error = True
social_media_user_text = ""
social_media_active = False
image_path = ""
exist = False
cutting_value = False
file = 0
buttons_list = {}
btn_nr = -1
var = 0

# main window
root = Tk()
root.title("ONE-PASS")

width_window = 1057
height_window = 661

root.config(bg="#292A2D")
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = screen_width / 2 - width_window / 2
y = screen_height / 2 - height_window / 2
root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))



# ---------------------Importing Images------------------

image1 = tk_image.PhotoImage(image.open(f"{path}background.jpg"))
iconimage = tk_image.PhotoImage(image.open(f"{path}icon2.png"))

image1_label = Label(root, image=image1, bd=0)
image1_label.place(x=0, y=0)

root.config(bg="black")

labelframe = LabelFrame(
    root, bg="#28292A", width=350, bd=0, highlightthickness=0, height=500, borderwidth=0, relief="solid"
)
labelframe.pack(padx=100, pady=80)

icon_label = Label(labelframe, bg="#28292A", image=iconimage)
icon_label.place(x=115, y=20)

# ----------------------Buttons----------------------------

register_button = Button(
    labelframe,
    text="L O G I N",
    width=22,
    height=2,
    font=("consolas"),
    fg="#292A2D",
    bg="#356745",
    activebackground="#356745",
    activeforeground="#292A2D",
    bd=0,
    command=lambda: login_class.login(main_window.window_after,my_cursor,root),
)
register_button.place(x=75, y=190 + 40)
view = Button(
    labelframe,
    text="R E G I S T E R",
    width=22,
    height=2,
    font=("consolas"),
    fg="#292A2D",
    bg="#356745",
    activebackground="#356745",
    activeforeground="#292A2D",
    bd=0,
    command=lambda: register_class.register(root,main_window.window_after, my_cursor, root),
)
view.place(x=75, y=300 + 40)

root.resizable(False, False)
root.mainloop()

""" to remove all decrypted files
the glob function returns a list of files ending with decrypted.bin"""
list_file = glob.glob("*decrypted.bin")
for i in list_file:
    try:
        os.remove(str(i))
    except:
        pass
