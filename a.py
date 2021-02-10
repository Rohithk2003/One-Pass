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
root = tix.Tk()
root.geometry("1000x1000")
# root = Frame(
#     self, width=1000 + 50, height=1057, bd="0", highlightthickness=0
# )
# root.place(x=120 + 34, y=0)
username = 'rohith'
new_s = Frame(root, bg="#1E1E1E", width=500, height=500, bd=0)
new_s.place(x=150, y=150)


def copy(value):
    pyperclip.copy(value)
    messagebox.showinfo("Copied", "Copied!!!")


dot_text = Label(new_s, text=":", bg="#1E1E1E", fg="white", font=(20))
dot_text1 = Label(new_s, text=":", bg="#1E1E1E", fg="white", font=(20))
dot_text2 = Label(new_s, text=":", bg="#1E1E1E", fg="white", font=(20))
dot_text3 = Label(new_s, text=":", bg="#1E1E1E", fg="white", font=(20))

# with open(f'{username}decrypted.bin', 'rb') as f:
#     lists = pickle.load(f)
delete_account = Button(
    new_s,
    text="Delete Account",
    bd=0,
    font=("consolas"),
    fg="#292A2D",
    activeforeground="#292A2D",
    bg="#994422",
    activebackground="#994422",
    command=lambda: delete_object.delete_social_media_account(
        button, False, lists[button][2]), )

ChangeAccount = Button(
    new_s,
    text="Change Details",
    bd=0,
    font=("consolas"),
    fg="#292A2D",
    activeforeground="#292A2D",
    bg="#994422",
    activebackground="#994422",
    command=lambda: change_object.change_window_creation(lists[button][0], button))
# getting the username and password
username = ''
account_name = 'facebook'
password = ''
i = ['rohith', 'rohithk123', '', 'www.facebook.com']
username, password, website = i[0], i[1], i[3]
image_path = f'{path}followers.png'

username_label = Label(
    new_s,
    text="Username",
    bg="#1E1E1E",
    fg="white",
    font=("Yu Gothic Ui", 15),
)

password_label = Label(
    new_s,
    text="Password",
    bg="#1E1E1E",
    fg="white",
    font=("Yu Gothic Ui", 15),
)
social_account = Label(
    new_s,
    text="Account Name",
    bg="#1E1E1E",
    fg="white",
    font=("Yu Gothic Ui", 15),
)
website_text = Label(new_s, text='Website',    bg="#1E1E1E",
                     fg="white",
                     font=("Yu Gothic Ui", 15),)
username_text = Label(
    new_s,
    text=username,
    bg="#1E1E1E",
    fg="white",
    font=("Yu Gothic Ui", 15),
)
password_text = Label(
    new_s,
    text=password,
    bg="#1E1E1E",
    fg="white",
    font=("Yu Gothic Ui", 15),
)
social_account_text = Label(
    new_s,
    text=account_name,
    bg="#1E1E1E",
    fg="white",
    font=("Yu Gothic Ui", 15),
)
website_label1 = HTMLLabel(
    new_s, html=f''' 
    <!DOCTYPE html>
    <html>
        <head>
            <link rel="stylesheet" href="style.css">
        </head>
    <body>
        <a   style='color:white;text-align:center;font-family:sans-serif'  href={website}>Open Website</a>
    </body>
    </html>
    ''',
    background="#1E1E1E", foreground='white', width=20, height=2)
try:
    tip = tix.Balloon(new_s)
    tip.config(background='white')
    tip.label.config(bg='white', fg='white')
    try:
        for sub in tip.subwidgets_all():
            sub.configure(bg='white')
    except:
        pass
    tip.subwidget('label').forget()
    tip.message.config(bg='white', fg='#06090F',
                       font=('Segoe UI SemiBold', 10))
    # display the ballon text
    tip.bind_widget(website_label1, balloonmsg=f'Open {website}')

except:
    pass
copy_but_password = Button(new_s, text="Copy Password", bd=0,
                           font=("consolas"),
                           fg="#292A2D",
                           activeforeground="#292A2D",
                           bg="#994422",
                           activebackground="#994422", command=lambda: copy(password))
copy_but_username = Button(new_s, text="Copy Username", bd=0,
                           font=("consolas"),
                           fg="#292A2D",
                           activeforeground="#292A2D",
                           bg="#994422",
                           activebackground="#994422", command=lambda: copy(username))

img = tk_image.PhotoImage(image.open(image_path))

img_button = Label(
    new_s,
    image=img,
    border="0",
    bg="#1E1E1E",
    activebackground="#1E1E1E",

)
img_button.photo = img
img_button.place(x=160, y=30)
dot_text.place(x=170 + 20, y=175 + 3)
dot_text1.place(x=170 + 20, y=200 + 25 + 3)
dot_text2.place(x=170 + 20, y=250 + 25 + 3)
dot_text3.place(x=170 + 20, y=300 + 25 + 3)

delete_account.place(x=0 + 25, y=340+50)
username_label.place(x=30, y=250 + 25)
website_text.place(x=30, y=325)
password_label.place(x=30, y=200 + 25)
social_account.place(x=30, y=175)
username_text.place(x=250, y=250 + 25)
password_text.place(x=250, y=200 + 25)
social_account_text.place(x=250, y=175)
ChangeAccount.place(x=340, y=340+50)
copy_but_username.place(x=360, y=30)
copy_but_password.place(x=360, y=80)
website_label1.place(x=250, y=300 + 20+5)
root.mainloop()
