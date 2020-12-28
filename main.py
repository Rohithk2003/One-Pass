# all required modules
import base64
import glob
import hashlib
import os.path
import pickle
import pyAesCrypt

import random
import smtplib
import sqlite3
import pyaes
import pbkdf2
import os
import secrets
import threading
import platform
from string_en import *

from focus_pass import *
from main_encryption import *
from login_class import *
from string_en import *
# tkinter modules
from PIL import Image as image
from PIL import ImageTk as tk_image
from tkinter import colorchooser
from tkinter import filedialog as fd
from tkinter import messagebox
from tkinter import simpledialog
from tkinter.ttk import *
from tkinter import *

from register_class import *

# for updating the file
from update_check import isUpToDate
from update_check import update

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
    path = "images\\"
if platform.system() == 'Darwin':
    dir_path = os.getcwd()
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


# displaying the profile

# for handling registrations



def log_out(*window):
    try:
        for i in window:
            i.destroy()

        a = Tk()
        a.withdraw()
        messagebox.showinfo(
            "Logged Out", "You have been successfully logged out")
        a.destroy()
        list_file = glob.glob("*decrypted.bin")
        for i in list_file:
            converting_str = str(i)
            try:
                os.remove(converting_str)
            except:
                pass
        login()

    except:
        pass



def checkforupdates():
    # isUpToDate check whether the file ie main.py  is same as the one present in my github repository and it returns true if same else false
    if isUpToDate(
            "main.py",
            "https://raw.githubusercontent.com/Rohithk2003/One-Pass/develop/main.py",
    ):
        result = messagebox.askyesno(
            "Update Available", "Do you want to update the app?"
        )
        if result == True:
            try:
                messagebox.showinfo(
                    "Updating", "Please wait while the software is being updated"
                )
                # used for updating the file
                update(
                    "main.py",
                    "https://raw.githubusercontent.com/Rohithk2003/One-Pass/develop/main.py",
                )
                messagebox.showinfo(
                    "Updated", "The file has been updated please restart to take effect"
                )
            except:
                messagebox.showerror(
                    "No internet Available", "Internet is not available"
                )

        else:
            quit()
    else:
        messagebox.showinfo("Update", "No update is currently available")


def settings(
        real_username,
        main_window,
        hashed_password,
        window,
        password_button,
        rec_pas,
        original_password,
):
    settings_window = Toplevel()
    settings_window.resizable(False, False)
    width_window = 187
    height_window = 175
    screen_width = settings_window.winfo_screenwidth()
    screen_height = settings_window.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2

    settings_window.geometry("%dx%d+%d+%d" %
                             (width_window, height_window, x, y))

    settings_window.title("Settings")
    settings_window.config(bg="#292A2D")

    delete_object = Deletion(real_username, hashed_password, window,my_cursor)
    change_object = Change_details(real_username, hashed_password, window,my_cursor)

    log_label = Button(
        settings_window,
        text="Log out",
        width=20,
        font=("consolas"),
        fg="white",
        activebackground="white",
        activeforeground="white",
        bg="#994422",
        bd=0,
        command=lambda: log_out(settings_window, window, main_window),
    )

    check_for_updates = Button(
        settings_window,
        command=checkforupdates,
        text="Check for updates",
        width=20,
        activebackground="#994422",
        font=("consolas"),
        activeforeground="white",
        fg="white",
        bg="#994422",
        bd=0,
    )
    Delete_account_button = Button(
        settings_window,
        text="Delete main account",
        command=lambda: delete_object.delete_main_account(
            main_window, settings_window),
        font=("consolas"),
        width=20,
        fg="black",
        activeforeground="black",
        activebackground="white",
        bg="white",
        bd=0,
    )
    Delete_social_button = Button(
        settings_window,
        text="Delete sub  account",
        command=lambda: delete_object.delete_social_media_account(
            password_button, True
        ),
        font=("consolas"),
        fg="black",
        width=20,
        activeforeground="black",
        activebackground="white",
        bg="white",
        bd=0,
    )
    change_account_button = Button(
        settings_window,
        text="Change Details",
        command=lambda: login_password("Change Details"),
        font=("consolas"),
        fg="white",
        activebackground="#994422",
        activeforeground="white",
        width=20,
        bg="#994422",
        bd=0,
    )
    change_email_button = Button(
        settings_window,
        text="Change recovery email",
        command=lambda: change_object.change_email(rec_pas, original_password),
        font=("consolas"),
        fg="black",
        activebackground="white",
        activeforeground="black",
        width=20,
        bg="white",
        bd=0,
    )

    Delete_account_button.grid(row=1, column=1, columnspan=2)
    check_for_updates.grid(row=2, column=1, columnspan=2)
    Delete_social_button.grid(row=3, column=1, columnspan=2)
    change_account_button.grid(row=4, column=1, columnspan=2)
    change_email_button.grid(row=5, column=1, columnspan=2)
    log_label.grid(row=6, column=1, columnspan=2)

    if os.stat(f"{real_username}decrypted.bin").st_size == 0:
        Delete_social_button.config(state=DISABLED)
    else:
        Delete_social_button.config(state=NORMAL)
    settings_window.mainloop()


# forgot password function
def forgot_password(email, *OTP):
    try:
        global running
        running = True
        SUBJECT = "EMAIL verification for ONE-PASS-MANAGER"
        otp = f"Hey {OTP[2]}!\nOTP to change password is {OTP[0]}"
        msg = f"Subject: {SUBJECT}\n\n{otp}"
        s = smtplib.SMTP("smtp.gmail.com", 587)
        s.starttls()
        s.login("", "")
        s.sendmail("", email, msg)
    except:
        a = Tk()
        a.withdraw()
        messagebox.showwarning("No internet", "No internet is available")


def login_password(title1):
    window = Toplevel()
    window.config(bg="#292A2D")
    window.resizable(False, False)

    window.title(title1)
    text = (
        "Please provide the recovery email  and recovery email password \n that you provided while creating an "
        "account "
    )
    text_label = Label(window, text=text, fg="white", bg="#292A2D")
    width_window = 400
    height_window = 300
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2
    window.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))

    username_forgot = Label(window, text="Username", fg="white", bg="#292A2D")
    recover_email = Label(window, text="Email", fg="white", bg="#292A2D")
    recover_password = Label(window, text="Password", fg="white", bg="#292A2D")
    recover_email_entry = Entry(window)
    recover_password_entry = Entry(window)
    username_forgot_entry = Entry(window)

    username_forgot.place(x=50, y=70)
    recover_password.place(x=50, y=100)
    recover_email.place(x=50, y=130)
    username_forgot_entry.place(x=200, y=70)
    recover_password_entry.place(x=200, y=100)
    recover_email_entry.place(x=200, y=130)
    text_label.place(x=20, y=0)
    key = ""
    l = "abcdefghijklmnopqrstuvwxyz"
    for i in range(7):
        key += random.choice(l)

    def generate_key1(file, button):
        pyAesCrypt.encryptFile(file, "otp.bin.fenc", key, bufferSize)
        os.unlink(file)
        button.config(state=DISABLED)

        messagebox.showinfo(
            "OTP", f"An OTP has been sent to  {str(recover_email_entry.get())}"
        )
        window.focus_set()

    def change_password(email, password1, username12):
        root = Toplevel()
        new_img = tk_image.PhotoImage(image.open(f"{path}user.png"))
        new_img_label = Label(root, image=new_img, bg="#292A2D")
        new_img_label.photo = new_img
        root.resizable(False, False)

        file_name_reentry = username12 + ".bin.fenc"

        width_window = 400
        height_window = 400
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        root.title("Change Details")
        root.geometry("300x300")
        root.config(bg="#292A2D")

        new_username = Label(root, text="New Username",
                             fg="white", bg="#292A2D")
        new_password = Label(root, text="New Password",
                             fg="white", bg="#292A2D")

        new_username_entry = Entry(root)
        new_password_entry = Entry(root, show="*")

        new_img_label.grid(row=0, column=1)
        new_username.grid(row=1, column=0)
        new_password.grid(row=2, column=0)
        new_username_entry.grid(row=1, column=1)
        new_password_entry.grid(row=2, column=1)

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
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
            activeforeground="white",
            relief=RAISED,
        )
        show_both_12.grid(row=0, column=5)
        show_both_12.place(x=250 - 15, y=100 + 50 - 5)

        def change():
            my_cursor.execute(
                "select password,salt from data_input where email_id = (?)", (
                    simple_encrypt(email),)
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
            new_val = password_decrypt[::-1]
            main_pass = new_val + "/" + password1
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

            re_hash = hashlib.sha3_512(value.encode()).hexdigest()
            try:
                pyAesCrypt.decryptFile(
                    file_name_reentry,
                    username12 + "decrypted.bin",
                    re_hash,
                    bufferSize,
                )
            except:
                pass
            if os.path.exists(f"{username12}decrypted.bin"):
                os.remove(username12 + ".bin.fenc")
                re_hash_text = str(new_password_entry.get()) + str(
                    new_username_entry.get()
                )
                new_salt = str(new_password_entry.get()) + "@" + main_pass
                re_hash_new = hashlib.sha3_512(
                    re_hash_text.encode()).hexdigest()
                re_encrypt, new_salt = create_key(main_pass, new_salt)
                pyAesCrypt.encryptFile(
                    username12 + "decrypted.bin",
                    str(new_username_entry.get()) + ".bin.fenc",
                    re_hash_new,
                    bufferSize,
                )
                my_cursor.execute(
                    "select email_id from data_input where username=(?)", (
                        simple_encrypt(username12),)
                )
                for i in my_cursor.fetchall():
                    password_recovery_email = simple_decrypt(
                        i[0]) + re_hash_new
                    passwordSalt = secrets.token_bytes(512)
                    key = pbkdf2.PBKDF2(
                        password_recovery_email, passwordSalt).read(32)
                    aes = pyaes.AESModeOfOperationCTR(key)
                    encrypted_pass = aes.encrypt(password1)

                    my_cursor.execute(
                        "update data_input set username = (?),password=(?),recovery_password = (?),salt_recovery=(?) "
                        "where email_id = (?)",
                        (
                            simple_encrypt(str(new_username_entry.get())),
                            re_encrypt,
                            encrypted_pass,
                            passwordSalt,
                            simple_encrypt(email),
                        ),
                    )
                messagebox.showinfo(
                    "Success", "Your username and password has been changed"
                )

            else:
                messagebox.showinfo("Error", "Wrong recovery password")

        change_button = Button(root, text="Change", command=change)
        change_button.grid(row=3, column=0)

    def Verification(password, otp_entry, email, email_password, username12, button):
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
                    button.config(state=NORMAL)
                    otp_entry.delete(0, END)
        else:
            messagebox.showinfo(
                "Error", "Please provide the OTP  send to your email")

    def main(key, otp_window, button):
        run = False
        global running
        username_verify = str(username_forgot_entry.get())
        recover_email_entry_verify = str(recover_email_entry.get())
        recover_password_entry_verify = str(recover_password_entry.get())
        if (
                username_verify == "Username"
                and recover_email_entry_verify == "Email ID"
                and recover_password_entry_verify == "Password"
        ):
            roo21 = Tk()
            roo21.withdraw()
            messagebox.showinfo(
                "Error",
                "Please provide the details",
            )
            roo21.destroy()

        elif username_verify == "Username":

            messagebox.showwarning("Warning", f"Username cannot be blank")

        elif recover_password_entry_verify == "Password":
            messagebox.showwarning("Warning", f"Password cannot be blank")
        elif not os.path.exists(username_verify + ".bin.fenc"):

            messagebox.showwarning(
                "Warning", f"Cannot find user {username_verify}")

        else:
            if os.path.exists(username_verify + ".bin.fenc"):
                verify_password = ""
                for i in recover_email_entry_verify:
                    if i == "@":
                        break
                    else:
                        verify_password += i
                verify_password += recover_password_entry_verify
                my_cursor.execute(
                    "select email_id from data_input where username = (?)",
                    (simple_encrypt(username_verify),),
                )
                values_fetch = my_cursor.fetchall()

                if values_fetch != []:
                    for i in values_fetch:

                        if simple_decrypt(i[0]) == recover_email_entry_verify:
                            run = True
                        else:
                            run = False

                            messagebox.showerror(
                                "Error", "Wrong Recovey email")
                else:
                    messagebox.showerror("Error", "No such account exists")

                if run:

                    otp_entry = Entry(otp_window)
                    otp_entry.grid(row=6, column=1)
                    otp_entry_button = Button(
                        otp_window,
                        text="verify otp",
                        command=lambda: Verification(
                            key,
                            otp_entry.get(),
                            recover_email_entry_verify,
                            recover_password_entry_verify,
                            username_verify,
                            button,
                        ),
                        fg="white",
                        bg="#292A2D",
                    )
                    otp_entry_button.grid(row=8, column=1)
                    otp_entry_button.place(x=50, y=200)
                    otp_entry.place(x=200, y=200)
                    digits = "1234567890"
                    OTP = ""
                    for i in range(6):
                        OTP += random.choice(digits)
                    OTP_secure = hashlib.sha512(OTP.encode()).hexdigest()
                    l = list(OTP_secure)
                    with open("otp.bin", "wb") as f:
                        pickle.dump(l, f)
                        f.close()
                    generate_key1("otp.bin", button)
                    forgot_password(
                        OTP, recover_email_entry_verify, username_verify)
            else:
                messagebox.showerror("Error", "No such account exists")

    forgot_password_button = Button(
        window,
        text="verify",
        command=lambda: main(key, window, forgot_password_button),
        bg="#292A2D",
        fg="white",
    )
    forgot_password_button.grid(row=5, column=1)
    forgot_password_button.place(x=250, y=170)

    unhide_img = tk_image.PhotoImage(image.open(f"{path}eye.png"))

    show_both_1 = Button(
        window,
        image=unhide_img,
        bd=0,
        command=lambda: password_sec(recover_password_entry, show_both_1),
        fg="white",
        bg="#292A2D",
        highlightcolor="#292A2D",
        activebackground="#292A2D",
        activeforeground="white",
        relief=RAISED,
    )
    show_both_1.photo = unhide_img
    show_both_1.grid(row=0, column=0)
    show_both_1.place(x=325, y=95)
    username_forgot_entry.insert(0, "Username")
    username_forgot_entry.config(fg="grey")
    recover_password_entry.insert(0, "Password")
    recover_password_entry.config(fg="grey")
    recover_password_entry.config(show="")

    recover_email_entry.config(fg="grey")
    recover_email_entry.insert(0, "Email ID")

    username_forgot_entry.bind(
        "<FocusIn>",
        lambda event, val_val=username_forgot_entry, index=1: handle_focus_in(
            val_val, index
        ),
    )
    username_forgot_entry.bind(
        "<FocusOut>",
        lambda event, val_val=username_forgot_entry, val="Username", index=1: handle_focus_out(
            val_val, val, index
        ),
    )

    recover_password_entry.bind(
        "<FocusIn>",
        lambda event, val_val=recover_password_entry, index=2: handle_focus_in(
            val_val, index
        ),
    )
    recover_password_entry.bind(
        "<FocusOut>",
        lambda event, val_val=recover_password_entry, val="Password", index=2: handle_focus_out(
            val_val, val, index
        ),
    )

    recover_email_entry.bind(
        "<FocusIn>",
        lambda event, val_val=recover_email_entry, index=3: handle_focus_in(
            val_val, index
        ),
    )
    recover_email_entry.bind(
        "<FocusOut>",
        lambda event, val_val=recover_email_entry, val="Email ID", index=3: handle_focus_out(
            val_val, val, index
        ),
    )


var = 0


def window_after(username, hash_password, password_new, *window):
    try:
        for i in window:
            i.destroy()
    except:
        pass
    # sidebar
    root = Tk()
    root.resizable(False, False)
    root.focus_set()
    global var
    global file
    status_name = False
    sidebar = Frame(
        root, width=5, bg="#292A2D", height=500, relief="sunken", borderwidth=1
    )
    sidebar.pack(expand=False, fill="both", side="left")
    file = None
    root.title("ONE-PASS")
    width_window = 1300
    height_window = 700
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2

    root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
    main_ic = tk_image.PhotoImage(image.open('images\\main_icon.png'))
    sidebar_icon = Label(sidebar, image=main_ic, bg='#292A2D')

    def testing(root, mainarea, username, hash_password, password_button):
        button["state"] = DISABLED
        notes_buttons["state"] = NORMAL
        profile_button["state"] = NORMAL
        root.title("Passwords")
        emptyMenu = Menu(root)
        root.geometry("1300x700")
        mainarea.config(bg="#292A2D")
        root.config(menu=emptyMenu)
        root.iconbitmap(f"{path}password.ico")
        list = mainarea.pack_slaves()
        for l in list:
            l.destroy()
        list = mainarea.grid_slaves()
        for l in list:
            l.destroy()
        gameloop(username, hash_password, mainarea, password_button)

    def note_pad_sec():
        global status_name
        global var
        notes_buttons["state"] = DISABLED
        button["state"] = NORMAL
        profile_button["state"] = NORMAL
        root.iconbitmap(f"{path}notes.ico")

        list = mainarea.grid_slaves()
        for l in list:
            l.destroy()

        if __name__ == "__main__":
            emptyMenu = Menu(root)
            root.config(menu=emptyMenu)
            try:
                list = mainarea.grid_slaves()
                for l in list:
                    l.destroy()
            except:
                pass

            def newFile():
                root.title("Untitled - Notepad")
                TextArea.delete(1.0, END)

            def openFile():
                global file
                file = fd.askopenfilename(
                    defaultextension=".txt",
                    filetypes=[("All Files", "*.*"),
                               ("Text Documents", "*.txt")],
                )

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
                if root.title() != "Untitled-Notepad":
                    application_window = Tk()
                    application_window.withdraw()
                    a = simpledialog.askstring(
                        "Input", "What is new file name?", parent=application_window
                    )
                    application_window.destroy()
                    if file != None or file != 0:
                        new_file, file_extension = os.path.splitext(file)
                        f = open(file, "r")
                        dir = os.path.dirname(file)
                        values = f.read()
                        f.close()
                        os.remove(file)
                        file = (dir) + "/" + a + file_extension
                        with open(file, "w") as f:
                            f.write(values)
                            f.close()
                        TextArea.delete(1.0, END)
                        with open(file, "r") as f:
                            TextArea.insert(1.0, f.read())
                            f.close()
                        root.title(a + file_extension + " - Notepad")
                    else:
                        messagebox.showinfo(
                            "Rename", "Please save your file before renaming it"
                        )
                        save_as_File()
                else:
                    messagebox.showinfo(
                        "Rename", "Please save your file before renaming it"
                    )
                    save_as_File()

            def save_as_File():
                global file
                if file == None:

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

            def save_file():
                global status_name
                global file
                if status_name:
                    with open(file, "w") as f:
                        f.write(TextArea.get(1.0, END))
                        f.close()
                else:
                    file = fd.asksaveasfilename(
                        initialfile="Untitled.txt",
                        defaultextension=".txt",
                        filetypes=[
                            ("All Files", "*.*"),
                            ("Text Documents", "*.txt"),
                        ],
                    )
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

            def quitApp():
                try:
                    root.destroy()
                except:
                    pass

            def cut(*event):
                global cutting_value
                try:
                    if TextArea.selection_get():
                        # grabbing selected text from text area
                        cutting_value = TextArea.selection_get()
                        TextArea.delete("sel.first", "sel.last")
                except:
                    cutting_value = ""

            def copy(*event):
                global cutting_value
                try:
                    if TextArea.selection_get():
                        # grabbing selected text from text area
                        cutting_value = TextArea.selection_get()
                except:
                    cutting_value = ""

            def paste(*event):
                if cutting_value:
                    postion = TextArea.index(INSERT)
                    TextArea.insert(postion, cutting_value)

            def about():
                messagebox.showinfo("Notepad", "Notepad by Rohithk-25-11-2020")

            # Basic tkinter setup
            root.geometry("1300x700")
            root.iconbitmap(False, f"{path}notes.ico")
            root.title("Untitled - Notepad")
            # Add TextArea
            root.resizable(0, 0)
            font_main = ("freesansbold", 12)
            Scroll_y = Scrollbar(mainarea, orient="vertical")
            Scroll_y.pack(side="right", fill=Y)
            TextArea = Text(
                mainarea,
                font=font_main,
                fg="#292A2D",
                insertofftime=600,
                insertontime=600,
                insertbackground="#292A2D",
                undo=True,
                yscrollcommand=Scroll_y.set,
            )

            Scroll_y.config(command=TextArea.yview)
            TextArea.pack(expand=True, fill=BOTH)

            # create a menubar
            MenuBar = Menu(root)
            MenuBar.config(bg="#292A2D", bd=0, activebackground="#292A2D")
            status_name = False
            root.config(bg="red", menu=MenuBar)
            # File Menu Starts

            FileMenu = Menu(MenuBar, tearoff=0)
            FileMenu.config(
                background="black",
                borderwidth="0",
                relief=SUNKEN,
                activebackground="#292A2D",
            )
            FileMenu.config(activebackground="#292A2D")
            # To open new file
            FileMenu.add_command(
                label="New",
                command=newFile,
                background="#292A2D",
                foreground="white",
                activebackground="#4B4C4F",
            )

            FileMenu.add_command(
                label="Open",
                command=openFile,
                background="#292A2D",
                foreground="white",
                activebackground="#4B4C4F",
            )
            # To save the current file
            FileMenu.add_command(
                label="Save",
                command=lambda: save_file(),
                background="#292A2D",
                foreground="white",
                activebackground="#4B4C4F",
            )
            FileMenu.add_command(
                label="Save As",
                command=lambda: save_as_File(),
                background="#292A2D",
                foreground="white",
                activebackground="#4B4C4F",
            )
            FileMenu.add_command(
                label="Rename",
                command=lambda: rename_file(),
                background="#292A2D",
                foreground="white",
                activebackground="#4B4C4F",
            )
            FileMenu.add_command(
                label="Exit",
                command=quitApp,
                foreground="white",
                background="#292A2D",
                activebackground="#4B4C4F",
            )
            MenuBar.add_cascade(
                label="File",
                menu=FileMenu,
                foreground="white",
                activebackground="#4B4C4F",
            )

            # File Menu ends
            def select_font(font):
                size = TextArea["font"]
                num = ""
                for i in size:
                    if i in "1234567890":
                        num += i
                real_size = int(num)
                new_font_size = (font, real_size)
                TextArea.config(font=new_font_size)

            def size_change(event):

                original_font = TextArea["font"]
                find_font = ""
                var = ""
                for i in original_font:
                    if i == " " or i.isalpha():
                        var += i
                size = 0

                find_font = var.rstrip()
                new_str = original_font.split()
                for i in new_str:
                    for a in i:
                        if a in "0123456789":
                            size = int(i)
                if size != 60 and event.delta == 120:
                    size += 1
                if size != 6 and event.delta == -120:
                    size -= 1
                new_font = (find_font, size)
                TextArea.configure(font=new_font)

            def change_size(size):
                global var
                lb = Label(mainarea, text=var, anchor=E)
                lb.pack(fill=X, side=TOP)
                var = len(str(TextArea.get("1.0", "end-1c")))
                lb.config(text=var)

                def update(event):
                    var = len(str(TextArea.get("1.0", "end-1c")))
                    lb.config(text=var)

                TextArea.bind("<KeyPress>", update)
                TextArea.bind("<KeyRelease>", update)
                original_font = TextArea["font"]
                find_font = ""
                var = ""
                for i in original_font:
                    if i == " " or i.isalpha():
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
                    "start", background="#FFFF00", foreground="#292A2D"
                )
                try:
                    TextArea.tag_add("start", "sel.first", "sel.last")
                except TclError:
                    pass

            def secondary(*event):
                replace_window = Toplevel(mainarea)
                replace_window.focus_set()
                replace_window.grab_set()
                replace_window.title("Replace")
                replace_entry = Entry(replace_window)
                find_entry_new = Entry(replace_window)
                find_entry_new.grid(row=0, column=0)
                replace_button = Button(
                    replace_window,
                    text="Replace",
                    command=lambda: replacenfind(
                        find_entry_new.get(), replace_window, str(replace_entry.get())
                    ),
                )
                replace_button.grid(row=1, column=1)
                replace_entry.grid(row=1, column=0)

            def primary(*event):
                find_window = Toplevel(mainarea)
                find_window.geometry("100x50")
                find_window.focus_set()
                find_window.grab_set()
                find_window.title("Find")
                find_entry = Entry(find_window)
                find_button = Button(
                    find_window,
                    text="Find",
                    command=lambda: find(find_entry.get(), find_window),
                )
                find_entry.pack()
                find_button.pack(side="right")

            def replacenfind(value, window, replace_value):
                text_find = str(value)
                index = "1.0"
                TextArea.tag_remove("found", "1.0", END)
                if value:
                    while 1:
                        index = TextArea.search(
                            text_find, index, nocase=1, stopindex=END
                        )
                        if not index:
                            break
                        lastidx = "% s+% d" % (index, len(text_find))
                        TextArea.delete(index, lastidx)
                        TextArea.insert(index, replace_value)
                        lastidx = "% s+% d" % (index, len(replace_value))
                        TextArea.tag_add("found", index, lastidx)
                        index = lastidx
                    TextArea.tag_config("found", foreground="blue")
                window.focus_set()

            def find(value, window):
                text_find = str(value)
                index = "1.0"
                TextArea.tag_remove("found", "1.0", END)
                if value:
                    while 1:
                        index = TextArea.search(
                            text_find, index, nocase=1, stopindex=END
                        )
                        if not index:
                            break
                        lastidx = "% s+% dc" % (index, len(text_find))
                        TextArea.tag_add("found", index, lastidx)
                        index = lastidx
                    TextArea.tag_config("found", foreground="red")
                window.focus_set()

            def popup_menu(e):
                my_menu.tk_popup(e.x_root, e.y_root)

            root.bind("<Control-Key-f>", primary)
            root.bind("<Control-Key-h>", secondary)

            EditMenu = Menu(MenuBar, tearoff=0)
            EditMenu.config(
                bg="#292A2D", bd="0", relief="ridge", activebackground="#292A2D"
            )
            TextArea.bind("<Control-MouseWheel>", size_change)

            my_menu = Menu(
                mainarea, tearoff=0, bd="0", borderwidth="0", background="#292A2D"
            )
            my_menu.config(bg="#292A2D", bd="0", activebackground="#292A2D")
            my_menu.add_command(
                label="Highlight",
                command=highlight_text,
                foreground="white",
                background="#292A2D",
                activebackground="#4B4C4F",
            )
            my_menu.add_command(
                label="Copy",
                command=copy,
                foreground="white",
                background="#292A2D",
                activebackground="#4B4C4F",
            )
            my_menu.add_command(
                label="Cut",
                command=cut,
                background="#292A2D",
                foreground="white",
                activebackground="#4B4C4F",
            )
            my_menu.add_command(
                label="Paste",
                command=paste,
                foreground="white",
                background="#292A2D",
                activebackground="#4B4C4F",
            )
            my_menu.add_separator()

            def undo():
                try:
                    TextArea.edit_undo()
                except:
                    pass

            def redo():
                try:
                    TextArea.edit_redo()
                except:
                    pass

            try:
                my_menu.add_command(
                    label="Undo",
                    command=undo,
                    foreground="white",
                    background="#292A2D",
                    activebackground="#4B4C4F",
                )
            except:
                pass

            try:
                my_menu.add_command(
                    label="Redo",
                    command=redo,
                    foreground="white",
                    background="#292A2D",
                    activebackground="#4B4C4F",
                )
            except:
                pass
            TextArea.focus_set()
            TextArea.bind("<Button-3>", popup_menu)

            # To give a feature of cut, copy and paste
            highlight_text_button = Button(
                MenuBar, text="highlight", command=highlight_text
            )
            highlight_text_button.grid(row=0, column=5, sticky=W)
            submenu = Menu(EditMenu, tearoff=0)
            submenu_size = Menu(EditMenu, tearoff=0)
            submenu.config(bg="#292A2D", bd="0", activebackground="#292A2D")
            submenu_size.config(bg="#292A2D", bd="0",
                                activebackground="#292A2D")

            submenu.add_command(
                label="MS Sans Serif",
                command=lambda: select_font("MS Sans Serif"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Arial",
                command=lambda: select_font("Arial"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Bahnschrift",
                command=lambda: select_font("Bahnschrift"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Cambria",
                command=lambda: select_font("Cambria"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Consolas",
                command=lambda: select_font("Consolas"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Courier",
                command=lambda: select_font("Courier"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Century",
                command=lambda: select_font("Century"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Calibri",
                command=lambda: select_font("Calibri"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Yu Gothic",
                command=lambda: select_font("Yu Gothic"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Times New Roman",
                command=lambda: select_font("Times New Roman"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Sylfaen",
                command=lambda: select_font("Sylfaen"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Nirmala UI",
                command=lambda: select_font("Nirmala UI"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Ebrima",
                command=lambda: select_font("Ebrima"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Comic Sans MS",
                command=lambda: select_font("Comic Sans MS"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Microsoft PhagsPa",
                command=lambda: select_font("Microsoft PhagsPa"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Lucida  Console",
                command=lambda: select_font("Lucida Console"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Franklin Gothic Medium",
                command=lambda: select_font("Franklin Gothic Medium"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Cascadia Code",
                command=lambda: select_font("Cascadia Code"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="6",
                command=lambda: change_size(6),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="7",
                command=lambda: change_size(7),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="8",
                command=lambda: change_size(8),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="9",
                command=lambda: change_size(9),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="10",
                command=lambda: change_size(10),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="11",
                command=lambda: change_size(11),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="12",
                command=lambda: change_size(12),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="13",
                command=lambda: change_size(13),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="14",
                command=lambda: change_size(14),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="15",
                command=lambda: change_size(15),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="16",
                command=lambda: change_size(16),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="17",
                command=lambda: change_size(17),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="18",
                command=lambda: change_size(18),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="19",
                command=lambda: change_size(19),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="20",
                command=lambda: change_size(20),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="21",
                command=lambda: change_size(21),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="22",
                command=lambda: change_size(22),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="23",
                command=lambda: change_size(23),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="24",
                command=lambda: change_size(24),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="25",
                command=lambda: change_size(25),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="26",
                command=lambda: change_size(26),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="27",
                command=lambda: change_size(27),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="28",
                command=lambda: change_size(28),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="29",
                command=lambda: change_size(29),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(30),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(31),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(32),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(33),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(34),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(35),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(36),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(37),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(38),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(39),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(40),
                foreground="white",
                activebackground="#4B4C4F",
            )

            EditMenu.add_command(
                label="Text Color",
                command=change_color,
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Background Color",
                command=bg_color,
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Cut",
                command=cut,
                accelerator="(Ctrl+x)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Copy",
                command=copy,
                accelerator="(Ctrl+c)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Paste",
                command=paste,
                accelerator="(Ctrl+v)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Find",
                command=primary,
                accelerator="(Ctrl+f)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Replace",
                command=secondary,
                accelerator="(Ctrl+h)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Undo",
                command=TextArea.edit_undo,
                accelerator="(Ctrl+z)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Redo",
                command=TextArea.edit_redo,
                accelerator="(Ctrl+y)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_cascade(
                label="Font",
                menu=submenu,
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_cascade(
                label="Size",
                menu=submenu_size,
                foreground="white",
                activebackground="#4B4C4F",
            )
            MenuBar.add_cascade(
                label="Edit",
                menu=EditMenu,
                foreground="white",
                activebackground="#4B4C4F",
            )

            def callback(event):
                save_file()

            def second_callback(event):
                file = None
                save_as_File(file)
                # To Open already existing file

            # bindings
            root.bind("<Control-Key-s>", callback)
            root.bind("<Control-Shift-S>", second_callback)
            root.bind("<Control-Key-x>", cut)
            root.bind("<Control-Key-c>", copy)
            root.bind("<Control-Key-v>", paste)
            # Help Menu Starts
            HelpMenu = Menu(
                MenuBar, tearoff=0, bg="#292A2D", bd="0", activebackground="#292A2D"
            )
            HelpMenu.add_command(
                label="About Notepad",
                command=about,
                foreground="white",
                activebackground="#4B4C4F",
            )
            MenuBar.add_cascade(
                label="Help",
                menu=HelpMenu,
                foreground="white",
                activebackground="#4B4C4F",
            )

            # Help Menu Ends
            MenuBar.pack_propagate(0)
            sidebar.pack_propagate(0)
            root.config(menu=MenuBar)

    # main content area
    # main content area
    pass_img = tk_image.PhotoImage(image.open(f"{path}password.png"))
    notes_img = tk_image.PhotoImage(image.open(f"{path}notes.png"))
    mainarea = Frame(root, bg="#292A2D", width=500, height=500)
    mainarea.pack(expand=True, fill="both", side="right")
    new_button = tk_image.PhotoImage(image.open(f"{path}new_but.jpg"))
    button = Button(
        sidebar,
        image=new_button,
        text='Passwords',
        bg='#292A2D',
        compound=CENTER,
        border=0,
        bd=0,
        borderwidth=0,
        highlightthickness=0,
        highlightcolor='#292A2D',
        command=lambda: testing(
            root, mainarea, username, hash_password, button),
    )
    my_cursor.execute(
        "select email_id,salt_recovery from data_input where username = (?)",
        (simple_encrypt(username),),
    )
    hash_password = hashlib.sha3_512(
        (password_new + username).encode()).hexdigest()
    email_id = ""
    for email in my_cursor.fetchall():
        email_id = simple_decrypt(email[0])
    # getting password
    # generating the static salt and decrypting the password
    email_split = ""
    decrypted_string = ""
    word = email_id.split()
    for i in word:
        for a in i:
            if i == "@":
                break
            else:
                email_split += i
    val = email_split[::-1]

    # decrypting the recovery passworwd using pbkdf2
    my_cursor.execute(
        "select recovery_password,salt_recovery from data_input where username = (?)",
        (simple_encrypt(username),),
    )
    encrypted_pass = ""
    d = my_cursor.fetchall()
    encrypt, salt = '', ''
    for i in d:
        salt = i[1]
        encrypt = i[0]

    password = email_id + hash_password
    key = pbkdf2.PBKDF2(password, salt).read(32)
    aes = pyaes.AESModeOfOperationCTR(key)
    encrypted_pass = aes.decrypt(encrypt)
    notes_buttons = Button(
        sidebar,
        image=new_button,
        text='Notes',
        bg='#292A2D',
        compound=CENTER,
        border=0,
        bd=0,
        borderwidth=0,
        highlightthickness=0,
        highlightcolor='#292A2D',
        command=note_pad_sec,

    )
    sidebar_icon.grid(row=0, column=1)
    button.grid(row=1, column=1)
    button.place(x=0, y=150 + 20)
    notes_buttons.grid(row=2, column=1)
    notes_buttons.place(x=0, y=140 + 20 + 20 + 17)

    # profile_button.grid(row=2,column=1)
    settings_image = tk_image.PhotoImage(image.open(f"{path}settings.png"))
    settings_button = Button(
        sidebar,
        activebackground="#292A2D",
        image=settings_image,
        fg="white",
        bg="#292A2D",
        border="0",
        command=lambda: settings(
            username,
            root,
            hash_password,
            mainarea,
            button,
            encrypted_pass,
            password_new,
        ),
        relief=FLAT,
        highlightthickness=0,
        activeforeground="white",
        bd=0,
        borderwidth=0,
    )
    profile_object = Profile_view(
        username,
        password_new,
        email_id,
        encrypted_pass,
        hash_password,
        mainarea,
        button,
        notes_buttons,
        root,
        my_cursor
    )

    profile_button = Button(
        sidebar,
        image=new_button,
        text=f'Profile',
        bg='#292A2D',
        compound=CENTER,
        border=0,
        bd=0,
        borderwidth=0,
        highlightthickness=0,
        highlightcolor='#292A2D',
        command=lambda: profile_object.profile_window(
            mainarea, root, profile_button),

    )
    profile_button.photo = new_button
    profile_button.grid(row=3, column=1)
    profile_button.place(x=0, y=140 + 20 + 20 + 30 + 14)

    settings_button.photo = settings_image
    settings_button.grid(row=10, column=1, columnspan=1)
    settings_button.place(x=30 + 50 + 10, y=440 + 200 + 20)

    root.mainloop()








def get(window, name):
    global l
    for i in l:
        for a in i:
            if a == name:
                d = tk_image.PhotoImage(image.open(i[a]), master=window)
                return d



def splash_screen(fn, username, main_password, passw):
    import time

    try:
        splash_screen = Tk()
        loading_acc = Label(
            splash_screen, fg="black", bg="white", text="Loading Your Accounts....."
        )
        # Progress bar widget
        progress = Progressbar(
            splash_screen, orient=HORIZONTAL, length=100, mode="determinate"
        )

        # Function responsible for the updation
        # of the progress bar value
        def bar():
            try:
                for i in range(0, 101):
                    progress["value"] = i
                    splash_screen.update_idletasks()
                    time.sleep(0.01)
            except:
                pass

        progress.pack(pady=10)
        loading_acc.pack(pady=20)
        threading.Thread(target=bar).start()
        splash_screen.config(bg="white")
        width_window = 400
        height_window = 100
        screen_width = splash_screen.winfo_screenwidth()
        screen_height = splash_screen.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        splash_screen.geometry("%dx%d+%d+%d" %
                               (width_window, height_window, x, y))

        splash_screen.overrideredirect(True)
        splash_screen.after(
            1600, lambda: fn(username, main_password, passw, splash_screen)
        )
        splash_screen.mainloop()
    except:
        pass



def login(*window):
    global unhide_img
    try:
        for i in window:
            i.destroy()
    except:
        pass

    login_window = Tk()

    login_window.resizable(False, False)
    login_window.title("Login")
    width_window = 1057
    height_window = 700
    login_window.focus_set()
    login_window.grab_set()
    login_window.config(bg="white")
    screen_width = login_window.winfo_screenwidth()
    screen_height = login_window.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2
    login_window.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))

    image1 = tk_image.PhotoImage(image.open(f"{path}loginbg.jpg"))
    image1_label = Label(login_window, image=image1, bd=0)
    image1_label.image = image1
    image1_label.place(x=0, y=0)

    labelframe = LabelFrame(
        login_window, bg="#06090F", width=900, height=450, relief="solid"
    )
    labelframe.place(x=80, y=125)

    # canvas for showing lines
    my_canvas = Canvas(labelframe, bg="grey", width=1, height=440 + 2)
    my_canvas.place(x=490 - 50, y=0)
    my_canvas.create_line(500, 0, 490, 450, width=0, fill="grey")

    # all label text widgets

    create_text = Label(
        labelframe,
        fg="#CACBC7",
        bg="#06090F",
        font=("Yu Gothic Ui", 15),
        text="If you don't already have an account click\nthe button below to create your account.",
        justify=LEFT,
    )
    create_text.place(x=485, y=50, anchor="w")

    or_text = Label(
        labelframe, text="OR", fg="#CACBC7",
        bg="#06090F", font=("Yu Gothic Ui", 15)
    )
    or_text.place(x=655, y=195)

    forgot_text = Label(
        labelframe,
        fg="#CACBC7",
        bg="#06090F",
        text="Can't login to your account?",
        font=("Yu Gothic Ui", 15),
        justify=LEFT,
    )
    forgot_text.place(x=485, y=300, anchor="w")

    # ------------------Entry---------------------------
    input_entry = Entry(
        labelframe,
        width=20 + 5,
        fg="#CACBC7",
        bg="#06090F",
        relief=RAISED,
        selectforeground="white",
        bd=0,
        insertbackground="#CACBC7",
        font=("consolas", 15, "normal"),
    )

    pass_entry = Entry(
        labelframe,
        fg="#CACBC7",
        bg="#06090F",
        relief=RAISED,
        selectforeground="#CACBC7",
        bd=0,
        insertbackground="#CACBC7",
        font=("consolas", 15, "normal"),
    )

    pass_entry.icursor(0)
    input_entry.icursor(0)

    pass_entry.place(x=50 + 3, y=200 + 30)
    input_entry.place(x=50 + 3, y=150)
    # login label
    login_label = Label(
        labelframe,
        text="Login",
        fg="#CACBC7",
        bg="#06090F",
        font=("Cascadia Mono SemiBold", 20, "bold"),
    )
    login_label.place(x=50, y=70)

    # dot label

    Frame(labelframe, width=280, height=2,
          bg="#CACBC7").place(x=50 + 3, y=230 + 30)
    Frame(labelframe, width=280, height=2,
          bg="#CACBC7").place(x=50 + 3, y=150 + 30)

    # ------------------Button---------------------------

    forgot = Button(
        labelframe,
        text="FORGOT PASSWORD?",
        width=33,
        command=lambda: login_password("Forgot Password"),
        fg="white",
        bg="#405A9B",
        border="0",
        highlightcolor="white",
        activebackground="#405A9B",
        activeforeground="white",
        relief=RAISED,
        font=("Segoe UI Semibold", 15),
    )
    register_button = Button(
        labelframe,
        text="CREATE ACCOUNT",
        width=33,
        command=lambda: register(window, login_window),
        fg="white",
        bg="orange",
        border="0",
        highlightcolor="white",
        activebackground="orange",
        activeforeground="white",
        relief=RAISED,
        font=("Segoe UI Semibold", 15),
    )

    register_button.place(x=485 + 2, y=100)

    forgot.place(x=485, y=340)
    bar_label = Label(labelframe, text="|", bg="white", fg="white", font=(100))

    bar_label.place(x=200, y=470 - 10 + 2)

    unhide_img = tk_image.PhotoImage(image.open(f"{path}eye.png"))
    show_both_1 = Button(
        labelframe,
        image=unhide_img,
        bg="#06090F",
        command=lambda: password_sec(pass_entry, show_both_1),
        highlightcolor="#06090F",
        activebackground="#06090F",
        activeforeground="#06090F",
        bd=0,
        relief=RAISED,
    )
    show_both_1.config(
        image=unhide_img,
    )
    show_both_1.photo = unhide_img

    def login_checking_1(*event):
        try:
            password = str(pass_entry.get())
            username = str(input_entry.get())
            login = Login(username, password)
            if username != "" or password != "":
                check, main_password, passw = login.login_checking()
                if check:
                    try:
                        root = Tk()
                        root.withdraw()

                        messagebox.showinfo(
                            "Success", "You have now logged in ")
                        root.destroy()
                        try:
                            login_window.destroy()
                        except:
                            pass
                        splash_screen(window_after, username,
                                      main_password, passw)
                    except:
                        pass
                else:
                    pass
            else:
                if username == "":
                    messagebox.showwarning("Error", "Cannot have username")
                elif password == "":
                    messagebox.showwarning(
                        "Error", "Cannot have blank password")
        except:
            pass

    login_window.bind("<Return>", login_checking_1)

    input_entry.insert(END, "Username")
    input_entry.config(foreground="grey")
    pass_entry.insert(END, "Password")
    pass_entry.config(foreground="grey")
    pass_entry.config(show="")

    sub_button = Button(
        labelframe,
        bd=0,
        width=23,
        height=1,
        text="LOG IN",
        font=("Cascadia Mono SemiBold", 15),
        activeforeground="white",
        relief=SUNKEN,
        fg="white",
        bg="#C52522",
        activebackground="#C52522",
        command=login_checking_1,
    )
    sub_button.place(x=50 + 3, y=300 + 30)

    show_both_1.place(x=300, y=200 + 30 - 5)

    input_entry.bind(
        "<FocusIn>",
        lambda event, val_val=input_entry, index=1: handle_focus_in(
            val_val, index, 0),
    )
    input_entry.bind(
        "<FocusOut>",
        lambda event, val_val=input_entry, val="Username", index=1: handle_focus_out(
            val_val, val, index
        ),
    )

    pass_entry.bind(
        "<FocusIn>",
        lambda event, val_val=pass_entry, index=2: handle_focus_in(
            val_val, index, 0),
    )
    pass_entry.bind(
        "<FocusOut>",
        lambda event, val_val=pass_entry, val="Password", index=2: handle_focus_out(
            val_val, val, index
        ),
    )


def register(window, *a):
    try:
        for wins in a:
            wins.destroy()
        window.destroy()

    except:
        pass
    login_window1 = Tk()
    login_window1.resizable(False, False)
    login_window1.focus_set()

    login_window1.title("Register")
    login_window1.config(bg="#292A2D")
    width_window = 1057
    height_window = 700
    screen_width = login_window1.winfo_screenwidth()
    screen_height = login_window1.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2

    login_window1.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))

    image1 = tk_image.PhotoImage(image.open(f"{path}background.jpg"))

    image1_label = Label(login_window1, bd=0, image=image1)
    image1_label.image = image1
    image1_label.place(x=0, y=0)
    iconimage = tk_image.PhotoImage(image.open(f"{path}member.png"))
    labelframe1 = LabelFrame(
        login_window1,
        bg="#292A2D",
        width=550,
        height=550,
        borderwidth=2,
        relief="solid",
    )
    labelframe1.place(x=270, y=75)

    icon_label = Label(labelframe1, image=iconimage, bg="#292A2D")
    icon_label.image = iconimage
    icon_label.place(x=180, y=20 + 30)

    # ------------------Labels---------------------------

    username = Label(
        labelframe1,
        fg="#ebebeb",
        text="Username",
        bd=5,
        bg="#292A2D",
        font=("Yu Gothic Ui", 15),
    )
    password = Label(
        labelframe1,
        fg="#ebebeb",
        text="Password",
        bd=5,
        bg="#292A2D",
        font=("Yu Gothic Ui", 15),
    )
    email_id = Label(
        labelframe1,
        fg="#ebebeb",
        text="Recovery Email",
        bg="#292A2D",
        bd=5,
        font=("Yu Gothic Ui", 15),
    )
    email_password = Label(
        labelframe1,
        fg="#ebebeb",
        text="Recovery Password",
        bg="#292A2D",
        bd=5,
        font=("Yu Gothic Ui", 15),
    )
    # placing the labels
    username.place(x=0, y=170 + 20 + 40 - 2)
    password.place(x=0, y=220 + 20 + 40 - 2)
    email_id.place(x=0, y=270 + 20 + 40 - 2)
    email_password.place(x=0, y=320 + 20 + 40 - 2)

    # ------------------Entry---------------------------
    username_entry = Entry(
        labelframe1,
        width=20,
        borderwidth=0,
        fg="#ebebeb",
        bg="#292A2D",
        relief=SUNKEN,
        insertbackground="white",
        font=("segoe ui", 15, "normal"),
    )
    password_entry = Entry(
        labelframe1,
        show="*",
        fg="#ebebeb",
        bg="#292A2D",
        borderwidth=0,
        width=17,
        insertbackground="white",
        font=("segoe ui", 15, "normal"),
    )
    email_id_entry = Entry(
        labelframe1,
        borderwidth=0,
        fg="#ebebeb",
        bg="#292A2D",
        width=20,
        insertbackground="white",
        font=("segoe ui", 15, "normal"),
    )
    email_password_entry = Entry(
        labelframe1,
        borderwidth=0,
        fg="#ebebeb",
        bg="#292A2D",
        width=17,
        show="*",
        insertbackground="white",
        font=("segoe ui", 15, "normal"),
    )

    username_entry.place(x=230-20, y=170 + 18 + 40 + 4-2)
    password_entry.place(x=230-20, y=220 + 18 + 40 + 4-2)
    email_id_entry.place(x=230-20, y=270 + 18 + 40 + 4-2)
    email_password_entry.place(x=230-20, y=320 + 18 + 40 + 4-2)

    Frame(labelframe1, width=220, height=2, bg="#ebebeb").place(
        x=230-20, y=170 + 18 + 40 + 4 + 20 + 7-2
    )
    Frame(labelframe1, width=220, height=2, bg="#ebebeb").place(
        x=230-20, y=220 + 18 + 40 + 4 + 20 + 7-2
    )
    Frame(labelframe1, width=220, height=2, bg="#ebebeb").place(
        x=230-20, y=270 + 18 + 40 + 4 + 20 + 7-2
    )
    Frame(labelframe1, width=220, height=2, bg="#ebebeb").place(
        x=230-20, y=320 + 18 + 40 + 4 + 20 + 7-2
    )

    # register function
    def register_saving(a, b, c, d):
        submit_but.config(state=DISABLED)
        username_register = str(a)
        password_register = str(b)
        email_id_register = str(c)
        email_password_register = str(d)
        if username_register == "" or password_register == "":
            messagebox.showinfo("Fields Empty", "Fields cannot be empty")
        else:
            print(email_id_register)
            register_user = Register(
                username_register,
                password_register,
                email_id_register,
                email_password_register,
                window_after
            )
            if register_user.check_pass_length():
                if register_user.check_password_integrity(password_register):
                    if register_user.email_exists():
                        registering = register_user.saving(my_cursor)
                        if registering:
                            messagebox.showinfo(
                                "Error", "Username or email is unavailable")
                            submit_but.config(state=NORMAL)
                        if not registering:
                            register_user.creation(login_window1)

                    else:
                        root2 = Tk()
                        root2.withdraw()
                        messagebox.showinfo(
                            "Error", "Invalid Email"
                        )
                        submit_but.config(state=NORMAL)

                        root2.destroy()
                else:
                    root2 = Tk()
                    root2.withdraw()
                    messagebox.showinfo(
                        "Error", "Please provide a stronger password"
                    )
                    submit_but.config(state=NORMAL)
                    root2.destroy()

            else:
                root2 = Tk()
                root2.withdraw()
                messagebox.showinfo(
                    "Error", "Please provide password greater than 6 characters"
                )
                submit_but.config(state=NORMAL)
                root2.destroy()

    # except:
    #     pass

    submit_but = Button(
        labelframe1,
        bd=0,
        width=20,
        height=2,
        text="R E G I S T E R",
        font=("consolas"),
        fg="#292A2D",
        activeforeground="#292A2D",
        bg="#994422",
        activebackground="#994422",
        command=lambda: register_saving(str(username_entry.get()), str(password_entry.get()), str(email_id_entry.get()),
                                        str(email_password_entry.get())))

    unhide_img = tk_image.PhotoImage(image.open(f"{path}eye.png"))

    show_both_1 = Button(
        labelframe1,
        image=unhide_img,
        command=lambda: password_sec(password_entry, show_both_1),
        fg="#292A2D",
        bg="#292A2D",
        bd=0,
        highlightcolor="#292A2D",
        activebackground="#292A2D",
        activeforeground="#292A2D",
        relief=RAISED,
    )
    show_both_1.image = unhide_img
    show_both_12 = Button(
        labelframe1,
        image=unhide_img,
        command=lambda: password_sec(email_password_entry, show_both_12),
        fg="#292A2D",
        bg="#292A2D",
        bd=0,
        highlightcolor="#292A2D",
        activebackground="#292A2D",
        activeforeground="#292A2D",
        relief=RAISED,
    )
    show_both_12.image = unhide_img

    show_both_1.place(x=420-20 , y=220 + 18 + 34)
    show_both_12.place(x=420-20, y=320 + 18 + 34)

    login_button = Button(
        labelframe1,
        text="L O G I N",
        width=20,
        height=2,
        font=("consolas"),
        fg="#292A2D",
        bg="#994422",
        activebackground="#994422",
        bd=0,
        relief=SUNKEN,
        command=lambda: login(login_window1),
    )
    login_button.place(x=30, y=470)

    submit_but.place(x=320, y=470)
    generate = Button(        labelframe1,
            text="Generate",
            fg="#292A2D",
            bg="#994422",
            font=("consolas"),
            activebackground="#994422",
            bd=0,
            relief=SUNKEN,
            command=lambda:pass_generator(password_entry))
    generate.place(x=440, y=220 + 18 + 39 )
    generate1 = Button(        labelframe1,
            text="Generate",
            fg="#292A2D",
            bg="#994422",
            font=("consolas"),
            activebackground="#994422",
            bd=0,
            relief=SUNKEN,
        command=lambda: pass_generator(email_password_entry))
    generate1.place(x=440, y=320 + 18 + 40 + 4-2)
    login_window1.mainloop()


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
    command=lambda: login(root),
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
    command=lambda: register(root),
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
