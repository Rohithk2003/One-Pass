import mysql.connector as m
import glob
import json
import sys
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
from tkhtmlview import HTMLLabel
import time
import atexit

bufferSize = 64 * 1024
running = True

al = False
ind = None

if platform.system() == "Windows":
    l = os.path.dirname(os.path.realpath(__file__)).split("\\")
    dir_path = ""
    for i in l:
        if i != "data":
            dir_path += i + "\\"
    path = dir_path + "images\\"
    json_path = dir_path + "json_files\\"
if platform.system() == "Darwin":
    l = os.path.dirname(os.path.realpath(__file__)).split("/")
    dir_path = ""
    for i in l:
        if i != "data":
            dir_path += i + "/"
    path = dir_path + "/images/"
    json_path = dir_path + "json_files\\"
if platform.system() == "Linux":
    l = os.path.dirname(os.path.realpath(__file__)).split("/")
    dir_path = ""
    for i in l:
        if i != "data":
            dir_path += i + "/"
    path = dir_path + "/images/"
    json_path = dir_path + "json_files\\"
fa = None
testing_strng = ""
var = 0

# database

connection = m.connect(
    host="localhost", user="root", passwd="rohithk123", autocommit=True
)
my_cursor = connection.cursor()
my_cursor.execute("create database if not exists users")
my_cursor.execute("use users")
my_cursor.execute(
    "ALTER DATABASE `%s` CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_ci'" % "users"
)
my_cursor.execute(
    "create table if not exists usersdata (username varchar(255) primary key,email_id longtext,password blob ,salt blob, recovery_password LONGBLOB, salt_recovery blob) "
)
my_cursor.execute(
    "create table if not exists userspin (username varchar(255) primary key,password blob ,salt blob) "
)


def remove_decrypted():
    global running, al
    file_name = ""
    with open(f"{json_path}settings.json", "r") as f:
        value = json.load(f)
    for i in value:
        if value[i] == 1:
            file_name = f"{i}decrypted.bin"
            break
    ls = glob.glob("*decrypted.bin")
    if file_name in ls:
        ls.remove(file_name)
    for i in ls:
        os.remove(i)
    if os.path.exists("otp.bin.aes"):
        os.remove("otp.bin.aes")
    running = False
    al = False

    return


def destroy_all(root):
    for widget in root.winfo_children():
        if isinstance(widget, tix.Toplevel):
            widget.destroy()


def gotologin(master):
    global running, al
    running = False
    al = False
    username = ""
    with open(f"{json_path}settings.json", "r") as f:
        value = json.load(f)
        for i in value:
            if value[i] == 1:
                username = i
                value[i] = 0
                break
    with open(f"{json_path}settings.json", "w") as f:
        json.dump(value, f)
    if username:
        os.remove(f"{username}decrypted.bin")
    running = False
    al = False
    try:
        master.eval("::ttk::CancelRepeat")
        master.destroy()
    except:
        pass
    try:
        app = main_class()
        app.mainloop()
    except:
        pass


def write_value(real_username, value, variable):
    if real_username != "Username" and list(real_username) != []:
        values = {}
        if os.path.exists(f"{json_path}settings.json"):
            with open(f"{json_path}settings.json", "r") as f:
                values = json.load(f)
            values[real_username] = value
            with open(f"{json_path}settings.json", "w") as f:
                json.dump(values, f)
        else:
            values[real_username] = value
            with open(f"{json_path}settings.json", "w") as f:
                json.dump(values, f)

    else:
        variable.set(0)
        messagebox.showinfo("Details not provided",
                            "Please provide your username")


class PinDecryption(Frame):
    def __init__(self, master, username):
        self.master = master
        global al, running

        Frame.__init__(self, self.master)
        self.username = username
        self.master.title("Pin")
        self.config(bg="#121212")
        self.running = running
        self.al = al
        width_window = 1057

        def alpha():
            if str(enter_alpha["text"]) == "Enter Alphanumeric pin":
                self.running = False
                self.al = True
                enter_alpha.config(text="Enter Number pin")
                threading.Thread(target=for_alpha).start()
            elif enter_alpha["text"] == "Enter Number pin":
                self.running = True
                self.al = False
                enter_alpha.config(text="Enter Alphanumeric pin")
                threading.Thread(target=getting).start()

        def for_alpha():
            while self.al:

                try:
                    if self.ent.get():
                        save.config(state=NORMAL)
                        if len(self.ent.get()) >= 4:
                            a = self.ent.get()[:4]
                            self.ent.delete(4, END)
                except:
                    pass

        def getting():

            while self.running:
                try:
                    if self.ent.get():
                        save.config(state=NORMAL)
                        int(self.ent.get())
                        if len(self.ent.get()) >= 4:
                            a = self.ent.get()[:4]

                            self.ent.delete(4, END)
                except ValueError:
                    a = str(self.ent.get())
                    d = list(map(str, a))
                    f = 0
                    for i in d:
                        if i.isalpha():
                            f = d.index(i)
                    self.ent.delete(f, END)
                except:
                    pass

        lab = Label(
            self,
            text="Verify the security pin",
            bg="#121212",
            fg="white",
            font=("Segoe Ui", 20),
        )
        lab.place(x=width_window / 2 - 60 - 5 - 45, y=160)

        self.ent = Entry(self, width=20, font=("Segoe Ui", 15))
        self.ent.place(x=width_window / 2 - 40 - 5 - 5 - 30 - 10, y=250)
        enter_alpha = Button(
            self,
            text="Enter Alphanumeric pin",
            fg="#2A7BCF",
            activeforeground="#2A7BCF",
            bg="#121212",
            command=alpha,
            activebackground="#121212",
            bd=0,
            borderwidth=0,
            font=("Consolas", 14, UNDERLINE),
        )
        enter_alpha.place(x=width_window / 2 + 200 - 30 - 10, y=250)
        # adding the check box button

        t1 = threading.Thread(target=getting)

        t1.start()
        # adding the save button

        forgot_pass = Button(
            self,
            text="Go Back To Login?",
            fg="#2A7BCF",
            activeforeground="#2A7BCF",
            bg="#121212",
            command=lambda: gotologin(self.master),
            activebackground="#121212",
            bd=0,
            borderwidth=0,
            font=("Consolas", 14, UNDERLINE),
        )

        forgot_pass.place(x=700, y=300 + 30)

        def pin_save(event=None):
            if len(str(self.ent.get())) == 4:
                if self.ent.get():
                    self.running, self.al = False, False
                    self.pin = str(self.ent.get())
                    self.hash_value = hashlib.sha512(
                        self.pin.encode()).hexdigest()
                    with open(f"{json_path}pin.json", "r") as f:
                        data = json.load(f)
                    username = hashlib.sha512(
                        self.username.encode()).hexdigest()
                    for i in data:
                        if i == username:
                            if data[i] == self.hash_value:
                                main_pass = self.username + str(self.ent.get())
                                self.cipher = ""
                                self.salt = ""
                                my_cursor.execute(
                                    "select password,salt from userspin where username =(%s)",
                                    (self.username,),
                                )
                                for i in my_cursor.fetchall():
                                    self.cipher = i[0]
                                    self.salt = i[1]
                                st = retreive_key(
                                    main_pass, self.cipher, self.salt)
                                self.password = st
                                messagebox.showinfo(
                                    "Success", "Your pin has been verified"
                                )

                                self.master.switch_frame(
                                    main_window, self.username, self.password
                                )
                            else:
                                messagebox.showinfo(
                                    "Incorrect", "Incorrect Pin")

                else:
                    messagebox.showinfo("Error", "Please provide a pin")
            else:
                messagebox.showerror(
                    "Incorrect Length", "PIN must be equal to 4 characters"
                )

        # adding the save button
        save = Button(
            self,
            text="L O G I N",
            fg="#292A2D",
            activeforeground="#292A2D",
            bg="#994422",
            command=pin_save,
            state=DISABLED,
            activebackground="#994422",
            height=1,
            width=10,
            bd=0,
            borderwidth=0,
            font=("Consolas", 14),
        )
        save.place(x=width_window / 2 - 30 - 5, y=300 + 30)
        self.master.bind("<Return>", lambda event: pin_save())


def log_out(username, *window):
    for windows in window:
        windows.destroy()
    users = {}
    with open(f"{json_path}settings.json", "r") as f:
        users = json.load(f)
    for i in users:
        if i == username:
            users[i] = 0
    a = Tk()
    a.withdraw()
    messagebox.showinfo("Logged Out", "You have  successfully logged out")
    a.destroy()
    for file in glob.glob("*decrypted.bin"):
        os.remove(file)
    new_app = main_class()
    new_app.mainloop()


def settings(
    handler,
    real_username,
    master_main,
    hashed_password,
    window,
    password_button,
    rec_pas,
    original_password,
):
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
    if os.stat(f"{json_path}settings.json").st_size != 0:
        with open(f"{json_path}settings.json", "r") as f:
            values = json.load(f)
        if real_username in values.keys():
            if values[real_username] == 1:
                v.set(1)
    delete_object = Deletion(
        handler,
        real_username,
        original_password,
        hashed_password,
        window,
        my_cursor,
        master_main,
    )
    change_object = Change_details(
        master_main, real_username, original_password, hashed_password, my_cursor
    )
    deselectbutton = Button(settings_window, text="")

    keepmeloggedin = Checkbutton(
        settings_window,
        bg="#1E1E1E",
        foreground="green",
        fg="white",
        selectcolor="black",
        font=("Segoe Ui", 13),
        activebackground="#1E1E1E",
        activeforeground="white",
        text="Keep Me Logged In",
        variable=v,
        padx=20,
        command=lambda: write_value(real_username, v.get(), v),
    )
    log_label = Button(
        settings_window,
        text="Log out",
        width=20,
        font=("Segoe Ui", 13),
        fg="white",
        activebackground="#1E1E1E",
        activeforeground="white",
        bg="#1E1E1E",
        command=lambda: log_out(
            real_username, settings_window, window, master_main),
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
        justify="center",
        anchor="center",
        bg="#1E1E1E",
    )
    # text label
    Label(
        settings_window,
        text="Settings",
        font=("consolas", 30),
        fg="green",
        bg="#1E1E1E",
    ).place(x=160, y=0)

    Delete_account_button.place(x=30, y=70)
    keepmeloggedin.place(x=245, y=70)
    Delete_social_button.place(x=30, y=150)
    change_account_button.place(x=270, y=150)
    change_email_button.place(x=30, y=230)
    log_label.place(x=270, y=230)

    if os.stat(f"{real_username}decrypted.bin").st_size == 0:
        Delete_social_button.config(state=DISABLED)
    else:
        Delete_social_button.config(state=NORMAL)
    settings_window.mainloop()


# main class
class main_class(Tk):
    def __init__(self):
        tix.Tk.__init__(self)
        self.resizable(False, False)
        self.title("Password Manager")
        width_window = 1057
        height_window = 661
        self.focus_force()
        self.config(bg="#292A2D")
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        self.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        self._frame = None
        username = ""
        frame_class = ""
        if (
            os.path.exists(f"{json_path}settings.json")
            and os.stat(f"{json_path}settings.json").st_size != 0
        ):
            with open(f"{json_path}settings.json", "r") as f:
                values = json.load(f)
            for i in values:
                if values[i] == 1:
                    username = str(i)
                    break
            if username:
                if os.path.exists(f"{username}decrypted.bin"):
                    self.switch_frame(PinDecryption, username)
                else:
                    values[username] = 0
                    with open("settings.json", "w") as f:
                        json.dump(values, f)
                    self.switch_frame(Login_page)
            else:
                self.switch_frame(Login_page)

        else:
            self.switch_frame(Login_page)

    def switch_frame(self, frame_class, *args):
        global new_frame
        new_frame = frame_class(self, *args)
        if self._frame is not None:
            self._frame.destroy()
        self._frame = new_frame
        self._frame.config(width=1057, height=661)
        self._frame.place(x=0, y=0)


# login class
class Login_page(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        master.title("Login")
        self.config(bg="grey")
        global running, al
        running, al = False, False
        fa = Login_page

        # canvas for showing lines
        image1 = tk_image.PhotoImage(image.open(f"{path}loginbg.jpg"))
        image1_label = Label(self, image=image1, bd=0)
        image1_label.image = image1
        image1_label.place(x=0, y=0)

        labelframe = LabelFrame(
            self, bg="#06090F", width=900, height=450, relief="solid"
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
        self.v = IntVar()

        or_text = Label(
            labelframe, text="OR", fg="#CACBC7", bg="#06090F", font=("Yu Gothic Ui", 15)
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
        self.input_entry = Entry(
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

        self.pass_entry = Entry(
            labelframe,
            fg="#CACBC7",
            bg="#06090F",
            relief=RAISED,
            selectforeground="#CACBC7",
            bd=0,
            insertbackground="#CACBC7",
            font=("consolas", 15, "normal"),
        )

        self.pass_entry.icursor(0)
        self.input_entry.icursor(0)
        self.keepmeloggedin = Checkbutton(
            labelframe,
            bg="#06090F",
            foreground="green",
            fg="white",
            selectcolor="black",
            font=("Segoe Ui", 13),
            activebackground="#06090F",
            activeforeground="white",
            text="Keep Me Logged In",
            variable=self.v,
            padx=20,
            command=lambda: write_value(
                str(self.input_entry.get()), self.v.get(), self.v
            ),
        )
        self.pass_entry.place(x=50 + 3, y=200 + 30)
        self.input_entry.place(x=50 + 3, y=150)
        self.keepmeloggedin.place(x=30 + 3, y=280)
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
            command=lambda: login_password("Forgot Password", my_cursor),
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
            fg="white",
            bg="orange",
            command=lambda: master.switch_frame(Register_page),
            border="0",
            highlightcolor="white",
            activebackground="orange",
            activeforeground="white",
            relief=RAISED,
            font=("Segoe UI Semibold", 15),
        )

        register_button.place(x=485 + 2, y=100)

        forgot.place(x=485, y=340)
        bar_label = Label(labelframe, text="|", bg="white",
                          fg="white", font=(100))

        bar_label.place(x=200, y=470 - 10 + 2)

        unhide_img = tk_image.PhotoImage(image.open(f"{path}eye.png"))
        show_both_1 = Button(
            labelframe,
            image=unhide_img,
            bg="#06090F",
            command=lambda: password_sec(self.pass_entry, show_both_1),
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

        self.input_entry.insert(END, "Username")
        self.input_entry.config(foreground="grey")
        self.pass_entry.insert(END, "Password")
        self.pass_entry.config(foreground="grey")
        self.pass_entry.config(show="")

        sub_button = Button(
            labelframe,
            bd=0,
            width=23,
            height=1,
            text="LOG IN",
            font=("Segoe UI SemiBold", 15),
            activeforeground="white",
            relief=SUNKEN,
            fg="white",
            bg="#C52522",
            activebackground="#C52522",
            anchor="center",
            command=lambda: self.login_checking_1(master),
        )
        master.bind("<Return>", lambda event,
                    a=master: self.login_checking_1(a))
        sub_button.place(x=50 + 3, y=300 + 30)

        show_both_1.place(x=300, y=200 + 30 - 5)
        try:
            tip = tix.Balloon(master)
            tip.config(background="white")
            tip.label.config(bg="white", fg="white")
            try:
                for sub in tip.subwidgets_all():
                    sub.configure(bg="white")
            except:
                pass
            tip.subwidget("label").forget()
            tip.message.config(bg="white", fg="#06090F",
                               font=("Segoe UI SemiBold", 10))
            # display the ballon text
            tip.bind_widget(sub_button, balloonmsg="Login")
            tip.bind_widget(forgot, balloonmsg="Forgot password?")
            tip.bind_widget(register_button, balloonmsg="Register")
            tip.bind_widget(self.input_entry, balloonmsg="Username")
            tip.bind_widget(self.pass_entry, balloonmsg="Password")
        except:
            pass
        self.input_entry.bind(
            "<FocusIn>",
            lambda event, val_val=self.input_entry, index=1: handle_focus_in(
                val_val, index, 0
            ),
        )
        self.input_entry.bind(
            "<FocusOut>",
            lambda event, val_val=self.input_entry, val="Username", index=1: handle_focus_out(
                val_val, val, index
            ),
        )

        self.pass_entry.bind(
            "<FocusIn>",
            lambda event, val_val=self.pass_entry, index=2: handle_focus_in(
                val_val, index, 0
            ),
        )
        self.pass_entry.bind(
            "<FocusOut>",
            lambda event, val_val=self.pass_entry, val="Password", index=2: handle_focus_out(
                val_val, val, index
            ),
        )

    def login_checking_1(self, master, *event):

        self.username = str(self.input_entry.get())
        self.password = str(self.pass_entry.get())
        if self.username != "" or self.password != "":
            check = self.login_checking()
            if check:
                root = Tk()
                root.withdraw()

                messagebox.showinfo("Success", "You have now logged in ")
                root.destroy()
                master.switch_frame(main_window, self.username, self.password)

            else:
                pass
        else:
            if self.username == "":
                messagebox.showwarning("Error", "Cannot blank have username")
            elif self.password == "":
                messagebox.showwarning("Error", "Cannot have blank password")

    def login_checking(self):  # verifying the user
        for_hashing_both = self.password + self.username
        main_password = hashlib.sha3_512(for_hashing_both.encode()).hexdigest()
        if self.username == "Username":
            # checking for blank username
            root_error = Tk()
            root_error.withdraw()
            messagebox.showerror("Error", "Cannot have blank Username ")
            root_error.destroy()
            return False
        elif self.password == "Password":
            # checking for blank password
            root_error = Tk()
            root_error.withdraw()
            messagebox.showerror("Error", "Password cannot be empty ")
            root_error.destroy()
            return False
        else:
            for_hashing_both = self.password + self.username
            if os.path.exists(f"{self.username}.bin.aes"):
                try:
                    # trying to decrypt the users file to check whether the password entered is valid
                    pyAesCrypt.decryptFile(
                        self.username + ".bin.aes",
                        self.username + "decrypted.bin",
                        main_password,
                        bufferSize,
                    )
                except ValueError:  # if the password is incorrect
                    root = Tk()
                    root.withdraw()
                    messagebox.showerror(
                        "Error",
                        f"Wrong password for {self.username}",
                    )
                    root.destroy()
                    return False

            else:
                root_error = Tk()
                root_error.withdraw()
                messagebox.showerror(
                    "Error",
                    f"{self.username} doesn't exist, Please register or provide the correct username",
                )
                root_error.destroy()
                return False
            return True


# register class
class Register_page(Frame):
    def __init__(self, master):
        self.master = master
        Frame.__init__(self, self.master)
        global fa
        fa = Register_page
        self.master.title("Register")
        self.config(bg="grey")
        image1 = tk_image.PhotoImage(image.open(f"{path}background.jpg"))
        master.unbind("<Return>")
        image1_label = Label(self, bd=0, image=image1)
        image1_label.image = image1
        image1_label.place(x=0, y=0)
        iconimage = tk_image.PhotoImage(image.open(f"{path}member.png"))
        self.labelframe1 = LabelFrame(
            self,
            bg="#292A2D",
            width=550,
            height=550,
            borderwidth=2,
            relief="solid",
        )
        self.labelframe1.place(x=270, y=75)

        icon_label = Label(self.labelframe1, image=iconimage, bg="#292A2D")
        icon_label.image = iconimage
        icon_label.place(x=180, y=20 + 30)

        # ------------------Labels---------------------------
        username = Label(
            self.labelframe1,
            fg="#ebebeb",
            text="Username",
            bd=5,
            bg="#292A2D",
            font=("Yu Gothic Ui", 15),
        )
        password = Label(
            self.labelframe1,
            fg="#ebebeb",
            text="Master Password",
            bd=5,
            bg="#292A2D",
            font=("Yu Gothic Ui", 15),
        )
        email_id = Label(
            self.labelframe1,
            fg="#ebebeb",
            text="Recovery Email",
            bg="#292A2D",
            bd=5,
            font=("Yu Gothic Ui", 15),
        )
        email_password = Label(
            self.labelframe1,
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
        self.username_entry = Entry(
            self.labelframe1,
            width=20,
            borderwidth=0,
            fg="#ebebeb",
            bg="#292A2D",
            relief=SUNKEN,
            insertbackground="white",
            font=("segoe ui", 15, "normal"),
        )
        self.password_entry = Entry(
            self.labelframe1,
            show="*",
            fg="#ebebeb",
            bg="#292A2D",
            borderwidth=0,
            width=17,
            insertbackground="white",
            font=("segoe ui", 15, "normal"),
        )
        self.email_id_entry = Entry(
            self.labelframe1,
            borderwidth=0,
            fg="#ebebeb",
            bg="#292A2D",
            width=20,
            insertbackground="white",
            font=("segoe ui", 15, "normal"),
        )
        self.email_password_entry = Entry(
            self.labelframe1,
            borderwidth=0,
            fg="#ebebeb",
            bg="#292A2D",
            width=17,
            show="*",
            insertbackground="white",
            font=("segoe ui", 15, "normal"),
        )

        self.username_entry.place(x=230 - 20, y=170 + 18 + 40 + 4 - 2)
        self.password_entry.place(x=230 - 20, y=220 + 18 + 40 + 4 - 2)
        self.email_id_entry.place(x=230 - 20, y=270 + 18 + 40 + 4 - 2)
        self.email_password_entry.place(x=230 - 20, y=320 + 18 + 40 + 4 - 2)
        self.v = IntVar()
        # keep me logged in
        self.keepmeloggedin = Checkbutton(
            self.labelframe1,
            bg="#292A2D",
            foreground="green",
            fg="white",
            selectcolor="black",
            font=("Segoe Ui", 13),
            activebackground="#292A2D",
            activeforeground="white",
            highlightcolor="white",
            text="Keep Me Logged In",
            variable=self.v,
            padx=20,
            command=lambda: write_value(
                str(self.username_entry.get()), self.v.get(), self.v
            ),
        )
        self.keepmeloggedin.place(x=150, y=370 + 18 + 40 + 4 - 2)

        Frame(self.labelframe1, width=220, height=2, bg="#ebebeb").place(
            x=230 - 20, y=170 + 18 + 40 + 4 + 20 + 7 - 2
        )
        Frame(self.labelframe1, width=220, height=2, bg="#ebebeb").place(
            x=230 - 20, y=220 + 18 + 40 + 4 + 20 + 7 - 2
        )
        Frame(self.labelframe1, width=220, height=2, bg="#ebebeb").place(
            x=230 - 20, y=270 + 18 + 40 + 4 + 20 + 7 - 2
        )
        Frame(self.labelframe1, width=220, height=2, bg="#ebebeb").place(
            x=230 - 20, y=320 + 18 + 40 + 4 + 20 + 7 - 2
        )

        self.submit_but = Button(
            self.labelframe1,
            bd=0,
            width=20,
            height=2,
            text="R E G I S T E R",
            font=("consolas"),
            fg="#292A2D",
            activeforeground="#292A2D",
            bg="#994422",
            activebackground="#994422",
            command=lambda: self.register_saving(),
        )

        unhide_img = tk_image.PhotoImage(image.open(f"{path}eye.png"))
        self.master.bind("<Return>", lambda event: self.register_saving())

        show_both_1 = Button(
            self.labelframe1,
            image=unhide_img,
            command=lambda: password_sec(self.password_entry, show_both_1),
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
            self.labelframe1,
            image=unhide_img,
            command=lambda: password_sec(
                self.email_password_entry, show_both_12),
            fg="#292A2D",
            bg="#292A2D",
            bd=0,
            highlightcolor="#292A2D",
            activebackground="#292A2D",
            activeforeground="#292A2D",
            relief=RAISED,
        )
        show_both_12.image = unhide_img

        show_both_1.place(x=420 - 20, y=220 + 18 + 34)
        show_both_12.place(x=420 - 20, y=320 + 18 + 34)

        login_button = Button(
            self.labelframe1,
            text="B A C K",
            width=20,
            height=2,
            font=("consolas"),
            fg="#292A2D",
            bg="#994422",
            activebackground="#994422",
            bd=0,
            relief=SUNKEN,
            command=lambda: master.switch_frame(Login_page),
        )

        login_button.place(x=30, y=470)
        self.submit_but.place(x=320, y=470)

        generate = Button(
            self.labelframe1,
            text="Generate",
            fg="#292A2D",
            bg="#994422",
            font=("consolas"),
            activebackground="#994422",
            bd=0,
            relief=SUNKEN,
            command=lambda: pass_generator(self.password_entry),
        )
        generate.place(x=440, y=220 + 18 + 39)
        generate1 = Button(
            self.labelframe1,
            text="Generate",
            fg="#292A2D",
            bg="#994422",
            font=("consolas"),
            activebackground="#994422",
            bd=0,
            relief=SUNKEN,
            command=lambda: pass_generator(self.email_password_entry),
        )
        generate1.place(x=440, y=320 + 18 + 40 + 4 - 2)

    def register_saving(self, event=None):

        self.submit_but.config(state=DISABLED)
        self.username = str(self.username_entry.get())
        self.password = str(self.password_entry.get())
        self.email_password = str(self.email_password_entry.get())
        self.email = str(self.email_id_entry.get())
        if self.username == "" or self.password == "":
            messagebox.showinfo("Fields Empty", "Fields cannot be empty")
        else:
            if self.check_pass_length():
                if self.check_password_integrity():
                    if self.email_exists():
                        registering = self.saving()
                        if registering:
                            messagebox.showinfo(
                                "Error", "Username or email is unavailable"
                            )
                            self.submit_but.config(state=NORMAL)
                        if not registering:
                            self.creation()

                    else:
                        root2 = Tk()
                        root2.withdraw()
                        messagebox.showinfo("Error", "Invalid Email")
                        self.submit_but.config(state=NORMAL)

                        root2.destroy()
                else:
                    root2 = Tk()
                    root2.withdraw()
                    messagebox.showinfo(
                        "Error", "Please provide a stronger password")
                    self.submit_but.config(state=NORMAL)
                    root2.destroy()

            else:
                root2 = Tk()
                root2.withdraw()
                messagebox.showinfo(
                    "Error", "Please provide password greater than 6 characters"
                )
                self.submit_but.config(state=NORMAL)
                root2.destroy()

    def check_password_integrity(self):
        if self.username == self.password:
            return False
        with open("pass.txt", "r") as file:
            data = file.read().split()
            for i in data:
                if i == self.password:
                    return False

        return True

    def email_exists(self):
        return self.email.endswith(("gmail.com", "yahoo.com"))

    def check_pass_length(self):  # checking if the entered password is lesser than 5
        return len(self.password) >= 5

    """to create a file named user and to store his accounts and also add his details to the database"""

    def saving(self):
        my_cursor.execute("select username from usersdata")

        values_username = my_cursor.fetchall()
        for i in values_username:
            for usernames in i:
                if simple_decrypt(usernames) == self.username and os.path.exists(
                    self.username + ".bin.aes"
                ):
                    return (
                        True,
                    )  # checking whether the username already exists in the database
        email_split = ""
        word = self.email.split()
        for i in word:
            for a in i:
                if i == "@":
                    break
                else:
                    email_split += i
        val = email_split[::-1]
        main_password = val + "/" + self.email_password  # static salt
        static_salt_password = self.password + "@" + main_password
        # hashing/encrypting the password and store the dynamic salt created during create_key() fn is called along with the encrypted password in database
        cipher_text, salt_for_decryption = create_key(
            main_password, static_salt_password
        )

        for_hashing = self.password + self.username
        """for encrypting the file"""
        hash_pass = hashlib.sha3_512(for_hashing.encode()).hexdigest()
        # for encrypting the recovery password

        password_recovery_email = self.email + hash_pass
        passwordSalt = secrets.token_bytes(512)
        key = pbkdf2.PBKDF2(password_recovery_email, passwordSalt).read(32)
        aes = pyaes.AESModeOfOperationCTR(key)
        encrypted_pass = aes.encrypt(self.email_password)
        my_cursor.execute(
            "insert into usersdata values (%s,%s,%s,%s,%s,%s)",
            (
                simple_encrypt(self.username),
                simple_encrypt(self.email),
                cipher_text,
                salt_for_decryption,
                encrypted_pass,
                passwordSalt,
            ),
        )
        return False

    # adding the account
    def creation(self):

        for_hashing = self.password + self.username
        """for encrypting the file"""
        hash_pass = hashlib.sha3_512(for_hashing.encode()).hexdigest()

        file_name = self.username + ".bin"
        with open(file_name, "wb"):
            pyAesCrypt.encryptFile(
                file_name, file_name + ".aes", hash_pass, bufferSize)
        os.remove(file_name)
        # to display that his account has been created
        windows = Tk()
        windows.withdraw()
        messagebox.showinfo("Success", "Your account has been created")
        windows.destroy()
        # for opening the main section where he can store his passwords and use notepad so the file has to be decrypted
        pyAesCrypt.decryptFile(
            file_name +
            ".aes", f"{self.username}decrypted.bin", hash_pass, bufferSize
        )
        self.master.switch_frame(PinFrame, self.username, self.password)


# class which handles the main window for seeing the password
class main_window(Frame):
    def __init__(self, parent, username, password):
        Frame.__init__(self, parent)
        global var
        status_name = False
        parent.unbind("<Return>")
        parent.title("Password Manager")
        self.parent = parent
        self.var = var
        self.object = my_cursor
        self.status = status_name
        self.username = username
        self.password_new = password
        self.hash_password = hashlib.sha3_512(
            (self.password_new + self.username).encode()
        ).hexdigest()

        main_ic = tk_image.PhotoImage(image.open(f"{path}main_icon.png"))
        new_button = tk_image.PhotoImage(image.open(f"{path}_new_but.jpg"))

        self.sidebar = Frame(
            self, width=5, bg="#292A2D", height=661, relief="sunken", borderwidth=1
        )
        self.sidebar_icon = Label(
            self.sidebar,
            text=f"ONE-PASS",
            compound="top",
            font=("Segoe UI SemiBold", 15),
            fg="white",
            image=main_ic,
            bg="#292A2D",
        )
        self.sidebar_icon.image = main_ic
        self.mainarea = Frame(self, bg="#292A2D", width=1000, height=661)
        self.button = Button(
            self.sidebar,
            image=new_button,
            text="Passwords",
            bg="#292A2D",
            compound=CENTER,
            border=0,
            bd=0,
            width=132,
            borderwidth=0,
            activebackground="#292A2D",
            highlightthickness=0,
            highlightcolor="#292A2D",
            command=lambda: self.testing(parent),
        )

        settings_image = tk_image.PhotoImage(
            image.open(f"{path}\\settings.png"))
        self.settings_button = Button(
            self.sidebar,
            activebackground="#292A2D",
            image=settings_image,
            fg="white",
            bg="#292A2D",
            border="0",
            relief=FLAT,
            highlightthickness=0,
            activeforeground="white",
            bd=0,
            borderwidth=0,
            command=lambda: settings(
                self,
                self.username,
                parent,
                self.hash_password,
                self.mainarea,
                self.button,
                self.decrypted_pass,
                self.password_new,
            ),
        )
        self.settings_button.image = settings_image

        self.profile_button = Button(
            self.sidebar,
            image=new_button,
            text=f"Profile",
            bg="#292A2D",
            width=132,
            activebackground="#292A2D",
            compound=CENTER,
            command=lambda: self.temp(),
            border=0,
            bd=0,
            borderwidth=0,
            highlightthickness=0,
            highlightcolor="#292A2D",
        )
        try:
            tip = tix.Balloon(parent)
            tip.config(background="white")
            tip.label.config(bg="white", fg="white")
            try:
                for sub in tip.subwidgets_all():
                    sub.configure(bg="white")
            except:
                pass
            tip.subwidget("label").forget()
            tip.message.config(bg="white", fg="#06090F",
                               font=("Segoe UI SemiBold", 10))
            # display the ballon text
            tip.bind_widget(self.profile_button, balloonmsg="View Profile")
            tip.bind_widget(self.settings_button, balloonmsg="View Settings")
            tip.bind_widget(self.button, balloonmsg="View Password")
        except:
            pass
        self.profile_button.photo = new_button
        self.settings_button.photo = settings_image

        self.sidebar.pack(expand=False, fill="both", side="left")
        self.mainarea.pack(expand=True, fill="both", side="right")

        self.object.execute(
            "select email_id,salt_recovery from usersdata where username = (%s)",
            (simple_encrypt(self.username),),
        )

        for email in self.object.fetchall():
            self.email_id = simple_decrypt(email[0])
        email_split = ""

        word = self.email_id.split()
        for i in word:
            for a in i:
                if i == "@":
                    break
                else:
                    email_split += i
        val = email_split[::-1]
        self.object.execute(
            "select recovery_password,salt_recovery from usersdata where username = (%s)",
            (simple_encrypt(self.username),),
        )
        d = self.object.fetchall()
        encrypt, salt = "", ""
        for i in d:
            salt = i[1]
            encrypt = i[0]
        password = self.email_id + self.hash_password
        key_rec = pbkdf2.PBKDF2(password, salt).read(32)
        aes = pyaes.AESModeOfOperationCTR(key_rec)
        self.decrypted_pass = aes.decrypt(encrypt)

        self.button.grid(row=1, column=1)
        self.button.place(x=0, y=150 + 50)
        self.profile_button.grid(row=2, column=1)
        self.profile_button.place(x=0, y=140 + 20 + 20 + 3 + 14 + 30)
        self.settings_button.grid(row=10, column=1, columnspan=1)
        self.settings_button.place(x=30 + 50 + 10, y=620)
        self.sidebar_icon.grid(row=0, column=0)
        self._frame = None

    def temp(self):
        if self.button['state'] == 'disabled':
            global ind
        self.switchframe(
            Profile_view,
            self.parent,
            self.username,
            self.password_new,
            self.email_id,
            self.decrypted_pass,
            self.hash_password,
            self.object,
        )

    def testing(self, master):
        self.button["state"] = DISABLED
        self.profile_button["state"] = NORMAL
        self.parent.title("Passwords")
        self.parent.iconbitmap(f"{path}password.ico")
        self.switchframe(
            Password_display,
            self.parent,
            self.username,
            self.hash_password,
            self.object,
            self.password_new,
        )

    def switchframe(self, frame_class, master, *args):
        global new_frame

        new_frame = frame_class(
            master, self.button, self.profile_button, self, self.mainarea, *args
        )
        if self._frame is not None:
            self._frame.destroy()
        self._frame = new_frame
        self._frame.config(width=1057, height=661)
        self._frame.place(x=134, y=0)


# displaying the passwords
class Password_display(Frame):
    def __init__(
        self, main_window, button, profile_button, handler, second_frame, *args
    ):
        self.main_window = main_window
        Frame.__init__(self, self.main_window)
        self.config(bg="#292A2D")
        self.style = ttk.Style()
        button.config(state=DISABLED)

        profile_button.config(state=NORMAL)
        emptyMenu = Menu(self.main_window)
        self.main_window.config(menu=emptyMenu)
        self.main_window.unbind("<Return>")
        self.main_window.title("Passwords")
        #  # getting the username
        self.handler = handler
        self.username = args[0]
        self.hashed_password = args[1]
        self.object = args[2]
        self.password = args[3]
        self.button = button
        bg_img = tk_image.PhotoImage(image.open(f"{path}log.jpg"))

        self.subbar = Frame(
            self, bg="black", width=105, height=1057, relief="sunken", borderwidth=2
        )

        self.subbar.place(x=0, y=0)
        self.subbar.grid_propagate(False)
        scrollbar = ScrolledFrame(
            self.subbar,
            width=129,
            borderwidth=0,
            bd=0,
            height=661,
            highlightcolor="#1E1E1E",
            background="#1E1E1E",
            bg="#1E1E1E",
        )

        scrollbar.pack(expand=1, fill=Y)
        # configure the canvas
        scrollbar.bind_arrow_keys(self.subbar)
        scrollbar.bind_scroll_wheel(self.subbar)
        scrollbar.focus_force()

        # creating another frame
        self.second_frame = scrollbar.display_widget(
            Frame, bg="#1E1E1E", width=129, height=661
        )

        # add that new frame to a new window in the canvas
        image_new = tk_image.PhotoImage(image.open(f"{path}add_button.png"))

        self.add_button = Button(
            self.second_frame,
            text="Add",
            fg="white",
            image=image_new,
            compound="top",
            activeforeground="white",
            bg="#1E1E1E",
            height=60,
            activebackground="#1E1E1E",
            width=120,
            relief=RAISED,
            font=("Verdana", 10),
            command=lambda: self.addaccount(),
        )
        self.add_button.photo = image_new
        values = []
        if os.stat(f"{self.username}decrypted.bin").st_size != 0:
            with open(f"{self.username}decrypted.bin", "rb") as f:
                values = p.load(f)

        length_list = len(values)
        self.add_button.grid(row=length_list, column=0)
        self.buttons_blit()
        global ind
        if ind != None:
            with open(f'{self.username}decrypted.bin', 'rb') as f:
                val = p.load(f)
            self.account_name = val[ind][2]
            self.show_account(ind, self.account_name)

    def buttons_blit(self):

        new = []
        if os.stat(f"{self.username}decrypted.bin").st_size != 0:
            with open(f"{self.username}decrypted.bin", "rb") as f:
                val = p.load(f)
                for i in val:
                    new.append(i[2])
                d = {}
                for i in range(len(new)):
                    button_img = tk_image.PhotoImage(
                        image.open(f"{path}a.png"))
                    d[
                        Button(
                            self.second_frame,
                            text=f"{new[i]}",
                            bg="#1E1E1E",
                            fg="white",
                            height=60,
                            activeforeground="white",
                            activebackground="#1E1E1E",
                            width=120,
                            font=("Segoe UI Semibold", 9),
                            image=button_img,
                            compound="top",
                            command=lambda a=i, value=new[i]: self.show_account(
                                a, value
                            ),
                        )
                    ] = [i, button_img]

                for i in d:
                    i.image = d[i][1]
                    i.grid(row=d[i][0], column=0)
                values = []
                if os.stat(f"{self.username}decrypted.bin").st_size != 0:
                    with open(f"{self.username}decrypted.bin", "rb") as f:
                        values = p.load(f)
                length_list = len(values)
                self.add_button.grid(row=length_list + 1, column=0)

    def verify(self):
        file_name = f"{self.username}decrypted.bin"
        if os.stat(file_name).st_size != 0:
            with open(file_name, "rb") as f:
                test_values = p.load(f)
                for user in test_values:
                    if user[2] == str(self.name_of_social_entry.get()):
                        return True

    def save(self):

        list_account = [
            str(self.username_window_entry.get()),
            str(self.password_entry.get()),
            str(self.name_of_social_entry.get()),
            str(self.website_ent.get()),
        ]
        if str(self.username_window_entry.get()) == "":
            messagebox.showwarning("Warning", "Username cannot be empty")
        elif str(self.password_entry.get()) == "":
            messagebox.showwarning("Warning", "Password cannot be empty")
        elif str(self.name_of_social_entry.get()) == "":
            messagebox.showwarning(
                "Warning", "Name of the account cannot be empty")
        else:
            verifying = self.verify()

            if verifying:
                messagebox.showerror("Error", "The account already exists")
            else:
                line = []

                name_file = self.username + "decrypted.bin"
                if os.stat(f"{self.username}decrypted.bin").st_size != 0:
                    with open(f"{self.username}decrypted.bin", "rb") as f:
                        line = p.load(f)
                        line.append(list_account)
                    with open(name_file, "wb") as f1:
                        p.dump(line, f1)
                        f.close()
                else:
                    with open(f"{self.username}decrypted.bin", "wb") as f:
                        line.append(list_account)
                        pickle.dump(line, f)

                index_value = line.index(list_account)
                os.remove(self.username + ".bin.aes")
                pyAesCrypt.encryptFile(
                    name_file,
                    f"{self.username}.bin.aes",
                    self.hashed_password,
                    bufferSize,
                )
                messagebox.showinfo("Success", "Your account has been saved")
                if os.stat(f"{self.username}decrypted.bin").st_size != 0:
                    with open(f"{self.username}decrypted.bin", "rb") as f:
                        val = p.load(f)
                    self.add_button.grid(row=len(val) + 1, column=0)
                self.root1.destroy()
                self.buttons_blit()
                self.show_account(index_value, list_account[2])

    def addaccount(self):
        self.root1 = Toplevel()
        self.root1.geometry("400x300")
        self.root1.title("Add Account")
        self.root1.focus_set()
        self.root1.grab_set()
        self.root1.resizable(False, False)
        width_window = 400
        height_window = 400
        screen_width = self.root1.winfo_screenwidth()
        screen_height = self.root1.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        self.root1.config(bg="#292A2D")
        self.root1.geometry("%dx%d+%d+%d" %
                            (width_window, height_window, x, y))
        name_of_social = Label(
            self.root1,
            text="Account Name:",
            fg="white",
            font=("Yu Gothic Ui", 15),
            bg="#292A2D",
        )
        username_window = Label(
            self.root1,
            text="Username:",
            font=("Yu Gothic Ui", 15),
            fg="white",
            bg="#292A2D",
        )
        password_window = Label(
            self.root1,
            text="Password:",
            font=("Yu Gothic Ui", 15),
            fg="white",
            bg="#292A2D",
        )
        website_label = Label(
            self.root1,
            text="Website",
            font=("Yu Gothic Ui", 15),
            fg="white",
            bg="#292A2D",
        )
        self.username_window_entry = Entry(
            self.root1, font=("Yu Gothic Ui", 10))
        self.password_entry = Entry(self.root1, font=("Yu Gothic Ui", 10))
        self.name_of_social_entry = Entry(
            self.root1, font=("Yu Gothic Ui", 10))
        self.website_ent = Entry(self.root1, font=("Yu Gothic Ui", 10))
        username_window.place(x=10, y=100 + 100)
        password_window.place(x=10, y=130 + 110)
        name_of_social.place(x=10, y=60 + 100)
        website_label.place(x=10, y=280)
        self.username_window_entry.place(
            x=200 + 10, y=100 + 110, height=20, width=150)
        self.password_entry.place(
            x=200 + 10, y=130 + 118, height=20, width=150)
        self.name_of_social_entry.place(
            x=200 + 10, y=70 + 100, height=20, width=150)
        self.website_ent.place(x=200 + 10, y=290, height=20, width=150)

        new_id = tk_image.PhotoImage(image.open(f"{path}photo.png"))
        self.add_icon_button = Label(
            self.root1,
            image=new_id,
            borderwidth="0",
            highlightthickness="0",
            activebackground="#292A2D",
            bg="#292A2D",
        )
        self.add_icon_button.photo = new_id
        self.add_icon_button.place(x=125, y=200)

        self.save_button = Button(
            self.root1,
            text="S A V E",
            bd=0,
            width=15,
            height=1,
            font=("consolas"),
            fg="#292A2D",
            activeforeground="#292A2D",
            bg="#994422",
            activebackground="#994422",
            command=lambda: self.save(),
        )
        self.save_button.place(x=130, y=200 + 130)
        self.add_icon_button.place(x=150, y=50)
        self.root1.mainloop()

    def show_account(self, button, account_name):
        global ind
        ind = button
        website = ""
        change_object = Change_details(
            self.main_window,
            self.username,
            self.password,
            self.hashed_password,
            my_cursor,
        )
        delete_object = Deletion(
            self.handler,
            self.username,
            self.password,
            self.hashed_password,
            self.main_window,
            my_cursor,
            self.main_window,
        )

        self.config(bg="#1E1E1E")
        bg_img = tk_image.PhotoImage(image.open(f"{path}log.jpg"))
        new_frame = Frame(
            self, width=1000 + 50, height=1057, bd="0", highlightthickness=0
        )
        new_frame.place(x=120 + 34, y=0)
        background = Label(new_frame, bd=0, borderwidth=0, image=bg_img)
        background.place(x=0, y=0)
        background.image = bg_img
        new_s = Frame(new_frame, bg="#1E1E1E", width=500, height=460, bd=0)
        new_s.place(x=150, y=120)

        def copy(value):
            pyperclip.copy(value)
            messagebox.showinfo("Copied", "Copied!!!")

        dot_text = Label(new_s, text=":", bg="#1E1E1E", fg="white", font=(20))
        dot_text1 = Label(new_s, text=":", bg="#1E1E1E", fg="white", font=(20))
        dot_text2 = Label(new_s, text=":", bg="#1E1E1E", fg="white", font=(20))
        dot_text3 = Label(new_s, text=":", bg="#1E1E1E", fg="white", font=(20))

        with open(f"{self.username}decrypted.bin", "rb") as f:
            lists = pickle.load(f)
        delete_account = Button(
            new_s,
            text="Delete Account",
            bd=0,
            font=("Yu Gothic Ui", 12),
            fg="#292A2D",
            activeforeground="#292A2D",
            bg="#994422",
            activebackground="#994422",
            command=lambda: delete_object.delete_social_media_account(
                self.button, False, lists[button][2]
            ),
        )

        ChangeAccount = Button(
            new_s,
            text="Change Details",
            bd=0,
            font=("Yu Gothic Ui", 12),
            fg="#292A2D",
            activeforeground="#292A2D",
            bg="#994422",
            activebackground="#994422",
            command=lambda: change_object.change_window_creation(
                lists[button][0], self.button
            ),
        )
        # getting the username and password
        username = ""
        password = ""
        if os.stat(f"{self.username}decrypted.bin").st_size != 0:
            with open(f"{self.username}decrypted.bin", "rb") as f:
                values = p.load(f)
                for i in values:
                    if i[2] == account_name:
                        username, password, website = i[0], i[1], i[3]
        image_path = f"{path}followers.png"

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
        website_text = Label(
            new_s,
            text="Website",
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
            new_s,
            html=f""" 
            <body>
                <a style='color:white;text-align:center;font-family:sans-serif;'  href={website}>{website}</a>
            </body>
            """,
            background="#1E1E1E",
            fg="white",
            foreground="white",
            highlightbackground="#1E1E1E",
            highlightcolor="white",
            selectforeground="white",
            inactiveselectbackground="#1E1E1E",
            width=2000,
            height=2,
        )

        try:
            tip = tix.Balloon(new_s)
            tip.config(background="white")
            tip.label.config(bg="white", fg="white")
            try:
                for sub in tip.subwidgets_all():
                    sub.configure(bg="white")
            except:
                pass
            tip.subwidget("label").forget()
            tip.message.config(bg="white", fg="#06090F",
                               font=("Segoe UI SemiBold", 10))
            # display the ballon text
            tip.bind_widget(website_label1, balloonmsg=f"Open {website}")

        except:
            pass
        copy_but_password = Button(
            new_s,
            text="Copy Password",
            bd=0,
            font=("Yu Gothic Ui", 12),
            fg="#292A2D",
            activeforeground="#292A2D",
            bg="#994422",
            width=13,
            activebackground="#994422",
            command=lambda: copy(password),
        )
        copy_but_username = Button(
            new_s,
            text="Copy Username",
            bd=0,
            font=("Yu Gothic Ui", 12),
            fg="#292A2D",
            width=13,
            activeforeground="#292A2D",
            bg="#994422",
            activebackground="#994422",
            command=lambda: copy(username),
        )

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

        delete_account.place(x=0 + 25, y=340 + 50)
        username_label.place(x=30, y=200 + 25)
        website_text.place(x=30, y=325)
        password_label.place(x=30, y=250 + 25)
        social_account.place(x=30, y=175)
        username_text.place(x=250, y=200 + 25)
        password_text.place(x=250, y=250 + 25)
        social_account_text.place(x=250, y=175)
        ChangeAccount.place(x=340, y=340 + 50)
        copy_but_username.place(x=360, y=30)
        copy_but_password.place(x=360, y=80)
        website_label1.place(x=250, y=300 + 20 + 5)


# for seeing the profile


class Profile_view(Frame):
    def __init__(
        self,
        master,
        password_button,
        profile_button,
        handler,
        window,
        *args,
    ):
        self.master = master
        Frame.__init__(self, self.master)
        self.config(bg="white")
        self.username = args[0]
        self.window = window
        self.password = args[1]
        self.email_id = args[2]
        self.email_password = args[3]
        self.hashed_password = args[4]
        self.object = args[5]
        self.profile_button = profile_button
        self.password_button = password_button
        self.handler = handler
        self.master.unbind("<Return>")

        self.master.iconbitmap(f"{path}profile.ico")
        self.profile_button["state"] = DISABLED
        self.password_button["state"] = NORMAL

        self.master.title("Profile")

        emptyMenu = Menu(self.master)

        self.master.config(menu=emptyMenu)

        self.master.iconbitmap(f"{path}profile.ico")
        # profile window image
        member = tk_image.PhotoImage(image.open(f"{path}member.png"))

        profileimg = tk_image.PhotoImage(
            image.open(f"{path}profile_image.png"))
        new_canvas = Canvas(self, width=1270, height=700, highlightthickness=0)
        new_canvas.place(x=0, y=0)
        new_canvas.background = profileimg
        new_canvas.create_image(0, 0, image=profileimg, anchor="nw")
        new_s = Frame(
            new_canvas,
            bg="#292A2D",
            highlightcolor="black",
            highlightbackground="black",
            width=500,
            height=430,
        )

        new_canvas.create_window(450, 300 + 50, window=new_s, anchor="center")

        # all labels
        username_label = Label(
            new_s,
            text="Username",
            font="consolas 15",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )
        password_label = Label(
            new_s,
            text="Password",
            font="consolas 15",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )
        email_id_label = Label(
            new_s,
            text="Email",
            font="consolas 15",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )
        email_password_label = Label(
            new_s,
            text="Email Password",
            font="consolas 15",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )

        # details label
        username_label_right = Label(
            new_s,
            text=self.username,
            font="consolas 15",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )

        password_label_right = Label(
            new_s,
            text=self.password,
            font="consolas 15",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
        )

        email_id_label_right = Label(
            new_s,
            text=self.email_id,
            font="consolas 15",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )
        email_password_label_right = Label(
            new_s,
            text=self.email_password,
            font="consolas 15",
            fg="white",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
        )

        # dot label
        dot = Label(new_s, font=(200), bg="#292A2D", text=":", fg="white")
        dot1 = Label(new_s, font=(200), bg="#292A2D", text=":", fg="white")
        dot2 = Label(new_s, font=(200), bg="#292A2D", text=":", fg="white")
        dot3 = Label(new_s, font=(200), bg="#292A2D", text=":", fg="white")

        # profile image

        profile_photo = Label(
            new_s,
            bg="#292A2D",
            image=member,
            activebackground="black",
            activeforeground="white",
        )
        profile_photo.photo = member
        delete_object = Deletion(
            self.handler,
            self.username,
            self.password,
            self.hashed_password,
            self.window,
            my_cursor,
            self.master,
        )
        delete_this_account = Button(
            new_s,
            text="Delete Account",
            fg="white",
            bg="black",
            activebackground="black",
            activeforeground="white",
            font="Helvetiva 10",
            command=lambda: delete_object.delete_main_account(self.master),
        )

        username_label.place(x=5, y=100 + 100)
        password_label.place(x=5, y=150 + 100)
        email_id_label.place(x=5, y=200 + 100)
        email_password_label.place(x=5, y=250 + 100)
        profile_photo.place(x=150, y=50)
        delete_this_account.place(x=0 + 2, y=400)

        username_label_right.place(x=300 - 70, y=100 + 100)
        password_label_right.place(x=300 - 70, y=150 + 100)
        email_id_label_right.place(x=300 - 70, y=200 + 100)
        email_password_label_right.place(x=300 - 70, y=250 + 100)

        # putting the dot on the frame
        dot.place(x=200, y=100 + 100 + 6)
        dot1.place(x=200, y=150 + 100 + 6)
        dot2.place(x=200, y=200 + 100 + 6)
        dot3.place(x=200, y=250 + 100 + 6)


# to change the details of the user
class Change_details:
    def __init__(self, handler, real_username, password, hashed_password, object):
        self.real_username = real_username
        self.hashed_password = hashed_password
        self.object = object
        self.hand = handler
        self.password = password

    def change_window_creation(self, selectaccount, pass_button):
        self.but = pass_button
        change_acccount = Toplevel()
        change_acccount.config(bg="#292A2D")
        change_acccount.resizable(False, False)
        change_acccount.focus_force()
        change_acccount.title("Change Account")

        # assigning the main value
        self.account_change = selectaccount
        width_window = 450
        height_window = 400
        screen_width = change_acccount.winfo_screenwidth()
        screen_height = change_acccount.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        change_acccount.geometry("%dx%d+%d+%d" %
                                 (width_window, height_window, x, y))

        iamge_load = tk_image.PhotoImage(image.open(f"{path}member.png"))
        iamge = Label(change_acccount, image=iamge_load, bg="#292A2D")
        iamge.photo = iamge_load
        new_username_label = Label(
            change_acccount,
            text="New Username:",
            fg="white",
            bg="#292A2D",
            font=("Yu Gothic Ui", 15),
        )
        new_password_label = Label(
            change_acccount,
            text="New Password:",
            fg="white",
            bg="#292A2D",
            font=("Yu Gothic Ui", 15),
        )
        new_account_name_label = Label(
            change_acccount,
            text="New Account Name:",
            fg="white",
            bg="#292A2D",
            font=("Yu Gothic Ui", 15),
        )

        new_username = Entry(
            change_acccount,
            width=13,
            bg="#292A2D",
            foreground="white",
            border=0,
            bd=0,
            font=("consolas", 15, "normal"),
            insertbackground="white",
        )
        new_password = Entry(
            change_acccount,
            width=13,
            bg="#292A2D",
            foreground="white",
            border=0,
            bd=0,
            font=("consolas", 15, "normal"),
            insertbackground="white",
        )
        new_account_name = Entry(
            change_acccount,
            width=13,
            bg="#292A2D",
            border=0,
            bd=0,
            font=("consolas", 15, "normal"),
            foreground="white",
            insertbackground="white",
        )

        change = Button(
            change_acccount,
            width=20,
            height=2,
            text="C H A N G E",
            font=("consolas"),
            fg="white",
            bg="#994422",
            bd=0,
            command=lambda: self.change_sub_account(
                str(new_username.get()),
                str(new_password.get()),
                str(new_account_name.get()),
            ),
        )
        change.grid(row=5, column=1)
        change.place(x=120, y=200 + 120)

        new_account_name_label.place(x=0, y=70 + 100 + 3)
        new_username_label.place(x=0, y=100 + 100 + 15 + 3)
        new_password_label.place(x=0, y=130 + 100 + 30 + 3)

        new_account_name.place(x=250, y=70 + 100 + 5)
        new_username.place(x=250, y=100 + 100 + 15 + 5)
        new_password.place(x=250, y=130 + 100 + 30 + 5)

        Frame(change_acccount, width=150, height=2, bg="white").place(
            x=250, y=70 + 100 + 10 + 16 + 5
        )
        Frame(change_acccount, width=150, height=2, bg="white").place(
            x=250, y=130 + 100 + 10 + 16 + 30 + 5
        )
        Frame(change_acccount, width=150, height=2, bg="white").place(
            x=250, y=100 + 100 + 10 + 16 + 15 + 5
        )

        iamge.place(x=145, y=10)

    def change_sub_account(self, new_username, new_password, account_name):
        with open(f"{self.real_username}decrypted.bin", "rb") as f:
            value1 = pickle.load(f)
            f.close()
        for i in value1:

            if i[0] == str(self.account_change):
                i[0] = str(new_username)
                i[1] = str(new_password)
                i[2] = str(account_name)
                messagebox.showinfo(
                    "Success", "The Account details has been changed")
                os.remove(f"{self.real_username}decrypted.bin")
                with open(f"{self.real_username}decrypted.bin", "wb") as f:
                    pickle.dump(value1, f)
                    f.close()
                os.remove(f"{self.real_username}.bin.aes")
                pyAesCrypt.encryptFile(
                    f"{self.real_username}decrypted.bin",
                    f"{self.real_username}.bin.aes",
                    self.hashed_password,
                    bufferSize,
                )
                destroy_all(self.hand)
                self.hand.switch_frame(
                    main_window, self.real_username, self.password)

    def save_email(self):

        email_split = ""
        word = self.new_email_entry.get().split()
        for i in word:
            for a in i:
                if i == "@":
                    break
                else:
                    email_split += i
        val = email_split[::-1]
        main_password = val + "/" + self.new_email_password_entry.get()

        re_hash_text1 = self.password + self.real_username
        new_salt1 = self.password + "@" + main_password
        re_hash_new1 = hashlib.sha3_512(re_hash_text1.encode()).hexdigest()
        re_encrypt, new_salt = create_key(main_password, new_salt1)

        # encrypting the new recovery password

        password = self.new_email_entry.get() + re_hash_new1
        passwordSalt = secrets.token_bytes(512)  # returns a random 64 byte
        new_key = pbkdf2.PBKDF2(password, passwordSalt).read(
            32
        )  # it creates a key based on the password provided by the user
        aes = pyaes.AESModeOfOperationCTR(new_key)
        # aes is mode of encryption for encrypting the password
        encrypted_pass = aes.encrypt(self.new_email_password_entry.get())

        os.remove(f"{self.real_username}.bin.aes")
        query = "update usersdata set password = (%s), email_id = (%s), salt_recovery = (%s), salt = (%s), recovery_password = (%s) where username = (%s)"
        self.object.execute(
            query,
            (
                re_encrypt,
                simple_encrypt(self.new_email_entry.get()),
                passwordSalt,
                new_salt,
                encrypted_pass,
                simple_encrypt(self.real_username),
            ),
        )
        pyAesCrypt.encryptFile(
            self.real_username + "decrypted.bin",
            self.real_username + ".bin.aes",
            re_hash_new1,
            bufferSize,
        )
        ad = Toplevel()
        ad.withdraw()
        messagebox.showinfo(
            "Success",
            "Your email and password has been changed",
        )
        ad.destroy()
        self.new_window.destroy()
        destroy_all(self.hand)
        self.hand.switch_frame(main_window, self.real_username, self.password)

    def change_email(self):

        self.new_window = Toplevel()
        self.new_window.focus_force()
        new_img = tk_image.PhotoImage(image.open(f"{path}member.png"))
        new_img_label = Label(self.new_window, image=new_img, bg="#1E1E1E")
        new_img_label.photo = new_img

        file_name_reentry = self.real_username + ".bin.aes"

        width_window = 400
        height_window = 300
        screen_width = self.new_window.winfo_screenwidth()
        screen_height = self.new_window.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        self.new_window.geometry("%dx%d+%d+%d" %
                                 (width_window, height_window, x, y))
        self.new_window.title("Change Recovery details")
        self.new_window.config(bg="#1E1E1E")

        self.new_email = Label(
            self.new_window,
            text="New Email",
            font=("Segoe UI SemiBold", 15),
            fg="white",
            bg="#1E1E1E",
        )
        self.new_email_password = Label(
            self.new_window,
            text="New Password",
            fg="white",
            font=("Segoe UI SemiBold", 15),
            bg="#1E1E1E",
        )

        self.new_email_entry = Entry(
            self.new_window,
            foreground="white",
            insertbackground="white",
            background="#1E1E1E",
            font=15,
            bd=0,
            width=17,
            border=0,
        )
        self.new_email_password_entry = Entry(
            self.new_window,
            insertbackground="white",
            foreground="white",
            background="#1E1E1E",
            font=15,
            bd=0,
            width=17,
            show="*",
        )

        new_img_label.grid(row=0, column=1)
        self.new_email.grid(row=1, column=0)
        self.new_email_password.grid(row=2, column=0)
        self.new_email_entry.grid(row=1, column=1)
        self.new_email_password_entry.grid(row=2, column=1)
        new_img_label.place(x=130, y=0)
        self.new_email.place(x=10, y=70 + 50)
        self.new_email_password.place(x=10, y=100 + 50 + 20)
        self.new_email_entry.place(x=165, y=70 + 52)
        self.new_email_password_entry.place(x=165, y=100 + 53 + 20)
        Frame(self.new_window, width=150, height=2, bg="#CACBC7").place(
            x=165, y=70 + 77
        )
        Frame(self.new_window, width=150, height=2, bg="#CACBC7").place(
            x=165, y=100 + 77 + 20
        )

        self.object.execute(
            "select email_id from usersdata where username=(%s)",
            (simple_encrypt(self.real_username),),
        )
        for i in self.object.fetchall():
            self.email_id = simple_decrypt(i[0])
        save = Button(
            self.new_window,
            text="Save",
            command=lambda: self.save_email(),
        )
        save.place(x=170, y=220)
        private_img = tk_image.PhotoImage(image.open(f"{path}private.png"))
        unhide_img = tk_image.PhotoImage(image.open(f"{path}eye.png"))

        show_both_12 = Button(
            self.new_window,
            image=unhide_img,
            command=lambda: password_sec(
                self.new_email_password_entry, show_both_12),
            fg="white",
            bd="0",
            bg="#1E1E1E",
            highlightcolor="#1E1E1E",
            activebackground="#1E1E1E",
            activeforeground="white",
            relief=RAISED,
        )
        show_both_12.image = unhide_img
        show_both_12.place(x=320, y=100 + 53 + 20)


class PinFrame(Frame):
    def __init__(self, master, username, password):
        self.master = master
        Frame.__init__(self, self.master)
        self.username = username
        self.master.title("PIN")
        self.password = password
        self.config(bg="#121212")
        global running, al
        self.running = running
        self.al = al

        def alpha():
            if str(enter_alpha["text"]) == "Enter Alphanumeric pin":
                self.running = False
                self.al = True
                enter_alpha.config(text="Enter Number pin")
                threading.Thread(target=for_alpha).start()
            elif enter_alpha["text"] == "Enter Number pin":
                self.running = True
                self.al = False
                enter_alpha.config(text="Enter Alphanumeric pin")
                threading.Thread(target=getting).start()

        def for_alpha():
            while self.al:

                try:
                    if self.ent.get():
                        if len(self.ent.get()) >= 4:
                            a = self.ent.get()[:4]
                            self.ent.delete(4, END)
                except:
                    pass

        def getting():

            while self.running:
                try:
                    if self.ent.get():
                        int(self.ent.get())
                        if len(self.ent.get()) >= 4:
                            a = self.ent.get()[:4]

                            self.ent.delete(4, END)
                except ValueError:
                    a = str(self.ent.get())
                    d = list(map(str, a))
                    f = 0
                    for i in d:
                        if i.isalpha():
                            f = d.index(i)
                    self.ent.delete(f, END)

        width_window = 1057
        lab = Label(
            self,
            text="Add a security pin",
            bg="#121212",
            fg="white",
            font=("Segoe Ui", 15),
        )
        lab.place(x=width_window / 2 - 60 - 5 - 10 - 10, y=100)
        lab1 = Label(
            self,
            text="This 4 digit  pin is used for further security\nYou cannot recover it.\nIf you lost the pin you may have to reset your account password.",
            bg="#121212",
            fg="white",
            justify="center",
            font=("Segoe Ui", 15),
        )
        pintext = Label(
            self,
            text="PIN:",
            bg="#121212",
            fg="white",
            justify="center",
            font=("Segoe Ui", 15),
        )
        pintext.place(x=width_window / 2 - 130 - 5 - 30 - 10 - 10, y=248)
        lab1.place(x=width_window / 2 - 190 - 5 - 60 - 10, y=150)

        self.ent = Entry(self, width=20, font=("Segoe Ui", 15))
        self.ent.place(x=width_window / 2 - 40 - 5 - 5 - 30 - 10 - 10, y=250)
        enter_alpha = Button(
            self,
            text="Enter Alphanumeric pin",
            fg="#2A7BCF",
            activeforeground="#2A7BCF",
            bg="#121212",
            command=alpha,
            activebackground="#121212",
            bd=0,
            borderwidth=0,
            font=("Consolas", 14, UNDERLINE),
        )
        enter_alpha.place(x=width_window / 2 + 200 - 30 - 10 - 10, y=250)
        # adding the check box button
        self.var = IntVar()
        check = Checkbutton(
            self,
            text="I understand that this security code cannot be recovered once it is lost",
            font=("Segoe Ui", 14),
            bg="#121212",
            fg="white",
            justify="center",
            variable=self.var,
            activebackground="#121212",
            activeforeground="white",
            selectcolor="black",
        )
        check.place(x=240 - 10, y=300)

        t1 = threading.Thread(target=getting)

        t1.start()

        # adding the entry widget

        def pin_save():
            if self.ent.get():
                if self.var.get() == 1:
                    self.running, self.al = False, False
                    self.pin = str(self.ent.get())
                    values = {}
                    self.hash_value = hashlib.sha512(
                        self.pin.encode()).hexdigest()
                    values[hashlib.sha512(self.username.encode()).hexdigest()] = str(
                        self.hash_value
                    )

                    if (
                        os.path.exists(f"{json_path}pin.json")
                        and os.stat(f"{json_path}pin.json").st_size != 0
                    ):
                        with open(f"{json_path}pin.json", "r") as f:
                            data = json.load(f)
                        data[hashlib.sha512(self.username.encode()).hexdigest()] = str(
                            self.hash_value
                        )
                        with open(f"{json_path}pin.json", "w") as f:
                            json.dump(data, f)
                    else:
                        with open(f"{json_path}pin.json", "w") as f:
                            json.dump(values, f)
                    main_pass = self.username + str(self.pin)
                    static_salt_password = self.password
                    cipher_text, salt_for_decryption = create_key(
                        main_pass, static_salt_password
                    )
                    my_cursor.execute(
                        "insert into userspin values(%s,%s,%s)",
                        (self.username, cipher_text, salt_for_decryption),
                    )
                    if (
                        os.path.exists(f"{json_path}settings.json")
                        and os.stat(f"{json_path}settings.json").st_size != 0
                    ):
                        with open(f"{json_path}settings.json", "r") as f:
                            value = json.load(f)
                        values = list(value.keys())
                        if not self.username in values:
                            value[self.username] = 0
                        with open(f"{json_path}settings.json", "w") as f:
                            json.dump(value, f)
                    else:
                        value = {}
                        value[self.username] = 0
                        with open(f"{json_path}settings.json", "w") as f:
                            json.dump(value, f)
                    a = Tk()
                    a.withdraw()
                    messagebox.showinfo(
                        "Saved", "PIN has been successfully registered")
                    a.destroy()
                    self.master.switch_frame(
                        main_window, self.username, self.password)
                else:
                    messagebox.showinfo("Error", "Checkbox is not ticked")
            else:
                messagebox.showinfo("Error", "Please provide a pin")

        # adding the save button
        save = Button(
            self,
            text="S A V E",
            fg="#292A2D",
            activeforeground="#292A2D",
            bg="#994422",
            command=pin_save,
            activebackground="#994422",
            height=1,
            width=10,
            bd=0,
            borderwidth=0,
            font=("Consolas", 14),
        )
        save.place(x=width_window / 2 - 30 - 5 - 10 - 10, y=350)


class Deletion:
    def __init__(
        self, handler, real_username, password, hashed_password, window, object, master
    ):
        self.real_username = real_username
        self.hashed_password = hashed_password
        self.window = window
        self.object = object
        self.window.unbind("<Return>")
        self.handler = handler
        self.password = password
        self.master = master

    def delete_social_media_account(self, password_button, Value, *account_name):

        if Value:
            self.delete_med_account = Tk()
            width_window = 440
            height_window = 60
            self.delete_med_account.focus_force()
            self.delete_med_account.config(bg="#292A2D")
            screen_width = self.delete_med_account.winfo_screenwidth()
            screen_height = self.delete_med_account.winfo_screenheight()
            x = screen_width / 2 - width_window / 2
            y = screen_height / 2 - height_window / 2
            self.delete_med_account.geometry(
                "%dx%d+%d+%d" % (width_window, height_window, x, y)
            )
            self.delete_med_account.config(bg="#292A2D")
            self.delete_med_account.title("Delete Account")
            selectaccount = Combobox(
                self.delete_med_account, width=27, state="#292A2D")
            # Adding combobox drop down list
            values = ()
            with open(f"{self.real_username}decrypted.bin", "rb") as selectfile:
                try:
                    ac = pickle.load(selectfile)
                    for i in ac:
                        values += (i[2],)
                except EOFError:
                    pass
            delete = Button(
                self.delete_med_account,
                text="Delete",
                fg="white",
                bg="#292A2D",
                command=lambda: self.change_account_name(
                    str(selectaccount.get()), password_button, True
                ),
            )
            selectaccount["values"] = values
            change_account_label = Label(
                self.delete_med_account,
                fg="white",
                bg="#292A2D",
                font=("Yu Gothic Ui", 15),
                text="Select account to be deleted:",
            )
            selectaccount.grid(column=1, row=0)
            change_account_label.grid(column=0, row=0)
            selectaccount.current()
            delete.grid(row=1, column=1)

        else:
            a = Tk()
            a.overrideredirect(1)
            a.withdraw()
            a.focus_force()
            result = messagebox.askyesno(
                "Delete Account", "Are you sure you want to delete your account?"
            )
            a.destroy()
            if result:
                self.change_account_name(
                    account_name[0], password_button, False)

    def change_account_name(self, account_name, button, val):
        if val:
            result = messagebox.askyesno(
                "Confirm", "Are you sure that you want to delete your account"
            )
        else:
            result = True
        if result == True:
            with open(f"{self.real_username}decrypted.bin", "rb") as f:
                values = pickle.load(f)
                for i in values:
                    if i[2] == account_name:
                        inde = values.index(i)
                        values.pop(inde)

                f.close()
            try:
                os.remove(f"{self.real_username}.bin.aes")
            except:
                pass
            with open(f"{self.real_username}decrypted.bin", "wb") as f:
                pickle.dump(values, f)
                f.close()

            pyAesCrypt.encryptFile(
                f"{self.real_username}decrypted.bin",
                f"{self.real_username}.bin.aes",
                self.hashed_password,
                bufferSize,
            )
            a = Tk()
            a.withdraw()
            messagebox.showinfo("Success", f"The account  has been  deleted")
            a.destroy()
            destroy_all(self.master)
            self.master.switch_frame(
                main_window, self.real_username, self.password)
            try:
                self.delete_med_account.destroy()

            except:
                pass
        else:
            a = Tk()
            a.withdraw()
            messagebox.showinfo("Error", "Please try again")
            a.destroy()

    def delete_main_account(self, window, *another_window):
        answer = messagebox.askyesno(
            "Delete Account", "Are you sure you want to delete you account"
        )
        if answer:
            result = simpledialog.askstring(
                "Delete Account",
                f"Please type {self.real_username}-CONFIRM to delete your account",
            )
            if result == f"{self.real_username}-CONFIRM":
                try:
                    os.remove(self.real_username + "decrypted.bin")
                    os.remove(self.real_username + ".bin.aes")

                    self.object.execute(
                        "delete from usersdata where username = (%s)",
                        (simple_encrypt(self.real_username),),
                    )
                    messagebox.showinfo(
                        "Account deletion",
                        "Success your account has been deleted. See you!!",
                    )
                    window.destroy()
                    for i in another_window:
                        i.destroy()
                    if not os.path.exists(f"{self.real_username}.bin.aes"):
                        quit()
                except:
                    pass
            else:
                messagebox.showwarning("Error", "Please try again")
        else:
            pass


if __name__ == "__main__":
    # initialising the main class
    app = main_class()

    def shutdown_ttk_repeat():
        app.eval("::ttk::CancelRepeat")
        app.destroy()

    app.protocol("WM_DELETE_WINDOW", shutdown_ttk_repeat)
    app.mainloop()
    remove_decrypted()
