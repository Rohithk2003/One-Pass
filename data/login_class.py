from data.register_class import register
from data.forgot_pass import *

bufferSize = 64 * 1024
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


class Login:
    def __init__(self, username, password):
        self.username = str(username)
        self.password = str(password)

    def login_checking(self):  # verifying the user
        for_hashing_both = self.password + self.username
        main_password = hashlib.sha3_512(
            for_hashing_both.encode()
        ).hexdigest()
        if self.username == "Username":
            # checking for blank username
            root_error = Tk()
            root_error.withdraw()
            messagebox.showerror("Error", "Cannot have blank Username ")
            root_error.destroy()
            return False, main_password
        elif self.password == "Password":
            # checking for blank password
            root_error = Tk()
            root_error.withdraw()
            messagebox.showerror("Error", "Password cannot be empty ")
            root_error.destroy()
            return False, main_password, self.password
        else:
            for_hashing_both = self.password + self.username
            if os.path.exists(f"{self.username}.bin.fenc"):
                try:
                    # trying to decrypt the users file to check whether the password entered is valid
                    pyAesCrypt.decryptFile(
                        self.username + ".bin.fenc",
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
                    return False, main_password, self.password
            else:
                root_error = Tk()
                root_error.withdraw()
                messagebox.showerror(
                    "Error",
                    f"{self.username} doesn't exist, Please register or provide the correct username",
                )
                root_error.destroy()
                return False, main_password, self.password
            return True, main_password, self.password


def login(window_after, object, *window):
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
        command=lambda: login_password(
            "Forgot Password", object),
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
        command=lambda: register(window_after, object, window, login_window),
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
                        window_after(username,
                                     main_password, password, object)
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
