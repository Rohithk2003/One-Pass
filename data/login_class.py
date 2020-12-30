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
