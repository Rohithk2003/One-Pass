
from data.for_encryption import *
from data.login_class import *
from data.focus_pass import *
bufferSize= 64*1024

class Register:
    def __init__(self, username, password, email_id, email_password, window_after):
        self.username = str(username)
        self.password = str(password)
        self.email_id = str(email_id)
        self.email_password = str(email_password)
        self.window = window_after
    def check_password_integrity(self, passw):
        self.p = passw
        if self.username == self.password:
            return False
        with open("pass.txt", 'r') as file:
            data = file.read().split()
            for i in data:
                if i == self.p:
                    return False

        return True

    def email_exists(self):
        print(self.email_id)
        print(type(self.email_id))
        return self.email_id.endswith(("gmail.com","yahho.com"))

    def check_pass_length(self):  # checking if the entered password is lesser than 5
        return len(self.password) >= 5

    """to create a file named user and to store his accounts and also add his details to the database"""

    def saving(self, object):

        object.execute("select username from data_input")
        values_username = object.fetchall()
        for i in values_username:
            for usernames in i:
                if simple_decrypt(usernames) == self.username and os.path.exists(
                        self.username + ".bin.fenc"
                ):
                    return (
                        True,
                    )  # checking whether the username already exists in the database

        email_split = ""
        word = self.email_id.split()
        for i in word:
            for a in i:
                if i == "@":
                    break
                else:
                    email_split += i
        val = email_split[::-1]
        main_password = val + "/" + self.email_password  # static salt
        static_salt_password = self.password + "@" + main_password
        # hashing/encrypting the password and store the dynamic salt created during creat_key() fn is called along with the encrypted password in database
        cipher_text, salt_for_decryption = create_key(
            main_password, static_salt_password
        )

        for_hashing = self.password + self.username
        """for encrypting the file"""
        hash_pass = hashlib.sha3_512(for_hashing.encode()).hexdigest()
        # for encrypting the recovery password

        password_recovery_email = self.email_id + hash_pass
        passwordSalt = secrets.token_bytes(512)
        key = pbkdf2.PBKDF2(password_recovery_email, passwordSalt).read(32)
        aes = pyaes.AESModeOfOperationCTR(key)
        encrypted_pass = aes.encrypt(self.email_password)
        try:
            object.execute(
                "insert into data_input values (?,?,?,?,?,?)",
                (
                    simple_encrypt(self.username),
                    simple_encrypt(self.email_id),
                    cipher_text,
                    salt_for_decryption,
                    encrypted_pass,
                    passwordSalt,
                ),
            )
        except:
            return True
        # so inserting the users details into database

        return False

    # adding the account
    def creation(self, window):
        try:
            window.destroy()
        except:
            pass
        for_hashing = self.password + self.username
        """for encrypting the file"""
        hash_pass = hashlib.sha3_512(for_hashing.encode()).hexdigest()

        file_name = self.username + ".bin"
        with open(file_name, "wb"):
            pyAesCrypt.encryptFile(
                file_name, file_name + ".fenc", hash_pass, bufferSize
            )
        os.remove(file_name)
        # to display that his account has been created
        windows = Tk()
        windows.withdraw()
        messagebox.showinfo("Success", "Your account has been created")
        windows.destroy()
        # for opening the main section where he can store his passwords and use notepad so the file has to be decrypted
        pyAesCrypt.decryptFile(
            file_name +
            ".fenc", f"{self.username}decrypted.bin", hash_pass, bufferSize
        )
        self.window(self.username, hash_pass, self.password)


def register(window,window_after,object, *a):
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
                        registering = register_user.saving(object)
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
        command=lambda: password_sec(
            email_password_entry, show_both_12),
        fg="#292A2D",
        bg="#292A2D",
        bd=0,
        highlightcolor="#292A2D",
        activebackground="#292A2D",
        activeforeground="#292A2D",
        relief=RAISED,
    )
    show_both_12.image = unhide_img

    show_both_1.place(x=420-20, y=220 + 18 + 34)
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
    generate = Button(labelframe1,
                      text="Generate",
                      fg="#292A2D",
                      bg="#994422",
                      font=("consolas"),
                      activebackground="#994422",
                      bd=0,
                      relief=SUNKEN,
                      command=lambda: pass_generator(password_entry))
    generate.place(x=440, y=220 + 18 + 39)
    generate1 = Button(labelframe1,
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
