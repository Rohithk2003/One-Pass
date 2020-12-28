import secrets
from data.for_encryption import  *
from data.focus_pass import *
from data.apploop import *


path = ''

if platform.system() == "Windows":
    path = "images\\"
if platform.system() == 'Darwin':
    dir_path = os.getcwd()
    path = dir_path + "/images/"
buttons_list = {}
btn_nr = -1
image_path = ""
exist = False

bufferSize = 64 * 1024

class Change_details:
    def __init__(self, real_username, hashed_password, window, object):
        self.real_username = real_username
        self.hashed_password = hashed_password
        self.window = window
        self.object = object
    def change_window_creation(self, selectaccount, pass_button):
        self.but = pass_button
        change_acccount = Toplevel()
        change_acccount.config(bg="#292A2D")
        change_acccount.resizable(False, False)

        change_acccount.title("Change Account")

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
            font=("Sitka Text", 15),
        )
        new_password_label = Label(
            change_acccount,
            text="New Password:",
            fg="white",
            bg="#292A2D",
            font=("Sitka Text", 15),
        )
        new_account_name_label = Label(
            change_acccount,
            text="New Account Name:",
            fg="white",
            bg="#292A2D",
            font=("Sitka Text", 15),
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
                selectaccount,
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

    def change_sub_account(
            self, accounttobechanged, new_username, new_password, account_name
    ):
        with open(f"{self.real_username}decrypted.bin", "rb") as f:
            value1 = pickle.load(f)
            f.close()
        for i in value1:

            if i[0] == str(accounttobechanged):
                i[0] = str(new_username)
                i[1] = str(new_password)
                i[2] = str(account_name)
                p = Tk()
                p.config(bg="#292A2D")
                p.withdraw()
                messagebox.showinfo(
                    "Success", "The Account details has been changed")
                p.destroy()
                os.remove(f"{self.real_username}decrypted.bin")
                with open(f"{self.real_username}decrypted.bin", "wb") as f:
                    pickle.dump(value1, f)
                    f.close()
                os.remove(f"{self.real_username}.bin.fenc")
                pyAesCrypt.encryptFile(
                    f"{self.real_username}decrypted.bin",
                    f"{self.real_username}.bin.fenc",
                    self.hashed_password,
                    bufferSize,
                )

                gameloop(
                    self.real_username, self.hashed_password, self.window, self.but
                )

    def save_email(
            self,
            new_email,
            old_email,
            recovery_password,
            another_recovery_password,
            user_password,
            object
    ):

        email_split = ""
        word = new_email.split()
        for i in word:
            for a in i:
                if i == "@":
                    break
                else:
                    email_split += i
        val = email_split[::-1]
        main_password = val + "/" + another_recovery_password

        re_hash_text1 = user_password + self.real_username
        new_salt1 = user_password + "@" + main_password
        re_hash_new1 = hashlib.sha3_512(re_hash_text1.encode()).hexdigest()
        re_encrypt, new_salt = create_key(main_password, new_salt1)

        # encrypting the new recovery password

        password = new_email + re_hash_new1
        message = another_recovery_password
        passwordSalt = secrets.token_bytes(512)  # returns a random 64 byte
        key = pbkdf2.PBKDF2(password, passwordSalt).read(
            32
        )  # it creates a key based on the password provided by the user
        aes = pyaes.AESModeOfOperationCTR(key)
        # aes is mode of encryption for encrypting the password
        encrypted_pass = aes.encrypt(message)

        os.remove(f"{self.real_username}.bin.fenc")
        self.object.execute(
            "update data_input set password = (?),  email_id = (?),  salt_recovery=(?), salt = (?), recovery_password = (?) where  username = (?)",
            (
                re_encrypt,
                simple_encrypt(new_email),
                passwordSalt,
                new_salt,
                encrypted_pass,
                simple_encrypt(self.real_username),
            ),
        )
        pyAesCrypt.encryptFile(
            self.real_username + "decrypted.bin",
            self.real_username + ".bin.fenc",
            re_hash_new1,
            bufferSize,
        )
        ad = Toplevel()
        ad.withdraw()
        messagebox.showinfo(
            "Success",
            "Your email and password has been changed.Please restart the program ",
        )
        ad.destroy()

    def change_email(self, rec_pass, ogi_pass):
        self.password = ogi_pass
        self.recovery = rec_pass
        new_window = Toplevel()

        new_img = tk_image.PhotoImage(image.open(f"{path}user.png"))
        new_img_label = Label(new_window, image=new_img, bg="#292A2D")
        new_img_label.photo = new_img

        file_name_reentry = self.real_username + ".bin.fenc"

        width_window = 400
        height_window = 200
        screen_width = new_window.winfo_screenwidth()
        screen_height = new_window.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        new_window.geometry("%dx%d+%d+%d" %
                            (width_window, height_window, x, y))
        new_window.title("Change Recovery details")
        new_window.geometry("300x300")
        new_window.config(bg="#292A2D")

        new_email = Label(new_window, text="New Email",
                          fg="white", bg="#292A2D")
        new_email_password = Label(
            new_window, text="New Password", fg="white", bg="#292A2D"
        )

        new_email_entry = Entry(new_window)
        new_email_password_entry = Entry(new_window, show="*")

        new_img_label.grid(row=0, column=1)
        new_email.grid(row=1, column=0)
        new_email_password.grid(row=2, column=0)
        new_email_entry.grid(row=1, column=1)
        new_email_password_entry.grid(row=2, column=1)

        new_img_label.place(x=110, y=50)
        new_email.place(x=10, y=70 + 50)
        new_email_password.place(x=10, y=100 + 50)
        new_email_entry.place(x=150 - 40, y=70 + 50)
        new_email_password_entry.place(x=150 - 40, y=100 + 50)

        new_email_password_entry.config(show="")

        new_email_password_entry.config(fg="grey")
        new_email_password_entry.insert(0, "New Email password")

        new_email_entry.config(fg="grey")
        new_email_entry.insert(0, "New Email")
        self.object.execute(
            "select email_id from data_input where username=(?)", (
                simple_encrypt(self.real_username),)
        )
        for i in self.object.fetchall():
            save = Button(
                new_window,
                text="Save",
                command=lambda: self.save_email(
                    str(new_email_entry.get()),
                    simple_decrypt(i[0]),
                    self.recovery,
                    str(new_email_password_entry.get()),
                    self.password,
                    self.object
                ),
            )
            save.place(x=150 - 40, y=200)

        new_email_entry.bind(
            "<FocusIn>",
            lambda event, val_val=new_email_entry, index=1: handle_focus_in(
                val_val, index
            ),
        )
        new_email_entry.bind(
            "<FocusOut>",
            lambda event, val_val=new_email_entry, val="Email", index=1: handle_focus_out(
                val_val, val, index
            ),
        )

        new_email_password_entry.bind(
            "<FocusIn>",
            lambda event, val_val=new_email_password_entry, index=2: handle_focus_in(
                val_val, index
            ),
        )
        new_email_password_entry.bind(
            "<FocusOut>",
            lambda event, val_val=new_email_password_entry, val="New Email password", index=2: handle_focus_out(
                val_val, val, index
            ),
        )

        private_img = tk_image.PhotoImage(image.open(f"{path}private.png"))
        unhide_img = tk_image.PhotoImage(image.open(f"{path}eye.png"))

        show_both_12 = Button(
            new_window,
            image=unhide_img,
            command=lambda: password_sec(
                new_email_password_entry, show_both_12),
            fg="white",
            bd="0",
            bg="#292A2D",
            highlightcolor="#292A2D",
            activebackground="#292A2D",
            activeforeground="white",
            relief=RAISED,
        )
        show_both_12.image = unhide_img
        show_both_12.place(x=250 - 15, y=100 + 50 - 5)
