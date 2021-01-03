import smtplib
import pyAesCrypt
import secrets
import pickle

from data.show_hide import *
from data.encryptiondecryption import *

# set the buffer size

bufferSize = 64 * 1024

# finding the os
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


def login_password(title1, object):
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
            object.execute(
                "select password,salt from data_input where email_id = (?)", (
                    simple_encrypt(email),)
            )
            values_password = object.fetchall()
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
                object.execute(
                    "select email_id from data_input where username=(?)", (
                        simple_encrypt(username12),)
                )
                for i in object.fetchall():
                    password_recovery_email = simple_decrypt(
                        i[0]) + re_hash_new
                    passwordSalt = secrets.token_bytes(512)
                    key = pbkdf2.PBKDF2(
                        password_recovery_email, passwordSalt).read(32)
                    aes = pyaes.AESModeOfOperationCTR(key)
                    encrypted_pass = aes.encrypt(password1)

                    object.execute(
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
                object.execute(
                    "select email_id from data_input where username = (?)",
                    (simple_encrypt(username_verify),),
                )
                values_fetch = object.fetchall()

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
