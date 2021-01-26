import smtplib
import pyAesCrypt
import secrets
import pickle
import sqlite3
from  data.show_hide import *
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
def check_pass_integrity(username,password):
                if username == password:
                    return False
                with open("pass.txt", 'r') as file:
                    data = file.read().split()
                for i in data:
                    if i == password:
                        return False
                return True

def forgot_password(email, *OTP):
    try:
        global running
        running = True
        SUBJECT = "EMAIL verification for ONE-PASS-MANAGER"
        otp = f"Hey {OTP[1]}!\nOTP to change password is {OTP[0]}"
        msg = f"Subject: {SUBJECT}\n\n{otp}"
        s = smtplib.SMTP("smtp.gmail.com", 587)
        s.starttls()
        s.login("rohithk6474@gmail.com", "Kedaram@123")
        s.sendmail("rohithk6474@gmail.com", email, msg)
    except:
        a = Tk()
        a.withdraw()
        messagebox.showwarning("Error", "Please try again later")
def change(window,object,email,rec_pass,username12,new_password,new_username,original_password,main_pass):
    if len(new_password) > 5:
        if check_pass_integrity(new_username,new_password):
            if not  os.path.exists(f'{username12}decrypted.bin'):#checking whether the user has logged in and trying to change password
                value = original_password + username12
                re_hash = hashlib.sha3_512(value.encode()).hexdigest()
                file_name_reentry = f'{username12}.bin.aes'
                pyAesCrypt.decryptFile(
                        file_name_reentry,
                        username12 + "decrypted.bin",
                        re_hash,
                        bufferSize,
                    )
            #if the user has logged then no need to decrypt the file again
            os.remove(f'{username12}.bin.aes')
            re_hash_text = str(new_password) + str(
                new_username
            )
            new_salt = str(new_password) + "@" + main_pass
            re_hash_new = hashlib.sha3_512(
                re_hash_text.encode()).hexdigest()#re hashing the new password for encrypting the file 
            re_encrypt, new_salt = create_key(main_pass, new_salt)
            pyAesCrypt.encryptFile(
                username12 + "decrypted.bin",
                str(new_username) + ".bin.aes",
                re_hash_new,
                bufferSize,
            )

            password_recovery_email = email + re_hash_new 
            passwordSalt = secrets.token_bytes(512)
            key = pbkdf2.PBKDF2(
                password_recovery_email, passwordSalt).read(32)
            aes = pyaes.AESModeOfOperationCTR(key)#initialising the mode of encryption for recovery pass
            encrypted_pass = aes.encrypt(rec_pass)
            #updating the database
            object.execute(
                "update data_input set username = (%s),password=(%s),recovery_password = (%s),salt_recovery=(%s) "
                "where email_id = (%s)",
                (
                    simple_encrypt(str(new_username)),
                    re_encrypt,
                    encrypted_pass,
                    passwordSalt,
                    simple_encrypt(email),
                ),
            )
            messagebox.showinfo(
                "Success", "Your username and password has been changed"
            )
            window.destroy()
        else:
            messagebox.showerror("Strength","Please provide a stronger password")
    else:
        messagebox.showerror("Length","length of the password must be greater than 5")

def login_password(title1, object):
    window = Toplevel()
    window.config(bg="#1E1E1E")
    window.resizable(False, False)
    window.focus_force()
    window.title(title1)
    text = (
        "Please provide the recovery email  and recovery email password \n that you entered while creating an "
        "account "
    )
    text_label = Label(window, text=text, font=("Yu Gothic Ui", 13), fg="#994422", bg="#1E1E1E")
    width_window = 450
    height_window = 400
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2
    window.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))

    logo_image = tk_image.PhotoImage(image.open(f"{path}member.png"))
    main_label = Label(window, image=logo_image, bg="#1E1E1E")
    main_label.photo = logo_image
    main_label.place(x=150, y=50)

    username_forgot = Label(window, text="Username:",
                            fg="white",
                            bg="#1E1E1E",
                            font=("Yu Gothic Ui", 15), )
    recover_email = Label(window, text="Recovery Email:",
                          fg="white",
                          bg="#1E1E1E",
                          font=("Yu Gothic Ui", 15), )
    recover_password = Label(window, text="Recovery Password:", fg="white",
                             bg="#1E1E1E",
                             font=("Yu Gothic Ui", 15), )
    recover_email_entry = Entry(window,
                                width=13,
                                bg="#1E1E1E",
                                foreground="white",
                                border=0,
                                bd=0,
                                fg='white',
                                font=("consolas", 15, "normal"),
                                insertbackground="white", )
    recover_password_entry = Entry(window,
                                   width=13,
                                   bg="#1E1E1E",
                                   foreground="white",
                                   fg='white',
                                   border=0,
                                   bd=0,
                                   font=("consolas", 15, "normal"),
                                   insertbackground="white", )
    username_forgot_entry = Entry(window,
                                  width=13,
                                  bg="#1E1E1E",
                                  border=0,
                                  bd=0,
                                  fg='white',

                                  font=("consolas", 15, "normal"),
                                  foreground="white",
                                  insertbackground="white", )

    username_forgot.place(x=0, y=70 + 100 + 3)
    recover_password.place(x=0, y=130 + 100 + 30 + 3)
    recover_email.place(x=0, y=100 + 100 + 15 + 3)
    username_forgot_entry.place(x=250, y=70 + 100 + 5)
    recover_password_entry.place(x=250, y=130 + 100 + 30 + 5)
    recover_email_entry.place(x=250, y=100 + 100 + 15 + 5)
    text_label.place(x=20, y=0)
    main_key = ""
    alphabets = string.ascii_lowercase
    for letters in range(7):
        main_key += random.choice(alphabets)
    def verify_rec_password(window,email,password,main_key,but,object):
            object.execute(
                "select password,salt from data_input where email_id = (%s)", (
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
            main_pass = new_val + "/" + password
            has = None
            salt = None
            decrypted_string = ""
            for i in values_password:
                has = i[0]
                salt = i[1]
            try:
                            string = retreive_key(main_pass, has, salt)
                            for i in string:
                                if i == "@":
                                    break
                                else:
                                    decrypted_string += i
                            main(main_key,window,but,decrypted_string,main_pass)
            except:
                messagebox.showerror("Wrong Password","Invalid recovery password")
    def generate_key1(file,main_key, button):

        pyAesCrypt.encryptFile(file, "otp.bin.aes", main_key, bufferSize)
        os.unlink(file)
        button.config(state=DISABLED)
        a = Tk()
        a.withdraw()
        messagebox.showinfo(
            "OTP", f"An OTP has been sent to  {str(recover_email_entry.get())}"
        )
        window.focus_force()

        a.destroy()
    def change_password(email, password1, username12,original_password,main_pass):

        window.destroy()
        root = Toplevel()
        new_img = tk_image.PhotoImage(image.open(f"{path}member.png"))
        new_img_label = Label(root, image=new_img, bg="#1E1E1E")
        new_img_label.photo = new_img
        root.resizable(False, False)
        file_name_reentry = 'kiren' + ".bin.aes"

        width_window = 400
        height_window = 400
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        root.title("Change Details")
        root.config(bg="#1E1E1E")

        new_username = Label(root, text="New Username",font=("Segoe Ui", 13),
                             fg="white", bg="#1E1E1E")
        new_password = Label(root, text="New Password",font=("Segoe Ui", 13),
                             fg="white", bg="#1E1E1E")

        new_username_entry = Entry(root)
        new_password_entry = Entry(root, show="*")

        new_img_label.place(x=130,y=0)
        new_username.place(x=50,y=200)
        new_password.place(x=50,y=250)
        new_username_entry.place(x=200,y=203)
        new_password_entry.place(x=200,y=250+3)


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
            bg="#1E1E1E",
            highlightcolor="#1E1E1E",
            activebackground="#1E1E1E",
            activeforeground="white",
            relief=RAISED,
        )
        show_both_12.place(x=340,y=245)
        
        save = Button(root,text='Save!',font=("Segoe Ui", 13),fg='white',bg="#1E1E1E",command=lambda:change(root,object,email,password1,username12,str(new_password_entry.get()),str(new_username_entry.get()),original_password,main_pass))
        save.place(x=150,y=290)
        
    def Verification(password, otp_entry, email, email_password, username12, button,original_password,main_pass):
        ot = str(otp_entry)
        if ot != "":
            pyAesCrypt.decryptFile(
                "otp.bin.aes", "otp_decyrpted.bin", password, bufferSize
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
                    os.remove("otp.bin.aes")
                    change_password(email, email_password,
                                    username12, original_password, main_pass)
                else:
                    messagebox.showinfo(
                        "Error", "Incorrect OTP Please verify it again")
                    button.config(state=NORMAL)
                    otp_entry.delete(0, END)
        else:
            messagebox.showinfo(
                "Error", "Please provide the OTP  send to your email")

    def main(main_key, otp_window, button,original_password,main_pass):
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
        elif not os.path.exists(username_verify + ".bin.aes"):

            messagebox.showwarning(
                "Warning", f"Cannot find user {username_verify}")

        else:
            if os.path.exists(username_verify + ".bin.aes"):
                verify_password = ""
                for i in recover_email_entry_verify:
                    if i == "@":
                        break
                    else:
                        verify_password += i
                verify_password += recover_password_entry_verify
                object.execute(
                    "select email_id from data_input where username = (%s)",
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
                        width=15,
                        font="consolas",
                        fg="white",
                        bg="#994422",
                        bd=0,
                        command=lambda: Verification(
                            str(main_key),
                            otp_entry.get(),
                            recover_email_entry_verify,
                            recover_password_entry_verify,
                            username_verify,
                            button,
                            original_password,
                            main_pass
                        ))
                    
                    otp_entry_button.grid(row=8, column=1)
                    otp_entry_button.place(x=70, y=200+ 120+40)
                    otp_entry.place(x=200+40, y=200 + 120+45)
                    digits = "1234567890"
                    OTP = ""
                    for i in range(6):
                        OTP += random.choice(digits)
                    OTP_secure = hashlib.sha512(OTP.encode()).hexdigest()
                    l = list(OTP_secure)
                    with open("otp.bin", "wb") as f:
                        pickle.dump(l, f)
                        f.close()
                    generate_key1("otp.bin",str(main_key), button)
                    forgot_password(recover_email_entry_verify, OTP,  username_verify)
            else:
                messagebox.showerror("Error", "No such account exists")

    forgot_password_button = Button(
        window,
        command=lambda:verify_rec_password(window,str(recover_email_entry.get()),str(recover_password_entry.get()),main_key,forgot_password_button,object),
        width=15,
        text="V E R I F Y",
        font="consolas",
        fg="white",
        bg="#994422",
        bd=0,
    )
    forgot_password_button.grid(row=5, column=1)
    forgot_password_button.place(x=150, y=200 + 120)


    # removing border for entry
    # then adding frames like a line
    Frame(window, width=150, height=2, bg="white").place(
        x=250, y=70 + 100 + 10 + 16 + 5
    )
    Frame(window, width=150, height=2, bg="white").place(
        x=250, y=130 + 100 + 10 + 16 + 30 + 5
    )
    Frame(window, width=150, height=2, bg="white").place(
        x=250, y=100 + 100 + 10 + 16 + 15 + 5
    )

