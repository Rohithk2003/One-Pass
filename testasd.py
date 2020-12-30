var = 0
file = None


class Gameloop(Frame):
    def __init__(self, parent, object, username):
        Frame.__init__(self, parent)
        global var
        global file
        self.var = var
        self.file = file
        self.object = object
        self.status = status_name
        self.username = username
        status_name = False

        self.sidebar = Frame(
            self, width=5, bg="#292A2D", height=500, relief="sunken", borderwidth=1
        )
        self.sidebar.pack(expand=False, fill="both", side="left")
        main_ic = tk_image.PhotoImage(image.open(f'{path}\\main_icon.png'))
        notes_img = tk_image.PhotoImage(image.open(f"{path}\\_notes.png"))
        self.mainarea = Frame(self, bg="#292A2D", width=500, height=500)
        self.mainarea.pack(expand=True, fill="both", side="right")
        new_button = tk_image.PhotoImage(image.open(f"{path}\\_new_but.jpg"))
        self.button = Button(
            self.sidebar,
            image=new_button,
            text='Passwords',
            bg='#292A2D',
            compound=CENTER,
            border=0,
            bd=0,
            borderwidth=0,
            highlightthickness=0,
            highlightcolor='#292A2D',
            command=lambda: self.testing())
        self.object.execute(
            "select email_id,salt_recovery from data_input where username = (?)",
            (simple_encrypt(self.username),),
        )
        self.hash_password = hashlib.sha3_512(
            (password_new + username).encode()).hexdigest()
        email_id = ""

        for email in self.object.fetchall():
            self.email_id = simple_decrypt(email[0])

        email_split = ""
        decrypted_string = ""

        word = self.email_id.split()
        for i in word:
            for a in i:
                if i == "@":
                    break
                else:
                    email_split += i
        val = email_split[::-1]
        self.object.execute(
            "select recovery_password,salt_recovery from data_input where username = (?)",
            (simple_encrypt(self.username),),
        )
        encrypted_pass = ""
        d = self.object.fetchall()
        encrypt, salt = '', ''
        for i in d:
            salt = i[1]
            encrypt = i[0]
        password = self.email_id + self.hash_password
        key = pbkdf2.PBKDF2(password, salt).read(32)
        aes = pyaes.AESModeOfOperationCTR(key)
        self.encrypted_pass = aes.decrypt(encrypt)
        self.notes_buttons = Button(
            self.sidebar,
            image=new_button,
            text='Notes',
            bg='#292A2D',
            compound=CENTER,
            border=0,
            bd=0,
            borderwidth=0,
            highlightthickness=0,
            highlightcolor='#292A2D',

        )
        self.sidebar_icon.grid(row=0, column=1)
        self.button.grid(row=1, column=1)
        self.button.place(x=0, y=150 + 20)
        self.notes_buttons.grid(row=2, column=1)
        self.notes_buttons.place(x=0, y=140 + 20 + 20 + 17)
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
        )
        profile_object = Profile_view(
            self.username,
            self.password,
            self.email_id,
            self.encrypted_pass,
            self.hash_password,
            self.mainarea,
            self.button,
            self.notes_buttons,
            parent,
            self.object
        )
        self.profile_button = Button(
            self.sidebar,
            image=new_button,
            text=f'Profile',
            bg='#292A2D',
            compound=CENTER,
            border=0,
            bd=0,
            borderwidth=0,
            highlightthickness=0,
            highlightcolor='#292A2D',


        )
        self.profile_button.photo = new_button
        self.profile_button.grid(row=3, column=1)
        self.profile_button.place(x=0, y=140 + 20 + 20 + 30 + 14)

        self.settings_button.photo = settings_image
        self.settings_button.grid(row=10, column=1, columnspan=1)
        self.settings_button.place(x=30 + 50 + 10, y=440 + 200 + 20)
    def testing(self):
        self.button["state"] = DISABLED
        self.notes_buttons["state"] = NORMAL
        self.profile_button["state"] = NORMAL
        parent.title("Passwords")
        emptyMenu = Menu(parent)
        self.config(bg="#292A2D")
        parent.config(menu=emptyMenu)
        parent.iconbitmap(f"{path}\\password.ico")
