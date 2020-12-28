

from data.apploop import *
from data.for_encryption import *
from data.settingsandlogout import settings
from data.note_pad import note_pad_sec
from data.profile_class import Profile_view
var = 0



#finding the os
bufferSize = 64 * 1024
if platform.system() == "Windows":
    path = "D:\\Computer Project\\One-Pass\\"
if platform.system() == 'Darwin':
    dir_path = os.getcwd()
    path = dir_path + "/images/"


def window_after(username, hash_password, password_new,object, *window):
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
    object.execute(
        "select email_id,salt_recovery from data_input where username = (?)",
        (simple_encrypt(username),),
    )
    hash_password = hashlib.sha3_512(
        (password_new + username).encode()).hexdigest()
    email_id = ""
    for email in object.fetchall():
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
    object.execute(
        "select recovery_password,salt_recovery from data_input where username = (?)",
        (simple_encrypt(username),),
    )
    encrypted_pass = ""
    d = object.fetchall()
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
        command=lambda: note_pad_sec(
            notes_buttons, button, profile_button, root, mainarea, sidebar),

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
            object
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
        object
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
