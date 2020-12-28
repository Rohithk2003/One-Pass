
from data.delete_class import *

path = ''
#finding the os so tha  the images are displayed properly
if platform.system() == "Windows":
    path = "images\\"
if platform.system() == 'Darwin':
    dir_path = os.getcwd()
    path = dir_path + "/images/"

class Profile_view:
    def __init__(
            self,
            username,
            password,
            email_id,
            email_password,
            hashed_password,
            profile,
            password_button,
            notepad_button,
            main,
            object
    ):
        self.username = username
        self.password = password
        self.email_id = email_id
        self.email_password = email_password
        self.hashed_password = hashed_password
        self.object = object
        for widget in profile.winfo_children():
            widget.destroy()
        self.root = main

        self.password_button = password_button
        self.notepad = notepad_button

    def profile_window(self, profile, s, profile_button):
        s.iconbitmap(f"{path}profile.ico")
        profile_button["state"] = DISABLED
        self.password_button["state"] = NORMAL
        self.notepad["state"] = NORMAL
        try:
            for widget in profile.winfo_children():
                widget.destroy()
        except:
            pass
        profile.config(bg="#292A2D")
        s.title("Profile")

        emptyMenu = Menu(s)

        s.config(menu=emptyMenu)

        s.iconbitmap(f"{path}profile.ico")
        # profile window image
        member = tk_image.PhotoImage(image.open(f"{path}member.png"))

        profileimg = tk_image.PhotoImage(
            image.open(f"{path}profile_image.png"))
        new_canvas = Canvas(profile, width=1270,
                            height=700, highlightthickness=0)
        new_canvas.place(x=0, y=0)
        new_canvas.background = profileimg
        new_canvas.create_image(0, 0, image=profileimg, anchor="nw")
        new_s = Frame(
            new_canvas,
            bg="#292A2D",
            highlightcolor="black",
            highlightbackground="black",
            width=560,
            height=500,
        )

        MainWindow = new_canvas.create_window(
            600 - 30, 300 + 50, window=new_s, anchor="center"
        )

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
        delete_object = Deletion(self.username, self.hashed_password, profile, self.object)
        delete_this_account = Button(
            new_s,
            text="Delete Account",
            fg="white",
            bg="black",
            activebackground="black",
            activeforeground="white",
            font="Helvetiva 10",
            command=lambda: delete_object.delete_main_account(s),
        )

        username_label.place(x=5, y=100 + 100)
        password_label.place(x=5, y=150 + 100)
        email_id_label.place(x=5, y=200 + 100)
        email_password_label.place(x=5, y=250 + 100)
        profile_photo.place(x=200, y=50)
        delete_this_account.place(x=0 + 2, y=400 + 50 + 20)

        username_label_right.place(x=300 - 70, y=100 + 100)
        password_label_right.place(x=300 - 70, y=150 + 100)
        email_id_label_right.place(x=300 - 70, y=200 + 100)
        email_password_label_right.place(x=300 - 70, y=250 + 100)

        # putting the dot on the frame
        dot.place(x=200, y=100 + 100 + 6)
        dot1.place(x=200, y=150 + 100 + 6)
        dot2.place(x=200, y=200 + 100 + 6)
        dot3.place(x=200, y=250 + 100 + 6)

