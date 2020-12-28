from tkinter.ttk import *
from tkinter import *
from PIL import ImageTk as tk_image
from PIL import Image as image
from tkinter import filedialog as fd
from tkinter import messagebox
from data.delete_class import *
import pickle
import pyAesCrypt
import os
import platform
from data.change_class import *
buttons_list = {}
btn_nr = -1
path = ''
image_path = ""
exist = False
bufferSize = 64 * 1024

#finding the os so tha  the images are displayed properly
if platform.system() == "Windows":
    path = "images\\"
if platform.system() == 'Darwin':
    dir_path = os.getcwd()
    path = dir_path + "/images/"


def verify(social_username, social_media, real_username):
    file_name = f"{real_username}decrypted.bin"
    with open(file_name, "rb") as f:
        try:
            test_values = pickle.load(f)
            for user in test_values:
                if user[0] == str(social_username) and user[2] == str(social_media):
                    return True
        except:
            return False


def addaccount(username, button, hashed_password, window, sidebar, password_button):
    root1 = Toplevel()
    root1.geometry("400x300")
    root1.title("Add Account")
    root1.focus_set()
    root1.grab_set()
    root1.resizable(False, False)
    width_window = 400
    height_window = 400
    screen_width = root1.winfo_screenwidth()
    screen_height = root1.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2
    root1.config(bg="#292A2D")
    root1.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
    name_of_social = Label(
        root1, text="Name of the account", fg="white", bg="#292A2D")
    name_of_social_entry = Entry(root1)
    username_window = Label(root1, text="Username:", fg="white", bg="#292A2D")
    password_window = Label(root1, text="Password:", fg="white", bg="#292A2D")
    username_window_entry = Entry(root1)
    password_entry = Entry(root1)

    password_entry.grid(row=2, column=2)
    username_window_entry.grid(row=1, column=2)
    password_window.grid(row=2, column=1)
    username_window.grid(row=1, column=1)
    name_of_social_entry.grid(row=0, column=2)
    name_of_social.grid(row=0, column=1)

    username_window.place(x=50, y=100 + 100)
    password_window.place(x=50, y=130 + 100)
    name_of_social.place(x=50, y=70 + 100)
    username_window_entry.place(x=200, y=100 + 100)
    password_entry.place(x=200, y=130 + 100)
    name_of_social_entry.place(x=200, y=70 + 100)

    def browsefunc():
        try:
            image_path = fd.askopenfilename()
            im = image.open(image_path)
            tkimage = tk_image.PhotoImage(im)
            add_icon_button.config(image=tkimage)
            add_icon_button.photo = tkimage
        except:
            image_path = f"{path}photo.png"
            im = image.open(image_path)
            tkimage = tk_image.PhotoImage(im)
            add_icon_button.config(image=tkimage)
            add_icon_button.photo = tkimage

    new_id = tk_image.PhotoImage(image.open(f"{path}photo.png"))
    add_icon_button = Button(
        root1,
        image=new_id,
        borderwidth="0",
        command=browsefunc,
        border="0",
        highlightthickness="0",
        activebackground="#292A2D",
        bg="#292A2D",
    )
    add_icon_button.photo = new_id
    add_icon_button.grid(row=3, column=0)
    add_icon_button.place(x=125, y=200)

    def save():
        global exist
        list_account = [
            str(username_window_entry.get()),
            str(password_entry.get()),
            str(name_of_social_entry.get()),
            image_path,
        ]
        if str(username_window_entry.get()) == "":
            messagebox.showwarning("Warning", "Username cannot be empty")
        elif str(password_entry.get()) == "":
            messagebox.showwarning("Warning", "Password cannot be empty")
        elif str(name_of_social_entry.get()) == "":
            messagebox.showwarning(
                "Warning", "Name of the account cannot be empty")
        else:
            verifying = verify(
                username_window_entry.get(), name_of_social_entry.get(), username
            )

            if verifying:
                messagebox.showerror("Error", "The account already exists")
            else:
                name_file = username + "decrypted.bin"
                with open(name_file, "rb") as f:
                    try:
                        line = pickle.load(f)
                    except:
                        line = []
                    line.append(list_account)
                    f.close()
                with open(name_file, "wb") as f1:
                    pickle.dump(line, f1)
                    f.close()
                os.remove(username + ".bin.fenc")
                pyAesCrypt.encryptFile(
                    name_file, username + ".bin.fenc", hashed_password, bufferSize
                )
                messagebox.showinfo("Success", "Your account has been saved")
                root1.destroy()
                with open(f"{username}decrypted.bin", "rb") as f:
                    val = pickle.load(f)
                    button.grid(row=len(val) + 1, column=0)
                gameloop(username, hashed_password, window, password_button)

    save_button = Button(root1, text="Save", command=save,
                         fg="white", bg="#292A2D")
    save_button.grid(row=4, column=1)
    save_button.place(x=250, y=170 + 100)
    add_icon_button.place(x=150, y=50)
    root1.mainloop()


def change_icon(
        button, usernam, users_username, hashed_password, window, password_button
):
    file_name = users_username + "decrypted.bin"
    l = [(32, 32), (16, 16)]
    image_path = fd.askopenfilename(
        filetypes=[("image", "*.png"), ("image", "*.jpeg"),
                   ("image", "*.jpg")],
        title="Add icon",
    )
    f = open(file_name, "rb")
    pad = pickle.load(f)
    f.close()
    path = ""
    for i in pad:
        if i[0] == usernam:
            path = i[3]
    if path == "":
        path_im = image.open(f"{path}camera.png")
    else:
        path_im = image.open(path)

    try:
        im = image.open(image_path)

        if im:

            if im.size in l:
                for i in pad:
                    if i[0] == usernam:
                        i[3] = image_path
                f.close()
                with open(file_name, "wb") as f1:
                    pickle.dump(pad, f1)
                    f1.close()
                os.remove(users_username + ".bin.fenc")

                pyAesCrypt.encryptFile(
                    file_name, users_username + ".bin.fenc", hashed_password, bufferSize
                )
                new_tk = tk_image.PhotoImage(im)
                button.config(image=new_tk)
                button.photo = new_tk
                gameloop(users_username, hashed_password,
                         window, password_button)
            else:
                messagebox.showerror(
                    "Error", "Please provide icon size of 32x32 or 16x16 "
                )
                im = image.open(f"{path}camera.png")
                new_tk = tk_image.PhotoImage(im)
                button.config(image=new_tk)
                button.photo = new_tk
                image_path = fd.askopenfilename(
                    filetypes=[("image", "*.png")], title="Add icon"
                )
                gameloop(users_username, hashed_password,
                         window, password_button)

    except:
        new_tk = tk_image.PhotoImage(path_im)
        button.config(image=new_tk)
        button.photo = new_tk

def actions(button, window, username, hashed_password, bg_img, password_button):
    global buttons_list

    change_object = Change_details(username, hashed_password, window)

    delete_object = Deletion(username, hashed_password, window)

    try:
        for widget in window.winfo_children():
            if str(widget.winfo_class()) != "Frame":
                widget.destroy()
    except:
        pass
    # creating a canvas to fix background image
    new_canvas = Canvas(
        window, width=1000 + 50, height=1057, bd="0", highlightthickness=0
    )
    new_canvas.place(x=120 + 20, y=0)
    new_canvas.create_image(0, 0, image=bg_img, anchor="nw")
    new_s = Frame(new_canvas, bg="#292A2D", width=450, height=400, bd=0)
    MainWindow = new_canvas.create_window(
        650 + 60, 600 - 60, window=new_s, anchor="se")

    with open(f"{username}decrypted.bin", "rb") as f:

        lists = pickle.load(f)
        dot_text = Label(new_s, text=":", bg="#292A2D", fg="white", font=(20))
        dot_text1 = Label(new_s, text=":", bg="#292A2D", fg="white", font=(20))
        dot_text2 = Label(new_s, text=":", bg="#292A2D", fg="white", font=(20))

        delete_account = Button(
            new_s,
            text="Delete Account",
            bg="#292A2D",
            fg="white",
            font=("Verdana", 15),
            command=lambda: delete_object.delete_social_media_account(
                password_button, False, lists[button][2]
            ),
        )

        ChangeAccount = Button(
            new_s,
            text="Change Details",
            bg="#292A2D",
            fg="white",
            font=("Verdana", 15),
            command=lambda: change_object.change_window_creation(
                lists[button][0], password_button
            ),
        )

        username_label = Label(
            new_s,
            text="Username",
            bg="#292A2D",
            fg="white",
            font=("Verdana", 15),
        )
        password_label = Label(
            new_s,
            text="Password",
            bg="#292A2D",
            fg="white",
            font=("Verdana", 15),
        )
        social_account = Label(
            new_s,
            text="Account Name",
            bg="#292A2D",
            fg="white",
            font=("Verdana", 15),
        )

        username_text = Label(
            new_s,
            text=lists[button][0],
            bg="#292A2D",
            fg="white",
            font=("Verdana", 15),
        )
        password_text = Label(
            new_s,
            text=lists[button][1],
            bg="#292A2D",
            fg="white",
            font=("Verdana", 15),
        )
        social_account_text = Label(
            new_s,
            text=lists[button][2],
            bg="#292A2D",
            fg="white",
            font=("Verdana", 15),
        )

        if lists[button][3] == "":
            img = tk_image.PhotoImage(image.open(f"{path}camera.png"))
        else:
            img = tk_image.PhotoImage(image.open(lists[button][3]))
        img_button = Button(
            new_s,
            image=img,
            border="0",
            bg="#292A2D",
            activebackground="#292A2D",
            command=lambda: change_icon(
                img_button,
                lists[button][0],
                username,
                hashed_password,
                new_s,
                password_button,
            ),
        )
        img_button.photo = img

        img_button.place(x=160, y=30)
        dot_text.place(x=170 + 20, y=175 + 3)
        dot_text1.place(x=170 + 20, y=200 + 25 + 3)
        dot_text2.place(x=170 + 20, y=250 + 25 + 3)

        delete_account.place(x=0 + 10, y=350)
        username_label.place(x=30, y=175)
        password_label.place(x=30, y=200 + 25)
        social_account.place(x=30, y=250 + 25)
        username_text.place(x=250, y=150 + 25)
        password_text.place(x=250, y=200 + 25)
        social_account_text.place(x=250, y=250 + 25)
        ChangeAccount.place(x=250 + 25 - 3, y=350)

def buttons_blit(
        username, window, add_button, mainarea, hashed_password, bg_img, password_button
):
    global buttons_list
    global btn_nr
    new = []

    with open(f"{username}decrypted.bin", "rb") as f:
        try:
            val = pickle.load(f)
            for i in val:
                new.append(i[2])
            d = {}
            for i in range(len(new)):
                if val[i][3] == "":
                    button_img = tk_image.PhotoImage(
                        image.open(f"{path}photo.png"))
                else:
                    button_img = tk_image.PhotoImage(image.open(val[i][3]))
                d[
                    Button(
                        window,
                        text=f"{new[i]}",
                        bg="#292A2D",
                        fg="white",
                        activeforeground="white",
                        activebackground="#292A2D",
                        width=120,
                        font=("Segoe UI Semibold", 9),
                        image=button_img,
                        compound="top",
                        command=lambda a=i: actions(
                            a,
                            mainarea,
                            username,
                            hashed_password,
                            bg_img,
                            password_button,
                        ),
                    )
                ] = [i, button_img]

            for i in d:
                i.image = d[i][1]
                i.grid(row=d[i][0], column=0)
            with open(f"{username}decrypted.bin", "rb") as f:
                try:
                    values = pickle.load(f)
                except:
                    values = []
            length_list = len(values)
            add_button.grid(row=length_list + 1, column=0)
        except:
            pass


def gameloop(username, hashed_password, window, password_button):
    bg_img = tk_image.PhotoImage(image.open(f"{path}log.jpg"))
    vals = window.grid_slaves()
    try:
        for i in vals:
            i.destroy()
    except:
        pass

    window.config(bg="#292A2D")
    subbar = Frame(
        window, bg="black", width=120, height=1027, relief="sunken", borderwidth=2
    )
    subbar.grid(row=0, column=0)
    subbar.grid_propagate(False)
    new_l = Label(window, image=bg_img, bd=0)
    new_l.image = bg_img
    new_l.place(x=120 + 20, y=0)
    canvas = Canvas(
        subbar, width=120, height=1027, bg="black", bd="0", highlightthickness=0
    )
    canvas.pack(side="left", fill=BOTH)

    scrollbar = Scrollbar(
        subbar,
        orient=VERTICAL,
        activebackground="#292A2D",
        troughcolor="white",
        takefocus=1,
        highlightbackground="#292A2D",
        highlightthickness=0,
        bg="#292A2D",
        command=canvas.yview,
    )

    scrollbar.pack(expand=1, fill=Y)

    # configure the canvas
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.bind(
        "<Configure>", lambda event: canvas.configure(
            scrollregion=canvas.bbox("all"))
    )

    # creating another frame
    second_frame = Frame(
        canvas, width=120, height=1027, bd="0", bg="black", highlightbackground="black"
    )

    # add that new frame to a new window in the canvas
    canvas.create_window((0, 0), window=second_frame, anchor="ne")
    image_new = tk_image.PhotoImage(image.open(f"{path}add-button.png"))
    bg_img = tk_image.PhotoImage(image.open(f"{path}log.jpg"))

    add_button = Button(
        second_frame,
        text="Add",
        fg="white",
        image=image_new,
        compound="top",
        activeforeground="white",
        bg="#292A2D",
        height=80,
        activebackground="#292A2D",
        width=120,
        relief=RAISED,
        font=("Verdana", 9),
        command=lambda: addaccount(
            username, add_button, hashed_password, window, subbar, password_button
        ),
    )
    add_button.photo = image_new
    values = []
    with open(f"{username}decrypted.bin", "rb") as f:
        try:
            values = pickle.load(f)
        except:
            pass
    length_list = len(values)
    add_button.grid(row=length_list, column=0)
    buttons_blit(
        username,
        second_frame,
        add_button,
        window,
        hashed_password,
        bg_img,
        password_button,
    )
