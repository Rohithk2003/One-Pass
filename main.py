import os
import pickle
import sys
from tkinter import *
from tkinter import messagebox
import pyAesCrypt
import pygame
import os.path

pygame.init()
bufferSize = 64 * 1024
root = Tk()  # main windows were the login screen and register screen goes
root.title("ONE-PASS")  # windows title
password = 0
username = 0
social_media = []

num_enemies = 5
facebook = pygame.image.load("facebook.png")
instagram = pygame.image.load("instagram.png")
google = pygame.image.load("google.png")
github = pygame.image.load("github.png")

# getting the size of the facebook image
fb_size = facebook.get_rect()

# social_media.append(facebook)
# social_media.append(instagram)
# social_media.append(google)
# social_media.append(github)

# colors
black = (0, 0, 0)
white = (255, 255, 255)
red = (255, 0, 0)
blue = (0, 0, 255)
green = (0, 255, 0)
catch_error = True

fb_user_text = ""
active_fb = False

font = pygame.font.Font("freesansbold.ttf", 30)


def text_object(text, font, color):
    textsurf = font.render(text, True, color)
    return textsurf, textsurf.get_rect()


# added message display function to blit text on to the window


def message_display_small(text, a, b, color, display):
    smalltext = pygame.font.Font("comic.ttf", 30)
    textsurf, textrect = text_object(text, smalltext, color)
    textrect.center = (int(a), int(b))
    display.blit(textsurf, textrect)


def fb_text(text, a, b, color, display):
    smalltext = pygame.font.Font("freesansbold.ttf", 30)
    textsurf, textrect = text_object(text, smalltext, color)
    textrect.center = (int(a), int(b))
    display.blit(textsurf, textrect)


def fb_button(username, password):
    file_name = str(username) + str(password) + ".bin"
    if os.path.exists(file_name):
        root = Tk()
        f1 = open(file_name, "rb")
        line = pickle.load(f1)
        root.title("Facebook Account")
        first = line[0]
        second = line[1]
        a1_text = Label(root, text=first)
        a2_text = Label(root, text=second)
        a1_text.grid(row=0, column=0)
        a2_text.grid(row=1, column=0)
    else:
        second = Tk()
        second.title("Facebook Login")
        username1 = Label(second, text="Username:")
        password1 = Label(second, text="Password:")
        username1_entry = Entry(second)
        password1_entry = Entry(second, show="*")
        login_text1 = "Please provide Facebook account and password"
        change = "Do you want to change password or username"
        change_button = Button(second, text=change)
        login_text = Label(second, text=login_text1)
        username1.grid(row=2, column=0)
        password1.grid(row=3, column=0)
        username1_entry.grid(row=2, column=1)
        password1_entry.grid(row=3, column=1, columnspan=2)
        username2 = username1_entry.get()
        password2 = password1_entry.get()
        username_list = []

        def save():
            username_list.append(username2)
            username_list.append(password2)
            fie = str(username) + str(password)
            f = open(fie + ".bin", "wb")
            pickle.dump(username_list, f)
            f.close()

        saving = Button(second, text="Save", command=save)
        saving.grid(row=3, column=1)
        change_button.grid(row=4, column=1)


def gameloop(a, file):
    fb = "Facebook"
    quitting = True
    while True:
        a.fill((255, 255, 255))
        for e in pygame.event.get():
            if e.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
                quit()
                break
        mouse = pygame.mouse.get_pressed()
        mouse_pos = pygame.mouse.get_pos()
        a.blit(facebook, (20, 20))
        message_display_small(
            fb,
            45 + facebook.get_width() - 100 + 10,
            25 + facebook.get_height() + 10,
            black,
            a,
        )
        if (
            mouse[0] == 1
            and 20 < mouse_pos[0] < 20 + facebook.get_width()
            and 20 < mouse_pos[1] < 20 + facebook.get_height()
        ):
            pygame.quit()
            quitting = False
            fb_button(username, password)
        if quitting:
            pygame.display.update()


def login():
    login_window = Tk()
    input_entry = Entry(login_window, text="Username:")
    login = Label(login_window, text="Username:")
    pass1 = Label(login_window, text="Password:")
    pass_entry = Entry(login_window, text="Password:", show="*")
    lbl = Label(login_window, text="Please enter your username and password:")

    def check():
        testing = False
        password = pass_entry.get()
        username = input_entry.get()
        main_password = username + "" + password
        file_name = username + password
        try:
            pyAesCrypt.decryptFile(
                file_name + ".bin.aes",
                file_name + "decrypted" + ".bin",
                main_password,
                bufferSize,
            )
            f = open(file_name + "decrypted" + ".bin", "rb")
            logins = pickle.load(f)
            for a in logins:
                if a[1] == password:
                    root = Tk()
                    root.withdraw()
                    messagebox.showinfo("Success", "Success")
                    login_window.destroy()
                    root.destroy()
            testing = True
        except:
            testing = False
            root = Tk()
            root.withdraw()
            messagebox.showinfo("Error", "Wrong Password or Username")
            root.destroy()
        if testing:
            d = pygame.display.set_mode((800, 600))
            gameloop(d, file_name + "decrypted" + ".bin")

    but = Button(login_window, text="Login", command=check)
    login.grid(row=2, column=2)
    lbl.grid(row=0, column=2, columnspan=2)
    pass1.grid(row=6, column=2)
    input_entry.grid(row=2, column=3)
    pass_entry.grid(row=6, column=3)
    but.grid(row=8, column=3)
    root.destroy()
    login_window.resizable(False, False)


def register():
    login_window1 = Tk()
    root.destroy()

    input_entry1 = Entry(login_window1)
    login = Label(login_window1, text="Username:")
    pass1 = Label(login_window1, text="Password:")
    pass_entry1 = Entry(login_window1, show="*")

    lbl = Label(login_window1, text="Please enter your username and password:")
    text = "!!Do not forgot the password,it is impossible to recover it"
    a = []

    def inputing():
        password = pass_entry1.get()
        username = input_entry1.get()
        if os.path.exists(username + password + ".bin"):
            messagebox.showinfo("Error", "The account with the same username exist!!")
        else:
            f = open(username + password + ".bin", "wb")
            l = []
            l.append(username)
            l.append(password)
            a.append(l)
            pickle.dump(a, f)
            HSP = username + "" + password
            f.close()
            file_name = str(username) + str(password)
            pyAesCrypt.encryptFile(
                str(username) + str(password) + ".bin",
                file_name + ".bin.aes",
                HSP,
                bufferSize,
            )

    but = Button(login_window1, text="Register", command=inputing)

    lbl1 = Label(login_window1, text=text)

    login.grid(row=2, column=0)
    lbl.grid(row=0, column=1)
    pass1.grid(row=6, column=0)
    input_entry1.grid(row=2, column=1)
    pass_entry1.grid(row=6, column=1)
    lbl1.grid(row=7, column=1)
    but.grid(row=8, column=1)


main = Label(root, text="Welcome to ONE-PASS manager")
login_text = Label(root, text="Do you already have an account")
register_text = Label(root, text='If you don"t have an account please register')
reg_button = Button(root, text="Register", command=register)
login_button = Button(root, text="login", command=login)  # added login button

main.grid(row=0, column=1, columnspan=2)
login_button.grid(row=7, column=1, columnspan=2)
login_text.grid(row=6, column=1, columnspan=2)
register_text.grid(row=8, column=1, columnspan=2)
reg_button.grid(row=9, column=1, columnspan=2)
root.resizable(False, False)
root.mainloop()
