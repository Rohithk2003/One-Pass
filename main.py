import os
import pickle
import sys
from tkinter import *
from tkinter import messagebox

import pyAesCrypt
import pygame

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

fb_user_text = ''
active_fb = False

font = pygame.font.Font('freesansbold.ttf', 30)


def text_object(text, font, color):
    textsurf = font.render(text, True, color)
    return textsurf, textsurf.get_rect()


# added message display function to blit text on to the window


def message_display_small(text, a, b, color, display):
    smalltext = pygame.font.Font('comic.ttf', 30)
    textsurf, textrect = text_object(text, smalltext, color)
    textrect.center = (int(a), int(b))
    display.blit(textsurf, textrect)


def fb_text(text, a, b, color, display):
    smalltext = pygame.font.Font('freesansbold.ttf', 30)
    textsurf, textrect = text_object(text, smalltext, color)
    textrect.center = (int(a), int(b))
    display.blit(textsurf, textrect)


def fb_button():

    root = Tk()


def gameloop(a, username, passwor, file):
    fb = 'Facebook'
    update = True
    while True:
        if update == True:
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
        message_display_small(fb, 45 + facebook.get_width() - 100 + 10,
                              25 + facebook.get_height() + 10, black, a)
        if mouse[0] == 1 and 20 < mouse_pos[0] < 20 + facebook.get_width() and 20 < mouse_pos[1] < 20 + facebook.get_height():
            fb_button()
            update = False
        if update == True:
            pygame.display.update()
        else:
            pass


def login():
    login_window = Tk()
    input_entry = Entry(login_window, text="Username:")
    login = Label(login_window, text="Username:")
    pass1 = Label(login_window, text="Password:")
    pass_entry = Entry(login_window, text="Password:", show="*")
    lbl = Label(login_window, text="Please enter your username and password:")

    def check():
        testing = True
        password = pass_entry.get()
        username = input_entry.get()
        main_password = username + "" + password
        file_name = username + password
        try:
            pyAesCrypt.decryptFile(
                file_name + '.bin.aes', file_name + 'decrypted' + '.bin', main_password, bufferSize)
            f = open(file_name + 'decrypted' + '.bin', 'rb')
            logins = pickle.load(f)
            for a in logins:
                if a[1] == password:
                    root = Tk()
                    root.withdraw()
                    messagebox.showinfo("Success", "Success")
                    login_window.destroy()
                    root.destroy()
            testing = False
        except:
            testing = True
            root = Tk()
            root.withdraw()
            messagebox.showinfo("Error", "Wrong Password or Username")
            root.destroy()
        if testing == False:
            d = pygame.display.set_mode((800, 600))
            gameloop(d, username, password, file_name + 'decrypted' + '.bin')

        else:
            pass
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
        f = open("user.bin", "ab")
        l = []
        password = pass_entry1.get()
        username = input_entry1.get()
        l.append(username)
        l.append(password)
        a.append(l)
        pickle.dump(a, f)
        HSP = username + "" + password
        f.close()
        file_name = username + password
        pyAesCrypt.encryptFile("user.bin", file_name +
                               '.bin.aes', HSP, bufferSize)
        os.remoce('user.bin')
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
register_text = Label(
    root, text='If you don"t have an account please register')
reg_button = Button(root, text="Register", command=register)
login_button = Button(root, text="login", command=login)  # added login button

main.grid(row=0, column=1, columnspan=2)
login_button.grid(row=7, column=1, columnspan=2)
login_text.grid(row=6, column=1, columnspan=2)
register_text.grid(row=8, column=1, columnspan=2)
reg_button.grid(row=9, column=1, columnspan=2)
root.resizable(False, False)
root.mainloop()
