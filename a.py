'------------------------------------importing modules------------------------------------'
import math
import pickle
import random
import smtplib
from tkinter import *

import mysql.connector
import pyAesCrypt
import pygame
from simplecrypt import encrypt
import os
import time
'------------------------------------main tkinter window------------------------------------'

bufferSize = 64 * 1024
root = Tk()
pygame.init()  # main windows were the login screen and register screen goes
root.title("ONE-PASS")
root.configure(bg='black')
width_window = 300
height_window = 300
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = screen_width / 2 - width_window / 2
y = screen_height / 2 - height_window / 2
root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
# windows titLE

'''  '''
password = 0
username = 0
social_media = []
'------------------------------------loading images------------------------------------'
num_password_account = 5
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
'------------------------------------ mysql database ------------------------------------'
my_database = mysql.connector.connect(
    host='localhost', user='root', password='rohithk123')
my_cursor = my_database.cursor()
my_cursor.execute("set autocommit=1")
try:
    my_cursor.execute('create database USERS')
    my_cursor.execute('use USERS')
    my_cursor.execute(
        'create table data_input (username varchar(20),hash varchar(20)')
except:
    my_cursor.execute('use USERS')
    try:
        my_cursor.execute(
            'create table data_input (username varchar(20),email_id varchar(20)')
    except:
        pass

'------------------------------------Colors------------------------------------'
black = (0, 0, 0)
white = (255, 255, 255)
red = (255, 0, 0)
blue = (0, 0, 255)
green = (0, 255, 0)
catch_error = True

fb_user_text = ""
active_fb = False

font = pygame.font.Font("freesansbold.ttf", 30)


def forgot_password():
    mailid = sys.argv[0]
    digits = "0123456789"
    OTP = ""
    for i in range(6):
        OTP += digits[math.floor(random.random() * 10)]
    msg = 'Your OTP Verification for app is ' + OTP + \
          ' Note..  Please enter otp within 2 minutes and 3 attempts, otherwise it becomes invalid'
    file2 = open("otp.txt", "w")
    file2.write(OTP)
    file2.close()
    s = smtplib.SMTP('smtp.gmail.com', 587)
    s.starttls()
    s.login("rohithk652@gmail.com", "rohithk2003")
    print(msg)
    s.sendmail('rohithk652@gmail.com', 'vivekvalsan.12a1@gmail.com', msg)


def text_object(text, font, color):
    textsurf = font.render(text, True, color)
    return textsurf, textsurf.get_rect()


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


# def button(social_media_name,username,password):
#
def login():
    pass


def register():
    login_window1 = Tk()
    root.destroy()

    def register_saving():
        username_register = str(username_entry.get())
        password_register = str(password_entry.get())
        email_id_register = str(email_id_entry.get())
        email_password_register = str(email_password_entry.get())
        word = email_id_register.split()
        original = ''
        for p in word:
            for i in p:
                if i == '@':
                    break
                else:
                    original += i
        main1 = original + email_password_register
        cipher_text = encrypt(main1, password_register)
        d = str(cipher_text)
        cipher_text_deleted = d[1::]
        my_cursor.execute('insert into  data_input values (%d,%d)', (username_register, cipher_text_deleted))

    def hide_password(entry, row, column, row1, column1):
        text = entry.get()
        text_str = str(text)
        entry1 = Entry(login_window1, show='*')
        entry1.grid(row=row, column=column)
        entry1.delete(0, END)ud
        entry1.insert(text_str, END)
        show_both_11 = Button(login_window1, text='show password',
                              command=lambda: show_password(entry1, row, column, row1, column1))
        show_both_11.grid(row=row1, column=column1)

    def show_password(entry, row, column, row1, column1):
        entry.config(show='')
        show_both_11 = Button(login_window1, text='hide password',
                              command=lambda: hide_password(entry, row, column, row1, column1))
        show_both_11.grid(row=row1, column=column1)

    username = Label(login_window1, text='Username')
    password = Label(login_window1, text='password')
    email_id = Label(login_window1, text='Recovery Email :')
    email_password = Label(login_window1, text='Recovery Email password')
    username_entry = Entry(login_window1)
    password_entry = Entry(login_window1, show='*')
    email_id_entry = Entry(login_window1)
    email_password_entry = Entry(login_window1, show='*')
    width = login_window1.winfo_screenwidth()
    # register button
    register_button = Button(login_window1, text='Register', command=register_saving)
    # putting the buttons and entries
    username.grid(row=2, column=0)
    password.grid(row=3, column=0)
    email_id.grid(row=4, column=0)
    email_password.grid(row=5, column=0)
    username_entry.grid(row=2, column=1)
    password_entry.grid(row=3, column=1)
    email_id_entry.grid(row=4, column=1)
    email_password_entry.grid(row=5, column=1)
    show_both_1 = Button(login_window1, text='show password', command=lambda: show_password(password_entry, 3, 1, 3, 2))
    show_both_2 = Button(login_window1, text='show password',
                         command=lambda: show_password(email_password_entry, 5, 1, 5, 2))
    show_both_1.grid(row=3, column=2)
    show_both_2.grid(row=5, column=2)

    register_button.grid(row=6, column=0)


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
