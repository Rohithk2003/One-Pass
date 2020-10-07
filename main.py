from tkinter import *
import math
import pickle
import pyAesCrypt
import os
import threading
import mysql.connector
from tkinter import messagebox
import pygame
display_height = 800
display_width = 600
pygame.init()
bufferSize = 64 * 1024
root = Tk()  # main windows were the login screen and register screen goes
root.title('ONE-PASS')  # windows title
password = 0
username = 0


def login():
    login_window = Tk()
    input_entry = Entry(login_window, text='Username:')
    login = Label(login_window, text='Username:')
    pass1 = Label(login_window, text='Password:')
    pass_entry = Entry(login_window, text='Password:', show='*')
    lbl = Label(login_window, text='Please enter your username and password:')

    def check():
        password = pass_entry.get()
        username = input_entry.get()

        try:
            pyAesCrypt.decryptFile(
                'user.bin.aes', 'usero1.bin', password, bufferSize)

        except:
            root = Tk()
            root.withdraw()
            messagebox.showinfo('Error', 'Wrong Password or Username')
            root.destroy()
        f = open('usero1.bin', 'rb')
        line = pickle.load(f)
        print(line)
        for a in line:
            if a[1] == password:
                root = Tk()
                root.withdraw()
                messagebox.showinfo('Success','Success')
                pygame.display.set_mode((display_height,display_width))
                login_window.withdraw()
                root.destroy()
    but = Button(login_window, text='Login', command=check)
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
    login = Label(login_window1, text='Username:')
    pass1 = Label(login_window1, text='Password:')
    pass_entry1 = Entry(login_window1, show='*')

    lbl = Label(login_window1, text='Please enter your username and password:')
    text = '!!Do not forgot the password,it is impossible to recover it'
    a = []

    def inputing():
        f = open('user.bin', 'ab')
        l = []
        password = pass_entry1.get()
        username = input_entry1.get()
        l.append(username)
        l.append(password)
        a.append(l)
        pickle.dump(a, f)
        pyAesCrypt.encryptFile(
            'user.bin', 'user.bin.aes', password, bufferSize)
        f.close()

    but = Button(login_window1, text='Register', command=inputing)

    lbl1 = Label(login_window1, text=text)

    login.grid(row=2, column=0)

    lbl.grid(row=0, column=1)

    pass1.grid(row=6, column=0)

    input_entry1.grid(row=2, column=1)

    pass_entry1.grid(row=6, column=1)

    lbl1.grid(row=7, column=1)

    but.grid(row=8, column=1)


main = Label(root, text='Welcome to ONE-PASS manager')
login_text = Label(root, text='Do you already have an account')
register_text = Label(
    root, text='If you don"t have an account please register')
reg_button = Button(root, text='Register', command=register)
login_button = Button(root, text='login', command=login)  # added login button

main.grid(row=0, column=1, columnspan=2)
login_button.grid(row=7, column=1, columnspan=2)
login_text.grid(row=6, column=1, columnspan=2)
register_text.grid(row=8, column=1, columnspan=2)
reg_button.grid(row=9, column=1, columnspan=2)
root.resizable(False, False)
root.mainloop()
