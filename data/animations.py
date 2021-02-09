from tkinter import *
import threading
import time


def main(window, x, y):
    def getting():
        ad = True
        try:
            d = Label(window, text="Creating Account ",
                      font=("Segoe Ui", 20), fg='white', bg='#1E1E1E')
            d.place(x=x, y=y)
            while ad:

                time.sleep(1)
                d.config(text="Creating Account .")
                time.sleep(1)
                d.config(text="Creating Account ..")
                time.sleep(1)
                d.config(text="Creating Account ...")
                time.sleep(1)
                d.config(text="Creating Account ")
        except:
            pass

    threading.Thread(target=getting).start()
