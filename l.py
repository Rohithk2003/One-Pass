from tkinter import *
import os
def copy():
    root = Tk()
    root.clipboard_clear()
    root.clipboard_append('hi')
    os.system('echo {}| clip'.format('hi'))
