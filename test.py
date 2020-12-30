from tkinter import *
from tkinter.ttk import *
from tkinter import messagebox
from PIL import ImageTk as tk_image
from PIL import Image as image
class SampleApp(Tk):
    def __init__(self):
        Tk.__init__(self)
        self.title("Password Manager")
        width_window = 1057
        height_window = 661

        self.config(bg="#292A2D")
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        self.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        



""" to remove all decrypted files
the glob function returns a list of files ending with decrypted.bin"""
list_file = glob.glob("*decrypted.bin")
for i in list_file:
    try:
        os.remove(str(i))
    except:
        pass
