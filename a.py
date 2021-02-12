import mysql.connector as m
import glob
import json
import sys
import pickle as p
from mysql.connector.constants import CharacterSet
import pyperclip
from tkscrolledframe import ScrolledFrame
from tkinter import tix
import platform
from data.checkupdates import *
from data.secure import *
from data.forgot_password import *

# tkinter modules
from PIL import Image as image
from PIL import ImageTk as tk_image
from tkinter import filedialog as fd
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import ttk
from tkinter import *
from tkhtmlview import HTMLLabel
import time
import atexit

self = Tk()
r = HTMLLabel(self,html='r.pack()
self.mainloop()