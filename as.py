from tkinter import *
from PIL import ImageTk,Image
root = Tk()
root.geometry(('800x600'))
file = 'D:/One-Pass/github.png'
image_add = ImageTk.PhotoImage(Image.open(file))
def change():
    pass
def addaccount(padx,pady):
    global add_button
    f = open('hi.txt','r')
    list_acc = f.readlines()
    if len(list_acc) != 0:
         add_button.place(x=padx+100*len(list_acc),y=pady)
padx=10
pady=100
add_button = Button(root,image = image_add,borderwidth='0')
add_button.grid(row=0,column=1,padx=10,pady=100)
root.mainloop()
