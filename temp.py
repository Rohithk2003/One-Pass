from tkinter import *
from threading import Thread
a = Tk()
ad = True
def d():
    global ad 
    i = 0
    while ad:
        Label(a,text=i).pack()
        i+=1
dddd = Button(a,text='d',command=lambda:Thread(target=d).start())
dddd.pack()
a.mainloop()