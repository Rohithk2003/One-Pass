import tkinter as tk

root = tk.Tk()
e1 = tk.Entry(root)
e2 = tk.Entry(root)
e1.pack()
e2.pack()

def handleReturn(event):
    print("return: event.widget is",event.widget)
    print("focus is:",root.focus_get())

root.bind("<Return>", handleReturn)

root.mainloop()