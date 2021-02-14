from tkinter import *
from tkinter import ttk, messagebox
from random import *
from string import *


def password(*args):

    if length.get().isdigit() and int(length.get()) in range(4, 21):
        p = choice(ascii_uppercase)+choice(ascii_lowercase) + \
            choice(digits)+choice(punctuation)
        w = choice(ascii_uppercase)+choice(ascii_lowercase)+choice(digits)
        count = 4
        while count < int(length.get()):
            x = choice(ascii_uppercase+ascii_lowercase+digits+punctuation)
            y = choice(ascii_uppercase+ascii_lowercase+digits)
            p += x
            w += y
            count += 1
        if var.get():
            gen.set(p)
        else:
            gen.set(w)
    elif length.get().isdigit():
        messagebox.showwarning(
            message="Length should be in the range of 4 to 20")
    else:
        messagebox.showwarning(message="Invalid input")


obj = Tk()
obj.title("Password Generator")
obj.resizable(width=False, height=False)

frame = ttk.Frame(obj, relief="ridge", padding="11 20 20 11")
frame.grid()
frame.rowconfigure(0)
frame.columnconfigure(0)

length = StringVar()
gen = StringVar()
var = IntVar()

len_entry = ttk.Entry(frame, textvariable=length)
len_entry.config(font=("verdana", "12", "bold"),
                 foreground="blue")   # Change Fonts
len_entry.grid(row=1, column=2)

label = ttk.Label(frame, text="Enter Length ", relief="ridge")
label.config(font=("verdana", "11", "italic bold"),
             foreground="white", background="black")
label.grid(row=1, column=1)

label1 = ttk.Label(frame, textvariable=gen, wraplength="6.5c", relief="flat")
label1.config(font=("verdana", "12", "bold italic"),
              foreground="red", background="white")
label1.grid(row=3, column=2, sticky=W)

checkbutton = ttk.Checkbutton(frame, text="Special Characters", variable=var)
checkbutton.grid(row=2, column=1)

button = ttk.Button(frame, text="Generate", command=password, width=20)
button.grid(row=2, column=2, sticky="W")

button1 = ttk.Button(frame, text="Exit", width=10, command=obj.destroy)
button1.grid(row=2, column=2, sticky="E")


for child in frame.winfo_children():
    child.grid_configure(padx=5, pady=5)

len_entry.focus()
obj.bind("<Return>", password)
obj.mainloop()
