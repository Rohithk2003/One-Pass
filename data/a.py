
import threading
from tkinter import *
from tkinter.font import BOLD

a = Tk()
running = True
a.config(bg='#121212')

al = False


def alpha():
    global running, al
    if str(enter_alpha['text']) == 'Enter Alphanumeric pin':
        running = False
        al = True
        enter_alpha.config(text="Enter Number pin")
        threading.Thread(target=for_alpha).start()
    elif enter_alpha['text'] == 'Enter Number pin':
        running = True
        al = False
        enter_alpha.config(text="Enter Alphanumeric pin")
        threading.Thread(target=getting).start()


def for_alpha():
    global al
    while al:

        try:
            if ent.get():
                if len(ent.get()) >= 4:
                    a = ent.get()[:4]
                    ent.delete(4, END)
        except:
            pass


def getting():
    global running
    while running:
        try:
            if ent.get():
                int(ent.get())
                if len(ent.get()) >= 4:
                    a = ent.get()[:4]
                    ent.delete(4, END)
        except ValueError:
            a = str(ent.get())
            d = list(map(str, a))
            f = 0
            for i in d:
                if i.isalpha():
                    f = d.index(i)
            ent.delete(f, END)


width_window = 1057
height_window = 661
a.focus_force()
screen_width = a.winfo_screenwidth()
screen_height = a.winfo_screenheight()
x = screen_width / 2 - width_window / 2
y = screen_height / 2 - height_window / 2
a.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
lab = Label(a, text='Add a security pin', bg='#121212',
            fg='white', font=("Segoe Ui", 15))
lab.place(x=width_window/2-60-5-10, y=100)
lab1 = Label(a, text='This 4 digit security pin is used for further security\nYou cannot recover it.',
             bg='#121212', fg='white', justify='center', font=("Segoe Ui", 15))
pintext = Label(a, text="PIN:", bg='#121212', fg='white',
                justify='center', font=("Segoe Ui", 15))
pintext.place(x=width_window/2-130-5-30-10, y=248)
lab1.place(x=width_window/2-190-5-10, y=150)

ent = Entry(a, width=20, font=("Segoe Ui", 15))
ent.place(x=width_window/2-40-5-5-30-10, y=250)
enter_alpha = Button(a, text='Enter Alphanumeric pin', fg="#2A7BCF",
                     activeforeground="#2A7BCF",
                     bg="#121212", command=alpha,
                     activebackground="#121212",  bd=0, borderwidth=0, font=("Consolas", 14, UNDERLINE))
enter_alpha.place(x=width_window/2+200-30-10, y=250)
# adding the check box button
check = Checkbutton(a, text="I understand that this security code cannot be recovered once it is lost", font=("Consolas", 14), bg='#121212', fg='white',
                    justify='center', activebackground="#121212", activeforeground='white', selectcolor='black')
check.place(x=200, y=300)

t1 = threading.Thread(target=getting)

# t1.start()
# adding the save button
save = Button(a, text="S A V E", fg="#292A2D",
              activeforeground="#292A2D",
              bg="#994422",
              activebackground="#994422", height=1, width=10, bd=0, borderwidth=0, font=("Consolas", 14))
save.place(x=width_window/2-30-5-10, y=350)
a.mainloop()
