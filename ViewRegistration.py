from tkinter import*
from tkinter import messagebox
from PIL import ImageTk, Image
from tkinter import ttk
import mysql.connector
mydb = mysql.connector.connect(host='localhost', user='root', password='rohithk123',database='project')
cur = mydb.cursor()


def Viewregist():
    view_r = Toplevel()
    view_r.title('Registration Page')
    view_r.geometry('1057x700+0+0')
    image1 = ImageTk.PhotoImage(Image.open("background.jpg"))
    image1_label = Label(view_r,image=image1)     
    image1_label.place(x=0, y=0)

    #---------------------Label Frame------------------------

    labelframe=LabelFrame(view_r,bg='white',width=500,height=550,borderwidth=2, relief="solid")
    labelframe.place(x=270,y=100)

    #
    titleimage = ImageTk.PhotoImage(Image.open("heading.png"))
    iconimage = ImageTk.PhotoImage(Image.open("icon.png"))
    back_button=ImageTk.PhotoImage(Image.open("back.png"))
    submit_button=ImageTk.PhotoImage(Image.open("submit.png"))
    icon_label=Label(labelframe, image=iconimage).place(x=200,y=20)
    welcome_label = Label(view_r, image=titleimage)
    welcome_label.place(x=320, y=10)



    # ------------------Labels---------------------------
    new_name = Label(labelframe, text="First Name", bd=5, bg='white', font=('ariel', 18))
    new_name.place(x=0, y=170)
    new_last = Label(labelframe, text="Last Name", bd=5, bg='white', font=('ariel', 18))
    new_last.place(x=0, y=220)
    # new_age = Label(view_r, text="Patient's Age", bg='white', bd=5, font=('ariel', 18))
    # new_age.place(x=550, y=250)

    # ------------------Entry---------------------------
    name_e = ttk.Entry(labelframe,width=20,font=('calibre', 15, 'normal'))
    name_e.place(x=230, y=170)
    last_e = ttk.Entry(labelframe,width=20,font=('calibre', 15, 'normal'))
    last_e.place(x=230, y=220)
    # num_e = Entry(view_r, width=40, bd=6)
    # num_e.place(x=750, y=250)

    def submit():
        view = Toplevel()
        view.title('Registration Page')
        view.geometry('1057x700+0+0')
        view.config(bg='sky blue')
        image1 = ImageTk.PhotoImage(Image.open("background.jpg"))
        image1_label = Label(view,image=image1)     
        image1_label.place(x=0, y=0)
        #new_label = Label(view, text='VIEW REGISTRATION', fg='white', bg='black', bd=6, relief=RAISED,font=('ariel', 30))
        #new_label.place(x=570, y=20)

        #------------------Image Label-----------------------
        labelframe=LabelFrame(view,bg='white',width=500,height=550,borderwidth=2, relief="solid")
        labelframe.place(x=270,y=100)

        #------------------
        titleimage = ImageTk.PhotoImage(Image.open("heading.png"))
        iconimage = ImageTk.PhotoImage(Image.open("icon.png"))
        icon_label=Label(labelframe, image=iconimage).place(x=200,y=20)
        back_button=ImageTk.PhotoImage(Image.open("back.png"))
        welcome_label = Label(view, image=titleimage)
        welcome_label.place(x=320, y=10)



        # ------------------Labels---------------------------
        new_name = Label(labelframe, text="First Name", bd=2, bg='white', font=('ariel', 18))
        new_name.place(x=0, y=170)
        new_last = Label(labelframe, text="Last Name", bd=2, bg='white', font=('ariel', 18))
        new_last.place(x=0, y=220)
        new_age = Label(labelframe, text="Age", bg='white',bd=2, font=('ariel', 18))
        new_age.place(x=0, y=270)
        new_gender = Label(labelframe, text="Gender", bg='white', bd=2, font=('ariel', 18))
        new_gender.place(x=0, y=320)
        new_num = Label(labelframe, text="Phone Number", bg='white', bd=2, font=('ariel', 18))
        new_num.place(x=0, y=370)
        new_app = Label(labelframe, text="Appointment Time", bg='white', bd=2, font=('ariel', 18))
        new_app.place(x=0, y=420)

        iname = name_e.get()
        ilast = last_e.get()
        # iage = num_e.get()

        mydb = mysql.connector.connect(host='localhost', user='root', password='anudeep',database='project')
        cur = mydb.cursor()
        cur.execute('create database if not exists project')
        #cur.execute('create table if not exists hospital(name varchar(255), last varchar(255), age varchar(255), gender varchar(255), phone varchar(255), appt varchar(255))')
        cur.execute("select name from hospital where name=%s and last=%s ",(iname, ilast))
        dname = cur.fetchone()
        cur.execute("select last from project.hospital where name=%s and last=%s ", (iname, ilast))
        dlast = cur.fetchone()
        cur.execute('select age from project.hospital where name=%s and last=%s ',(iname, ilast))
        dage = cur.fetchone()
        cur.execute('select gender from project.hospital where name=%s and last=%s',(iname, ilast))
        dgender = cur.fetchone()
        cur.execute('select phone from project.hospital where name=%s and last=%s ',(iname, ilast))
        dphone = cur.fetchone()
        cur.execute('select appt from project.hospital where name=%s and last=%s',(iname, ilast))
        dappt = cur.fetchone()

        # ------------------Labels---------------------------
        name = Label(labelframe, text=dname, bd=5, bg='white', font=('ariel', 15))
        name.place(x=230, y=170)
        last = Label(labelframe, text=dlast, bd=5, bg='white', font=('ariel', 15))
        last.place(x=230, y=220)
        age = Label(labelframe, text=dage, bd=5, bg='white', font=('ariel', 15))
        age.place(x=230, y=270)
        gender = Label(labelframe, text=dgender, bd=5, bg='white', font=('ariel', 15))
        gender.place(x=230, y=320)
        num = Label(labelframe, bd=5, text=dphone, bg='white', font=('ariel', 15))
        num.place(x=230, y=370)
        appt = Label(labelframe, bd=5, text=dappt, bg='white', font=('ariel', 15))
        appt.place(x=290, y=430)

        Button(labelframe,image=back_button,bd=0,bg='white', command=view.destroy).place(x=240, y=500)

        view.mainloop()

    # ------------------Button---------------------------
    Button(labelframe, bg='white', image=back_button,bd=0, command=view_r.destroy).place(x=100, y=470)
    Button(labelframe, bg='white', image=submit_button,bd=0,command=submit).place(x=300, y=470)
    view_r.mainloop()

