from tkinter import*
from tkinter import messagebox
from tkinter import ttk
from PIL import ImageTk, Image
import mysql.connector


#iconimage = ImageTk.PhotoImage(Image.open("icon.png"))

mydb = mysql.connector.connect(host='localhost', user='root', password='rohithk123')
cur=mydb.cursor()
cur.execute('create database if not exists project')

def Newregist():
    new_r = Toplevel()
    new_r.title('Registration Page')
    new_r.geometry('1057x700+0+0')
    new_r.config()
    image1 = ImageTk.PhotoImage(Image.open("background.jpg"))
    titleimage = ImageTk.PhotoImage(Image.open("heading.png"))
    back_button=ImageTk.PhotoImage(Image.open("back.png"))
    submit_button=ImageTk.PhotoImage(Image.open("submit.png"))
    image1_label = Label(new_r,image=image1)     
    #image1_label.image = image1
    image1_label.place(x=0, y=0)
    #new_label = Label(new_r, text='NEW REGISTRATION', fg='white', bg='black', bd=6, relief=RAISED, font=('ariel', 30))
    iconimage = ImageTk.PhotoImage(Image.open("icon.png"))
    welcome_label = Label(new_r, image=titleimage)
    welcome_label.place(x=320, y=10)

    labelframe1=LabelFrame(new_r,bg='black',width=500,height=550,borderwidth=2, relief="solid")
    labelframe1.place(x=270,y=100)
    icon_label=Label(labelframe1, image=iconimage).place(x=200,y=20)
    

    #------------------Labels---------------------------
    new_name = Label(labelframe1,  fg='white',text="Username", bd=5, bg='black', font=('ariel', 18))
    new_name.place(x=0, y=170-2)
    new_last = Label(labelframe1, fg='white', text="Password", bd=5, bg='black', font=('ariel', 18))
    new_last.place(x=0, y=220-2)
    new_age = Label(labelframe1, fg='white',text="Recovery Email", bg='black', bd=5, font=('ariel', 18))
    new_age.place(x=0, y=270-2)
    new_num = Label(labelframe1, fg='white', text="Recovery Password", bg='black', bd=5, font=('ariel', 18))
    new_num.place(x=0, y=320-2)


    # ------------------Entry---------------------------
    name_e = ttk.Entry(labelframe1, width=20,font=('calibre', 15, 'normal')) #, bd=6
    name_e.place(x=230, y=170)
    last_e = ttk.Entry(labelframe1, width=20,font=('calibre', 15, 'normal'))
    last_e.place(x=230, y=220)
    age_e = ttk.Entry(labelframe1, width=20,font=('calibre', 15, 'normal'))
    age_e.place(x=230, y=270)
    num_e = Entry(labelframe1, width=20,font=('calibre', 15, 'normal'))
    num_e.place(x=230, y=320)


    def insert():
        name = name_e.get()
        last = last_e.get()
        age = age_e.get()
        gender = v.get()
        phone = num_e.get()
        hours = time.get()
        minutex = minutes.get()
        amopm = ampm.get()
        timex = str(hours) + ':' + str(minutex) + str(amopm)
        mydb = mysql.connector.connect(host='localhost', user='root', password='anudeep',database='project')
        cur = mydb.cursor()
        #cur.execute('create database if not exists project')
        cur.execute(
            'create table if not exists hospital(name varchar(255), last varchar(255), age varchar(255), gender varchar(255), phone varchar(255), appt varchar(255))')
        cur.execute('insert into hospital(name, last, age, gender, phone, appt) values(%s, %s, %s, %s, %s, %s)',
                          (name, last, age, gender, phone, timex))

        mydb.commit()
        messagebox.showinfo(title='Registration Complete', message='Appointment Successfully Placed')
        new_r.destroy()

    #------------------Buttons------------------
    Button(labelframe1, bg='black', image=back_button,bd=0, command=new_r.destroy).place(x=100, y=470)
    Button(labelframe1, bg='black', image=submit_button,bd=0, command=insert).place(x=300, y=470)


    new_r.mainloop()

