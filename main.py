'------------------------------------importing modules------------------------------------'
import os
import os.path
import pickle
from tkinter import *
from tkinter import messagebox
import pyAesCrypt
import pygame
from selenium import webdriver 
from time import sleep 
from webdriver_manager.chrome import ChromeDriverManager 
from selenium.webdriver.chrome.options import Options 
'------------------------------------main tkinter window------------------------------------'

bufferSize = 64 * 1024
root = Tk()
pygame.init()  # main windows were the login screen and register screen goes
root.title("ONE-PASS")
root.configure(bg='black')
width_window = 300
height_window = 300
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = screen_width / 2 - width_window / 2
y = screen_height / 2 - height_window / 2
root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
# windows titLE


password = 0
username = 0
social_media = []
'------------------------------------loading images------------------------------------'
num_password_account = 5
facebook = pygame.image.load("facebook.png")
instagram = pygame.image.load("instagram.png")
google = pygame.image.load("google.png")
github = pygame.image.load("github.png")

# getting the size of the facebook image
fb_size = facebook.get_rect()

# social_media.append(facebook)
# social_media.append(instagram)
# social_media.append(google)
# social_media.append(github)

'------------------------------------ Colors ------------------------------------'
black = (0, 0, 0)
white = (255, 255, 255)
red = (255, 0, 0)
blue = (0, 0, 255)
green = (0, 255, 0)
catch_error = True

fb_user_text = ""
active_fb = False

font = pygame.font.Font("freesansbold.ttf", 30)


def text_object(text, font, color):
    textsurf = font.render(text, True, color)
    return textsurf, textsurf.get_rect()


# added message display function to blit text on to the window


def message_display_small(text, a, b, color, display):
    smalltext = pygame.font.Font("comic.ttf", 30)
    textsurf, textrect = text_object(text, smalltext, color)
    textrect.center = (int(a), int(b))
    display.blit(textsurf, textrect)


def fb_text(text, a, b, color, display):
    smalltext = pygame.font.Font("freesansbold.ttf", 30)
    textsurf, textrect = text_object(text, smalltext, color)
    textrect.center = (int(a), int(b))
    display.blit(textsurf, textrect)


def fb_button(username, password):
    file_name = str(username) + '_facebook' + ".bin.fenc"
    if os.path.exists(file_name):
        root = Tk()
        width_window = 300
        height_window = 300
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        pyAesCrypt.decryptFile(file_name, str(username) + '_facebook' + 'decrypted' + '.bin', password, bufferSize)
        f1 = open(str(username) + '_facebook' + 'decrypted' + '.bin', "rb")
        line = pickle.load(f1)
        root.title("Facebook Account")
        first = line[0]
        second = line[1]
        text12 = 'Facebook Username:'
        text22 = 'Facebook Password:'
        a1_text = Label(root, text=first)
        a2_text = Label(root, text=second)
        a1_text.grid(row=0, column=1)
        a2_text.grid(row=1, column=1)
        fwq = Label(root, text=text12)
        f12 = Label(root, text=text22)
        fwq.grid(row=0, column=0)
        f12.grid(row=1, column=0)
        def _delete_window():
            try:
                root.destroy()
            except:
                pass
        def back1():
            pygame.init()
            root.destroy()
            d = pygame.display.set_mode((800,600))
            gameloop(d, str(username),password)
        def _destroy(event):
            f1.close()
            if os.path.exists(str(username) + '_facebook' + 'decrypted' + '.bin'):  
                os.remove(str(username) + '_facebook' + 'decrypted' + '.bin')
            else:
                pass
        def remote():


            usr='rohithkrishnan2003@gmail.com'
            pwd='Batman@1234'

            driver = webdriver.Chrome(ChromeDriverManager().install()) 
            driver.get('https://www.facebook.com/') 
            print ("Opened facebook") 
            sleep(1) 

            username_box = driver.find_element_by_id('email') 
            username_box.send_keys(usr) 
            print ("Email Id entered") 
            sleep(1) 

            password_box = driver.find_element_by_id('pass') 
            password_box.send_keys(pwd) 
            print ("Password entered") 

            login_box = driver.find_element_by_id('u_0_b') 
            login_box.click() 

            print ("Done") 
            input('Press anything to quit') 
            driver.quit() 

        root.protocol("WM_DELETE_WINDOW", _delete_window)
        root.bind("<Destroy>", _destroy)

        back = Button(root,text='Go back!',command=back1,width=10)
        back.grid(row=3,column=0,columnspan=2)
        remote_login = Button(root,text='Facebook',command=remote,width=10)
        remote_login.grid(row=4,column=0,columnspan=2)

    else:
        second = Tk()
        width_window = 300
        height_window = 300
        screen_width = second.winfo_screenwidth()
        screen_height = second.winfo_screenheight()
        second.title("Facebook Login")
        username1 = Label(second, text="Facebook_Username:")
        password1 = Label(second, text="Facebook_Password:")
        username1_entry = Entry(second)
        password1_entry = Entry(second, show="*")
        login_text1 = "Please provide Facebook account and password"
        login_text = Label(second, text=login_text1)
        username1.grid(row=2, column=0)
        password1.grid(row=3, column=0)
        username1_entry.grid(row=2, column=1)
        password1_entry.grid(row=3, column=1, columnspan=2)
        username_list = []

        def save():
            c = username1_entry.get()
            print(username)
            fb_username = str(username)
            fb_password = password1_entry.get()
            a = fb_username + '_facebook'
            b = str(fb_password)
            fb_account_cipher = password
            username_list.append(str(c))
            username_list.append(b)
            f = open(a + ".bin", "wb")
            pickle.dump(username_list, f)
            f.close()
            print(a)
            pyAesCrypt.encryptFile(a + '.bin', a  + '.bin.fenc', fb_account_cipher, bufferSize)
            os.remove(a + '.bin')

        saving = Button(second, text="Save", command=save)
        saving.grid(row=4, column=1)


def insta_button(username, password):
    file_name = str(username) + '_facebook' + ".bin"
    if os.path.exists(file_name):
        root = Tk()
        root.configure(bg='black')
        width_window = 300
        height_window = 300
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        width_window = 300
        height_window = 300
        f1 = open(file_name, "rb")
        line = pickle.load(f1)
        root.title("Facebook Account")
        first = line[0]
        second = line[1]
        text12 = 'Facebook Username:'
        text22 = 'Facebook Password:'
        a1_text = Label(root, text=first)
        a2_text = Label(root, text=second)
        a1_text.grid(row=0, column=1)
        a2_text.grid(row=1, column=1)
        fwq = Label(root, text=text12)
        f12 = Label(root, text=text22)
        fwq.grid(row=0, column=0)
        f12.grid(row=1, column=0)

        def redirect():

            # Step 1) Open Firefox
            browser = webdriver.Chrome()
            # Step 2) Navigate to Facebook
            browser.get("http://www.facebook.com")
            # Step 3) Search & Enter the Email or Phone field & Enter Password
            username = browser.find_element_by_id("email")
            password = browser.find_element_by_id("pass")
            submit = browser.find_element_by_id("loginbutton")
            username.send_keys("you@email.com")
            password.send_keys("yourpassword")
            # Step 4) Click Login
            submit.click()

        redirect_message = 'Facebook login'
        redirect_button = Button(root, text=redirect_message, command=redirect)
        redirect_button.grid(row=3, column=0, columnspan=2)
    else:
        second = Tk()
        width_window = 300
        height_window = 300
        screen_width = second.winfo_screenwidth()
        screen_height = second.winfo_screenheight()
        second.title("Facebook Login")
        username1 = Label(second, text="Facebook_Username:")
        password1 = Label(second, text="Facebook_Password:")
        username1_entry = Entry(second)
        password1_entry = Entry(second, show="*")
        login_text1 = "Please provide Facebook account and password"
        login_text = Label(second, text=login_text1)
        username1.grid(row=2, column=0)
        password1.grid(row=3, column=0)
        username1_entry.grid(row=2, column=1)
        password1_entry.grid(row=3, column=1, columnspan=2)
        username_list = []

        def save():
            c = username1_entry.get()
            fb_username = str(username)
            fb_password = password1_entry.get()
            a = fb_username + '_facebook'
            b = str(fb_password)
            fb_account_cipher = password
            username_list.append(str(c))
            username_list.append(b)
            f = open(a + ".bin", "wb")
            pickle.dump(username_list, f)
            f.close()
            login()

        saving = Button(second, text="Save", command=save)
        saving.grid(row=4, column=1)
        redirect_button.grid(row=5, column=4)


def github_button(username, password):
    file_name = str(username) + '_facebook' + ".bin"
    if os.path.exists(file_name):
        root = Tk()
        root.configure(bg='black')
        width_window = 300
        height_window = 300
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        width_window = 300
        height_window = 300
        f1 = open(file_name, "rb")
        line = pickle.load(f1)
        root.title("Facebook Account")
        first = line[0]
        second = line[1]
        text12 = 'Facebook Username:'
        text22 = 'Facebook Password:'
        a1_text = Label(root, text=first)
        a2_text = Label(root, text=second)
        a1_text.grid(row=0, column=1)
        a2_text.grid(row=1, column=1)
        fwq = Label(root, text=text12)
        f12 = Label(root, text=text22)
        fwq.grid(row=0, column=0)
        f12.grid(row=1, column=0)

        def redirect():

            # Step 1) Open Firefox
            browser = webdriver.Chrome()
            # Step 2) Navigate to Facebook
            browser.get("http://www.facebook.com")
            # Step 3) Search & Enter the Email or Phone field & Enter Password
            username = browser.find_element_by_id("email")
            password = browser.find_element_by_id("pass")
            submit = browser.find_element_by_id("loginbutton")
            username.send_keys("you@email.com")
            password.send_keys("yourpassword")
            # Step 4) Click Login
            submit.click()

        redirect_message = 'Facebook login'
        redirect_button = Button(root, text=redirect_message, command=redirect)
        redirect_button.grid(row=3, column=0, columnspan=2)
    else:
        second = Tk()
        width_window = 300
        height_window = 300
        screen_width = second.winfo_screenwidth()
        screen_height = second.winfo_screenheight()
        second.title("Facebook Login")
        username1 = Label(second, text="Facebook_Username:")
        password1 = Label(second, text="Facebook_Password:")
        username1_entry = Entry(second)
        password1_entry = Entry(second, show="*")
        login_text1 = "Please provide Facebook account and password"
        login_text = Label(second, text=login_text1)
        username1.grid(row=2, column=0)
        password1.grid(row=3, column=0)
        username1_entry.grid(row=2, column=1)
        password1_entry.grid(row=3, column=1, columnspan=2)
        username_list = []

        def save():
            c = username1_entry.get()
            fb_username = str(username)
            fb_password = password1_entry.get()
            a = fb_username + '_facebook'
            b = str(fb_password)
            fb_account_cipher = password
            username_list.append(str(c))
            username_list.append(b)
            f = open(a + ".bin", "wb")
            pickle.dump(username_list, f)
            f.close()
            login()

        saving = Button(second, text="Save", command=save)
        saving.grid(row=4, column=1)
        redirect_button.grid(row=5, column=4)


def Google_button(username, password):
    file_name = str(username) + '_facebook' + ".bin"
    if os.path.exists(file_name):
        root = Tk()
        root.configure(bg='black')
        width_window = 300
        height_window = 300
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        width_window = 300
        height_window = 300
        f1 = open(file_name, "rb")
        line = pickle.load(f1)
        root.title("Facebook Account")
        first = line[0]
        second = line[1]
        text12 = 'Facebook Username:'
        text22 = 'Facebook Password:'
        a1_text = Label(root, text=first)
        a2_text = Label(root, text=second)
        a1_text.grid(row=0, column=1)
        a2_text.grid(row=1, column=1)
        fwq = Label(root, text=text12)
        f12 = Label(root, text=text22)
        fwq.grid(row=0, column=0)
        f12.grid(row=1, column=0)

        def redirect():

            # Step 1) Open Firefox
            browser = webdriver.Chrome()
            # Step 2) Navigate to Facebook
            browser.get("http://www.facebook.com")
            # Step 3) Search & Enter the Email or Phone field & Enter Password
            username = browser.find_element_by_id("email")
            password = browser.find_element_by_id("pass")
            submit = browser.find_element_by_id("loginbutton")
            username.send_keys("you@email.com")
            password.send_keys("yourpassword")
            # Step 4) Click Login
            submit.click()

        redirect_message = 'Facebook login'
        redirect_button = Button(root, text=redirect_message, command=redirect)
        redirect_button.grid(row=3, column=0, columnspan=2)
    else:
        second = Tk()
        width_window = 300
        height_window = 300
        screen_width = second.winfo_screenwidth()
        screen_height = second.winfo_screenheight()
        second.title("Facebook Login")
        username1 = Label(second, text="Facebook_Username:")
        password1 = Label(second, text="Facebook_Password:")
        username1_entry = Entry(second)
        password1_entry = Entry(second, show="*")
        login_text1 = "Please provide Facebook account and password"
        login_text = Label(second, text=login_text1)
        username1.grid(row=2, column=0)
        password1.grid(row=3, column=0)
        username1_entry.grid(row=2, column=1)
        password1_entry.grid(row=3, column=1, columnspan=2)
        username_list = []

        def save():
            c = username1_entry.get()
            fb_username = str(username)
            fb_password = password1_entry.get()
            a = fb_username + '_facebook'
            b = str(fb_password)
            fb_account_cipher = password
            username_list.append(str(c))
            username_list.append(b)
            f = open(a + ".bin", "wb")
            pickle.dump(username_list, f)
            f.close()
            login()

        saving = Button(second, text="Save", command=save)
        saving.grid(row=4, column=1)
        redirect_button.grid(row=5, column=4)


def Stackoverflow_button(username, password):
    file_name = str(username) + '_facebook' + ".bin"
    if os.path.exists(file_name):
        root = Tk()
        root.configure(bg='black')
        width_window = 300
        height_window = 300
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        width_window = 300
        height_window = 300
        f1 = open(file_name, "rb")
        line = pickle.load(f1)
        root.title("Facebook Account")
        first = line[0]
        second = line[1]
        text12 = 'Facebook Username:'
        text22 = 'Facebook Password:'
        a1_text = Label(root, text=first)
        a2_text = Label(root, text=second)
        a1_text.grid(row=0, column=1)
        a2_text.grid(row=1, column=1)
        fwq = Label(root, text=text12)
        f12 = Label(root, text=text22)
        fwq.grid(row=0, column=0)
        f12.grid(row=1, column=0)

        def redirect():

            # Step 1) Open Firefox
            browser = webdriver.Chrome()
            # Step 2) Navigate to Facebook
            browser.get("http://www.facebook.com")
            # Step 3) Search & Enter the Email or Phone field & Enter Password
            username = browser.find_element_by_id("email")
            password = browser.find_element_by_id("pass")
            submit = browser.find_element_by_id("loginbutton")
            username.send_keys("you@email.com")
            password.send_keys("yourpassword")
            # Step 4) Click Login
            submit.click()

        redirect_message = 'Facebook login'
        redirect_button = Button(root, text=redirect_message, command=redirect)
        redirect_button.grid(row=3, column=0, columnspan=2)
    else:
        second = Tk()
        width_window = 300
        height_window = 300
        screen_width = second.winfo_screenwidth()
        screen_height = second.winfo_screenheight()
        second.title("Facebook Login")
        username1 = Label(second, text="Facebook_Username:")
        password1 = Label(second, text="Facebook_Password:")
        username1_entry = Entry(second)
        password1_entry = Entry(second, show="*")
        login_text1 = "Please provide Facebook account and password"
        login_text = Label(second, text=login_text1)
        username1.grid(row=2, column=0)
        password1.grid(row=3, column=0)
        username1_entry.grid(row=2, column=1)
        password1_entry.grid(row=3, column=1, columnspan=2)
        username_list = []

        def save():
            c = username1_entry.get()
            fb_username = str(username)
            fb_password = password1_entry.get()
            a = fb_username + '_facebook'
            b = str(fb_password)
            fb_account_cipher = password
            username_list.append(str(c))
            username_list.append(b)
            f = open(a + ".bin", "wb")
            pickle.dump(username_list, f)
            f.close()
            login()

        saving = Button(second, text="Save", command=save)
        saving.grid(row=4, column=1)
        redirect_button.grid(row=5, column=4)


def Steam_button(username, password):
    file_name = str(username) + '_facebook' + ".bin"
    if os.path.exists(file_name):
        root = Tk()
        root.configure(bg='black')
        width_window = 300
        height_window = 300
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        width_window = 300
        height_window = 300
        f1 = open(file_name, "rb")
        line = pickle.load(f1)
        root.title("Facebook Account")
        first = line[0]
        second = line[1]
        text12 = 'Facebook Username:'
        text22 = 'Facebook Password:'
        a1_text = Label(root, text=first)
        a2_text = Label(root, text=second)
        a1_text.grid(row=0, column=1)
        a2_text.grid(row=1, column=1)
        fwq = Label(root, text=text12)
        f12 = Label(root, text=text22)
        fwq.grid(row=0, column=0)
        f12.grid(row=1, column=0)

        def redirect():

            # Step 1) Open Firefox
            browser = webdriver.Chrome()
            # Step 2) Navigate to Facebook
            browser.get("http://www.facebook.com")
            # Step 3) Search & Enter the Email or Phone field & Enter Password
            username = browser.find_element_by_id("email")
            password = browser.find_element_by_id("pass")
            submit = browser.find_element_by_id("loginbutton")
            username.send_keys("you@email.com")
            password.send_keys("yourpassword")
            # Step 4) Click Login
            submit.click()

        redirect_message = 'Facebook login'
        redirect_button = Button(root, text=redirect_message, command=redirect)
        redirect_button.grid(row=3, column=0, columnspan=2)
    else:
        second = Tk()
        width_window = 300
        height_window = 300
        screen_width = second.winfo_screenwidth()
        screen_height = second.winfo_screenheight()
        second.title("Facebook Login")
        username1 = Label(second, text="Facebook_Username:")
        password1 = Label(second, text="Facebook_Password:")
        username1_entry = Entry(second)
        password1_entry = Entry(second, show="*")
        login_text1 = "Please provide Facebook account and password"
        login_text = Label(second, text=login_text1)
        username1.grid(row=2, column=0)
        password1.grid(row=3, column=0)
        username1_entry.grid(row=2, column=1)
        password1_entry.grid(row=3, column=1, columnspan=2)
        username_list = []

        def save():
            c = username1_entry.get()
            fb_username = str(username)
            fb_password = password1_entry.get()
            a = fb_username + '_facebook'
            b = str(fb_password)
            fb_account_cipher = password
            username_list.append(str(c))
            username_list.append(b)
            f = open(a + ".bin", "wb")
            pickle.dump(username_list, f)
            f.close()
            login()

        saving = Button(second, text="Save", command=save)
        saving.grid(row=4, column=1)
        redirect_button.grid(row=5, column=4)


def Mega_button(username, password):
    file_name = str(username) + '_facebook' + ".bin"
    if os.path.exists(file_name):
        root = Tk()
        root.configure(bg='black')
        width_window = 300
        height_window = 300
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        width_window = 300
        height_window = 300
        f1 = open(file_name, "rb")
        line = pickle.load(f1)
        root.title("Facebook Account")
        first = line[0]
        second = line[1]
        text12 = 'Facebook Username:'
        text22 = 'Facebook Password:'
        a1_text = Label(root, text=first)
        a2_text = Label(root, text=second)
        a1_text.grid(row=0, column=1)
        a2_text.grid(row=1, column=1)
        fwq = Label(root, text=text12)
        f12 = Label(root, text=text22)
        fwq.grid(row=0, column=0)
        f12.grid(row=1, column=0)

        def redirect():

            # Step 1) Open Firefox
            browser = webdriver.Chrome()
            # Step 2) Navigate to Facebook
            browser.get("http://www.facebook.com")
            # Step 3) Search & Enter the Email or Phone field & Enter Password
            username = browser.find_element_by_id("email")
            password = browser.find_element_by_id("pass")
            submit = browser.find_element_by_id("loginbutton")
            username.send_keys("you@email.com")
            password.send_keys("yourpassword")
            # Step 4) Click Login
            submit.click()

        redirect_message = 'Facebook login'
        redirect_button = Button(root, text=redirect_message, command=redirect)
        redirect_button.grid(row=3, column=0, columnspan=2)
    else:
        second = Tk()
        width_window = 300
        height_window = 300
        screen_width = second.winfo_screenwidth()
        screen_height = second.winfo_screenheight()
        second.title("Facebook Login")
        username1 = Label(second, text="Facebook_Username:")
        password1 = Label(second, text="Facebook_Password:")
        username1_entry = Entry(second)
        password1_entry = Entry(second, show="*")
        login_text1 = "Please provide Facebook account and password"
        login_text = Label(second, text=login_text1)
        username1.grid(row=2, column=0)
        password1.grid(row=3, column=0)
        username1_entry.grid(row=2, column=1)
        password1_entry.grid(row=3, column=1, columnspan=2)
        username_list = []

        def save():
            c = username1_entry.get()
            fb_username = str(username)
            fb_password = password1_entry.get()
            a = fb_username + '_facebook'
            b = str(fb_password)
            fb_account_cipher = password
            username_list.append(str(c))
            username_list.append(b)
            f = open(a + ".bin", "wb")
            pickle.dump(username_list, f)
            f.close()
            login()

        saving = Button(second, text="Save", command=save)
        saving.grid(row=4, column=1)
        redirect_button.grid(row=5, column=4)


def OneDrive_button(username, password):
    file_name = str(username) + '_facebook' + ".bin"
    if os.path.exists(file_name):
        root = Tk()
        root.configure(bg='black')
        width_window = 300
        height_window = 300
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        width_window = 300
        height_window = 300
        f1 = open(file_name, "rb")
        line = pickle.load(f1)
        root.title("Facebook Account")
        first = line[0]
        second = line[1]
        text12 = 'Facebook Username:'
        text22 = 'Facebook Password:'
        a1_text = Label(root, text=first)
        a2_text = Label(root, text=second)
        a1_text.grid(row=0, column=1)
        a2_text.grid(row=1, column=1)
        fwq = Label(root, text=text12)
        f12 = Label(root, text=text22)
        fwq.grid(row=0, column=0)
        f12.grid(row=1, column=0)

        def redirect():

            # Step 1) Open Firefox
            browser = webdriver.Chrome()
            # Step 2) Navigate to Facebook
            browser.get("http://www.facebook.com")
            # Step 3) Search & Enter the Email or Phone field & Enter Password
            username = browser.find_element_by_id("email")
            password = browser.find_element_by_id("pass")
            submit = browser.find_element_by_id("loginbutton")
            username.send_keys("you@email.com")
            password.send_keys("yourpassword")
            # Step 4) Click Login
            submit.click()

        redirect_message = 'Facebook login'
        redirect_button = Button(root, text=redirect_message, command=redirect)
        redirect_button.grid(row=3, column=0, columnspan=2)
    else:
        second = Tk()
        width_window = 300
        height_window = 300
        screen_width = second.winfo_screenwidth()
        screen_height = second.winfo_screenheight()
        second.title("Facebook Login")
        username1 = Label(second, text="Facebook_Username:")
        password1 = Label(second, text="Facebook_Password:")
        username1_entry = Entry(second)
        password1_entry = Entry(second, show="*")
        login_text1 = "Please provide Facebook account and password"
        login_text = Label(second, text=login_text1)
        username1.grid(row=2, column=0)
        password1.grid(row=3, column=0)
        username1_entry.grid(row=2, column=1)
        password1_entry.grid(row=3, column=1, columnspan=2)
        username_list = []

        def save():
            c = username1_entry.get()
            fb_username = str(username)
            fb_password = password1_entry.get()
            a = fb_username + '_facebook'
            b = str(fb_password)
            fb_account_cipher = password
            username_list.append(str(c))
            username_list.append(b)
            f = open(a + ".bin", "wb")
            pickle.dump(username_list, f)
            f.close()
            login()

        saving = Button(second, text="Save", command=save)
        saving.grid(row=4, column=1)
        redirect_button.grid(row=5, column=4)


def Amazon_button(username, password):
    file_name = str(username) + '_facebook' + ".bin"
    if os.path.exists(file_name):
        root = Tk()
        root.configure(bg='black')
        width_window = 300
        height_window = 300
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        width_window = 300
        height_window = 300
        f1 = open(file_name, "rb")
        line = pickle.load(f1)
        root.title("Facebook Account")
        first = line[0]
        second = line[1]
        text12 = 'Facebook Username:'
        text22 = 'Facebook Password:'
        a1_text = Label(root, text=first)
        a2_text = Label(root, text=second)
        a1_text.grid(row=0, column=1)
        a2_text.grid(row=1, column=1)
        fwq = Label(root, text=text12)
        f12 = Label(root, text=text22)
        fwq.grid(row=0, column=0)
        f12.grid(row=1, column=0)

        def redirect():

            # Step 1) Open Firefox
            browser = webdriver.Chrome()
            # Step 2) Navigate to Facebook
            browser.get("http://www.facebook.com")
            # Step 3) Search & Enter the Email or Phone field & Enter Password
            username = browser.find_element_by_id("email")
            password = browser.find_element_by_id("pass")
            submit = browser.find_element_by_id("loginbutton")
            username.send_keys("you@email.com")
            password.send_keys("yourpassword")
            # Step 4) Click Login
            submit.click()

        redirect_message = 'Facebook login'
        redirect_button = Button(root, text=redirect_message, command=redirect)
        redirect_button.grid(row=3, column=0, columnspan=2)
    else:
        second = Tk()
        width_window = 300
        height_window = 300
        screen_width = second.winfo_screenwidth()
        screen_height = second.winfo_screenheight()
        second.title("Facebook Login")
        username1 = Label(second, text="Facebook_Username:")
        password1 = Label(second, text="Facebook_Password:")
        username1_entry = Entry(second)
        password1_entry = Entry(second, show="*")
        login_text1 = "Please provide Facebook account and password"
        login_text = Label(second, text=login_text1)
        username1.grid(row=2, column=0)
        password1.grid(row=3, column=0)
        username1_entry.grid(row=2, column=1)
        password1_entry.grid(row=3, column=1, columnspan=2)
        username_list = []

        def save():
            c = username1_entry.get()
            fb_username = str(username)
            fb_password = password1_entry.get()
            a = fb_username + '_facebook'
            b = str(fb_password)
            fb_account_cipher = password
            username_list.append(str(c))
            username_list.append(b)
            f = open(a + ".bin", "wb")
            pickle.dump(username_list, f)
            f.close()

        saving = Button(second, text="Save", command=save)
        saving.grid(row=4, column=1)
        redirect_button.grid(row=5, column=4)


def Flipkart_button(username, password):
    file_name = str(username) + '_facebook' + ".bin"
    if os.path.exists(file_name):
        root = Tk()
        root.configure(bg='black')
        width_window = 300
        height_window = 300
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = screen_width / 2 - width_window / 2
        y = screen_height / 2 - height_window / 2
        root.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
        width_window = 300
        height_window = 300
        f1 = open(file_name, "rb")
        line = pickle.load(f1)
        root.title("Facebook Account")
        first = line[0]
        second = line[1]
        text12 = 'Facebook Username:'
        text22 = 'Facebook Password:'
        a1_text = Label(root, text=first)
        a2_text = Label(root, text=second)
        a1_text.grid(row=0, column=1)
        a2_text.grid(row=1, column=1)
        fwq = Label(root, text=text12)
        f12 = Label(root, text=text22)
        fwq.grid(row=0, column=0)
        f12.grid(row=1, column=0)

        def redirect():

            # Step 1) Open Chrome
            browser = webdriver.Chrome()
            # Step 2) Navigate to Facebook
            browser.get("http://www.facebook.com")
            # Step 3) Search & Enter the Email or Phone field & Enter Password
            username = browser.find_element_by_id("email")
            password = browser.find_element_by_id("pass")
            submit = browser.find_element_by_id("loginbutton")
            username.send_keys("you@email.com")
            password.send_keys("yourpassword")
            # Step 4) Click Login
            submit.click()

        redirect_message = 'Facebook login'
        redirect_button = Button(root, text=redirect_message, command=redirect)
        redirect_button.grid(row=3, column=0, columnspan=2)
    else:
        second = Tk()
        width_window = 300
        height_window = 300
        screen_width = second.winfo_screenwidth()
        screen_height = second.winfo_screenheight()
        second.title("Facebook Login")
        username1 = Label(second, text="Facebook_Username:")
        password1 = Label(second, text="Facebook_Password:")
        username1_entry = Entry(second)
        password1_entry = Entry(second, show="*")
        login_text1 = "Please provide Facebook account and password"
        login_text = Label(second, text=login_text1)
        username1.grid(row=2, column=0)
        password1.grid(row=3, column=0)
        username1_entry.grid(row=2, column=1)
        password1_entry.grid(row=3, column=1, columnspan=2)
        username_list = []

        def save():
            c = username1_entry.get()
            fb_username = str(username)
            fb_password = password1_entry.get()
            a = fb_username + '_facebook'
            b = str(fb_password)
            fb_account_cipher = password
            username_list.append(str(c))
            username_list.append(b)
            f = open(a + ".bin", "wb")
            pickle.dump(username_list, f)
            f.close()

        saving = Button(second, text="Save", command=save)
        saving.grid(row=4, column=1)
        redirect_button.grid(row=5, column=4)


def gameloop(a, username,password):
    fb = "Facebook"
    quitting = True
    while quitting:
        a.fill((255, 255, 255))
        for e in pygame.event.get():
            if e.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
                quit()
                break
        mouse = pygame.mouse.get_pressed()
        mouse_pos = pygame.mouse.get_pos()
        a.blit(facebook, (20, 20))
        message_display_small(
            fb,
            45 + facebook.get_width() - 100 + 10,
            25 + facebook.get_height() + 10,
            black,
            a,
        )
        if (
                mouse[0] == 1
                and 20 < mouse_pos[0] < 20 + facebook.get_width()
                and 20 < mouse_pos[1] < 20 + facebook.get_height()
        ):
            quitting = False
            pygame.quit()
            fb_button(username, password)
            break
        pygame.display.update()


def login():
    login_window = Tk()
    width_window = 300
    height_window = 300
    screen_width = login_window.winfo_screenwidth()
    screen_height = login_window.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2
    login_window.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
    login_window.configure(bg='black')
    input_entry = Entry(login_window, text="Username:")
    login = Label(login_window, text="Username:")
    pass1 = Label(login_window, text="Password:")
    pass_entry = Entry(login_window, text="Password:", show="*")
    lbl = Label(login_window, text="Please enter your username and password:")

    def login_checking():
        testing = False
        password = pass_entry.get()
        username = input_entry.get()
        main_password = username + "" + password
        file_name = str(username)
        try:
            pyAesCrypt.decryptFile(
                file_name + ".bin.fenc",
                file_name + "decrypted" + ".bin",
                main_password,
                bufferSize,
            )
            f = open(file_name + "decrypted" + ".bin", "rb")
            logins = pickle.load(f)
            for a in logins:
                if a[1] == password:
                    root = Tk()
                    root.withdraw()
                    messagebox.showinfo("Success", "Success")
                    login_window.destroy()
                    root.destroy()
                    testing = True
        except:
            testing = False
            root = Tk()
            root.withdraw()
            messagebox.showinfo("Error", "Wrong Password or Username")
            root.destroy()
        if testing:
            d = pygame.display.set_mode((800, 600))
            gameloop(d,file_name, main_password)

    but = Button(login_window, text="Login", command=login_checking)
    login.grid(row=2, column=2)
    lbl.grid(row=0, column=2, columnspan=2)
    pass1.grid(row=6, column=2)
    input_entry.grid(row=2, column=3)
    pass_entry.grid(row=6, column=3)
    but.grid(row=8, column=3)
    root.destroy()
    login_window.resizable(False, False)


def register():
    login_window1 = Tk()
    screen_width = login_window1.winfo_screenwidth()
    screen_height = login_window1.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2
    login_window1.geometry("%dx%d+%d+%d" % (width_window, height_window, x, y))
    root.destroy()
    login_window1.configure(bg='black')
    input_entry1 = Entry(login_window1)
    login = Label(login_window1, text="Username:")
    pass1 = Label(login_window1, text="Password:")
    pass_entry1 = Entry(login_window1, show="*")

    lbl = Label(login_window1, text="Please enter your username and password:")
    text = "!!Do not forgot the password,it is impossible to recover it"
    a = []
    fb = True

    def inputing():
        password = pass_entry1.get()
        username = input_entry1.get()
        if os.path.exists(username + ".bin"):
            roo1 = Tk()
            roo1.withdraw()
            messagebox.showinfo("Error", "The account with the same username exist!!")
            roo1.destroy()
        else:
            f = open(str(username) + ".bin", "wb")
            l = []
            l.append(str(username))
            l.append(str(password))
            a.append(l)
            pickle.dump(a, f)
            HSP = username + "" + password
            f.close()
            file_name = str(username)
            pyAesCrypt.encryptFile(
                file_name + ".bin",
                file_name + ".bin.fenc",
                HSP,
                bufferSize,
            )
            fb = False
            os.remove(file_name + ".bin")
    if fb == False:
        hsp = username + "" + password
        pyAesCrypt.decryptFile(file_name + ".bin.fenc", file_name + 'decrypted' + '.bin', hsp, bufferSize)

        d = pygame.display.set_mode((800, 600))
        gameloop(d, file_name + "decrypted" + ".bin",password)

    but = Button(login_window1, text="Register", command=inputing)

    lbl1 = Label(login_window1, text=text)

    login.grid(row=2, column=0)
    lbl.grid(row=0, column=1)
    pass1.grid(row=6, column=0)
    input_entry1.grid(row=2, column=1)
    pass_entry1.grid(row=6, column=1)
    lbl1.grid(row=7, column=1)
    but.grid(row=8, column=1)


main = Label(root, text="Welcome to ONE-PASS manager")
login_text = Label(root, text="Do you already have an account")
register_text = Label(root, text='If you don"t have an account please register')
reg_button = Button(root, text="Register", command=register)
login_button = Button(root, text="login", command=login)  # added login button

main.grid(row=0, column=1, columnspan=2)
login_button.grid(row=7, column=1, columnspan=2)
login_text.grid(row=6, column=1, columnspan=2)
register_text.grid(row=8, column=1, columnspan=2)
reg_button.grid(row=9, column=1, columnspan=2)
root.resizable(False, False)
root.mainloop()
