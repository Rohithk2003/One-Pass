from data.delete_class import *
import glob
from data.update_checker import *
from data.login_class import *


def log_out(*window):
    try:
        for i in window:
            i.destroy()

        a = Tk()
        a.withdraw()
        messagebox.showinfo(
            "Logged Out", "You have been successfully logged out")
        a.destroy()
        list_file = glob.glob("*decrypted.bin")
        for i in list_file:
            converting_str = str(i)
            try:
                os.remove(converting_str)
            except:
                pass
        login()

    except:
        pass


def settings(
        real_username,
        main_window,
        hashed_password,
        window,
        password_button,
        rec_pas,
        original_password,
        object
):
    settings_window = Toplevel()
    settings_window.resizable(False, False)
    width_window = 187
    height_window = 175
    screen_width = settings_window.winfo_screenwidth()
    screen_height = settings_window.winfo_screenheight()
    x = screen_width / 2 - width_window / 2
    y = screen_height / 2 - height_window / 2

    settings_window.geometry("%dx%d+%d+%d" %
                             (width_window, height_window, x, y))

    settings_window.title("Settings")
    settings_window.config(bg="#292A2D")

    delete_object = Deletion(real_username, hashed_password, window,object)
    change_object = Change_details(real_username, hashed_password, window,object)

    log_label = Button(
        settings_window,
        text="Log out",
        width=20,
        font=("consolas"),
        fg="white",
        activebackground="white",
        activeforeground="white",
        bg="#994422",
        bd=0,
        command=lambda: log_out(settings_window, window, main_window),
    )

    check_for_updates = Button(
        settings_window,
        command=checkforupdates,
        text="Check for updates",
        width=20,
        activebackground="#994422",
        font=("consolas"),
        activeforeground="white",
        fg="white",
        bg="#994422",
        bd=0,
    )
    Delete_account_button = Button(
        settings_window,
        text="Delete main account",
        command=lambda: delete_object.delete_main_account(
            main_window, settings_window),
        font=("consolas"),
        width=20,
        fg="black",
        activeforeground="black",
        activebackground="white",
        bg="white",
        bd=0,
    )
    Delete_social_button = Button(
        settings_window,
        text="Delete sub  account",
        command=lambda: delete_object.delete_social_media_account(
            password_button, True
        ),
        font=("consolas"),
        fg="black",
        width=20,
        activeforeground="black",
        activebackground="white",
        bg="white",
        bd=0,
    )
    change_account_button = Button(
        settings_window,
        text="Change Details",
        command=lambda: login_password("Change Details"),
        font=("consolas"),
        fg="white",
        activebackground="#994422",
        activeforeground="white",
        width=20,
        bg="#994422",
        bd=0,
    )
    change_email_button = Button(
        settings_window,
        text="Change recovery email",
        command=lambda: change_object.change_email(rec_pas, original_password),
        font=("consolas"),
        fg="black",
        activebackground="white",
        activeforeground="black",
        width=20,
        bg="white",
        bd=0,
    )

    Delete_account_button.grid(row=1, column=1, columnspan=2)
    check_for_updates.grid(row=2, column=1, columnspan=2)
    Delete_social_button.grid(row=3, column=1, columnspan=2)
    change_account_button.grid(row=4, column=1, columnspan=2)
    change_email_button.grid(row=5, column=1, columnspan=2)
    log_label.grid(row=6, column=1, columnspan=2)

    if os.stat(f"{real_username}decrypted.bin").st_size == 0:
        Delete_social_button.config(state=DISABLED)
    else:
        Delete_social_button.config(state=NORMAL)
    settings_window.mainloop()
