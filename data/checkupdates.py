from update_check import isUpToDate
from update_check import update
from tkinter import *
from tkinter import messagebox


def checkforupdates(*window):
    # isUpToDate check whether the file ie main.py  is same as the one present in my github repository and it returns true if same else false
    if isUpToDate(
            "main.py",
            "https://raw.githubusercontent.com/Rohithk2003/One-Pass/develop/main.py",
    ):
        result = messagebox.askyesno(
            "Update Available", "Do you want to update the app?"
        )
        if result == True:
            try:
                messagebox.showinfo(
                    "Updating", "Please wait while the software is being updated"
                )
                # used for updating the file
                update(
                    "main.py",
                    "https://raw.githubusercontent.com/Rohithk2003/One-Pass/develop/main.py",
                )
                messagebox.showinfo(
                    "Updated", "The file has been updated please restart to take effect"
                )
            except:
                messagebox.showerror(
                    "No internet Available", "Internet is not available"
                )

        else:
            pass
            for i in window:
                i.focus_force()
    else:
        messagebox.showinfo("Update", "No update is currently available")
