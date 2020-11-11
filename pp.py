try: #python3 imports
    import tkinter as tk
except ImportError: #python3 failed, try python2 imports
    import Tkinter as tk

class Popup(tk.Toplevel):
    """modal window requires a master"""
    def __init__(self, master, **kwargs):
        tk.Toplevel.__init__(self, master, **kwargs)
        self.overrideredirect(True)
        self.geometry('300x200+500+500') # set the position and size of the popup

        lbl = tk.Label(self, text="Please wait for other players to join ... ")
        lbl.place(relx=.5, rely=.5, anchor='c')

        # The following commands keep the popup on top.
        # Remove these if you want a program with 2 responding windows.
        # These commands must be at the end of __init__
        self.transient(master) # set to be on top of the main window
        self.grab_set() # hijack all commands from the master (clicks on the main window are ignored)

### demo usage:

def open_popup():
    root.popup = Popup(root)

    # close the popup in 2 seconds
    root.after(2000, close_popup)

def close_popup():
    root.popup.destroy()

root = tk.Tk()
btn = tk.Button(root, text='Open Modal Window', command=open_popup)
btn.pack()
root.mainloop()
