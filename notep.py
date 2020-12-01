
    def note_pad_sec():
        global status_name
        global password
        global var
        notes_buttons["state"] = DISABLED
        button["state"] = NORMAL
        try:
            list = mainarea.pack_slaves()
            for i in list:
                i.forget()
        except:
            pass
        if __name__ == "__main__":
            emptyMenu = Menu(root)
            root.config(menu=emptyMenu)

            list = mainarea.grid_slaves()
            for l in list:
                l.destroy()

            def newFile():
                global password
                root.title("Untitled - Notepad")
                TextArea.delete(1.0, END)

            def openFile():
                global password
                global file
                file = fd.askopenfilename(
                    defaultextension=".txt",
                    filetypes=[("All Files", "*.*"), ("Text Documents", "*.txt")],
                )
                if file != None:
                    if file.endswith(".bin.fenc"):
                        password = str(
                            simpledialog.askstring(
                                title="Password Required",
                                prompt="Please provide the password",
                            )
                        )
                        if password == "":
                            messagebox.showerror("Error", "Password cannot be empty")
                        else:
                            new_file = os.path.splitext(file)[0]
                            b = os.path.basename(new_file)
                            new_d = os.path.basename(b)
                            filename = new_d + "decrypted.txt"
                            try:
                                pyAesCrypt.decryptFile(
                                    file, filename, password, bufferSize
                                )
                                root.title(os.path.basename(file) + " - Notepad")
                                TextArea.delete(1.0, END)
                                with open(filename, "r") as f:
                                    TextArea.insert(1.0, f.read())
                                    f.close()
                            except:
                                messagebox.showerror("Error", "Wrong password")

                # check to if there is a file_name
                global status_name
                status_name = file
                if file == "":
                    file = None
                else:
                    root.title(os.path.basename(file) + " - Notepad")
                    TextArea.delete(1.0, END)
                    with open(file, "r") as f:
                        TextArea.insert(1.0, f.read())
                        f.close()

            def rename_file():
                global file
                if root.title() != "Untitled-Notepad":
                    application_window = Tk()
                    application_window.withdraw()
                    a = simpledialog.askstring(
                        "Input", "What is new file name?", parent=application_window
                    )
                    application_window.destroy()
                    if file != None or file != 0:
                        new_file, file_extension = os.path.splitext(file)
                        b = os.path.basename(new_file)
                        new_d = os.path.basename(b)
                        new_file_name = os.path.basename(b)
                        f = open(file, "r")
                        dir = os.path.dirname(file)
                        values = f.read()
                        f.close()
                        os.remove(file)
                        file = (dir) + "/" + a + file_extension
                        with open(file, "w") as f:
                            f.write(values)
                            f.close()
                        TextArea.delete(1.0, END)
                        with open(file, "r") as f:
                            TextArea.insert(1.0, f.read())
                            f.close()
                        root.title(a + file_extension + " - Notepad")
                    else:
                        messagebox.showinfo(
                            "Rename", "Please save your file before renaming it"
                        )
                        save_as_File()
                else:
                    messagebox.showinfo(
                        "Rename", "Please save your file before renaming it"
                    )
                    save_as_File()

            def save_as_File():
                global password
                global file
                if file == None:
                    result = messagebox.askyesno(
                        "Confirm", "Do you want to encrypt your file?"
                    )
                    if not result:
                        file = fd.asksaveasfilename(
                            initialfile="Untitled.txt",
                            defaultextension=".txt",
                            filetypes=[
                                ("All Files", "*.*"),
                                ("Text Documents", "*.txt"),
                            ],
                        )
                        if file == "":
                            file = None

                        else:
                            # Save as a new file
                            with open(file, "w") as f:
                                f.write(TextArea.get(1.0, END))
                                f.close()
                            root.title(os.path.basename(file) + " - Notepad")
                            file = file
                    else:
                        application_window = Tk()
                        a = simpledialog.askstring(
                            "Input",
                            "What is  the password for the file?",
                            parent=application_window,
                        )
                        if a == "":
                            messagebox.showerror("Error", "Password cannot be empty")
                        else:
                            application_window.destroy()
                            file = fd.asksaveasfilename(
                                initialfile="Untitled.txt",
                                defaultextension=".txt",
                                filetypes=[("Text Documents", "*.txt")],
                            )
                            gmm = str(file)
                            password = "testing"
                            status_name = file
                            if file == "":
                                file = None

                            else:
                                # Save as a new file
                                with open(file, "w") as f:
                                    f.write(TextArea.get(1.0, END))
                                    f.close()
                                root.title(os.path.basename(file) + " - Notepad")
                                file = file
                            file_name = str(file)
                            f_encrypt = file_name + ".aes"
                            try:
                                pyAesCrypt.encryptFile(
                                    file_name, f_encrypt, a, 64 * 1024
                                )
                                os.remove(file)
                            except:
                                pass

            def save_file():
                global status_name
                if status_name:
                    with open(status_name, "w") as f:
                        f.write(TextArea.get(1.0, END))
                        f.close()
                else:
                    result = messagebox.askyesno(
                        "Confirm", "Do you want to encrypt your file?"
                    )
                    if result == False:
                        file = fd.asksaveasfilename(
                            initialfile="Untitled.txt",
                            defaultextension=".txt",
                            filetypes=[
                                ("All Files", "*.*"),
                                ("Text Documents", "*.txt"),
                            ],
                        )
                        gmm = str(file)
                        status_name = file
                        if file == "":
                            file = None

                        else:
                            # Save as a new file
                            with open(file, "w") as f:
                                status_name = True
                                f.write(TextArea.get(1.0, END))
                                f.close()
                            root.title(os.path.basename(file) + " - Notepad")
                    else:
                        file = fd.asksaveasfilename(
                            initialfile="Untitled.txt",
                            defaultextension=".txt",
                            filetypes=[
                                ("All Files", "*.*"),
                                ("Text Documents", "*.txt"),
                            ],
                        )
                        gmm = str(file)
                        password = str(
                            simpledialog.askstring(
                                title="Password", prompt="Please provide the password"
                            )
                        )
                        status_name = file
                        if file == "":
                            file = None

                        else:
                            # Save as a new file
                            with open(file, "w") as f:
                                f.write(TextArea.get(1.0, END))
                                f.close()
                            root.title(os.path.basename(file) + " - Notepad")
                            file = file
                        file_name = str(file)
                        try:
                            pyAesCrypt.encryptFile(
                                file_name, file_name + ".aes", password, 64 * 1024
                            )
                            os.remove(file)
                        except:
                            pass

            def quitApp():
                root.destroy()

            def cut(*event):
                global cutting_value
                try:
                    if TextArea.selection_get():
                        # grabbing selected text from text area
                        cutting_value = TextArea.selection_get()
                        TextArea.delete("sel.first", "sel.last")
                except:
                    cutting_value = ""

            def copy(*event):
                global cutting_value
                try:
                    if TextArea.selection_get():
                        # grabbing selected text from text area
                        cutting_value = TextArea.selection_get()
                except:
                    cutting_value = ""

            def paste(*event):
                if cutting_value:
                    postion = TextArea.index(INSERT)
                    TextArea.insert(postion, cutting_value)

            def about():
                messagebox.showinfo("Notepad", "Notepad by Rohithk-25-11-2020")

            # Basic tkinter setup
            root.geometry("1000x500")
            root.title("Untitled - Notepad")
            # Add TextArea
            root.resizable(0, 0)
            font_main = ("freesansbold", 12)
            Scroll_y = Scrollbar(mainarea, orient="vertical")
            Scroll_y.pack(side="right", fill=Y)
            TextArea = Text(
                mainarea,
                font=font_main,
                fg="#292A2D",
                insertofftime=600,
                insertontime=600,
                insertbackground="#292A2D",
                undo=True,
                yscrollcommand=Scroll_y.set,
            )

            Scroll_y.config(command=TextArea.yview)
            TextArea.pack(expand=True, fill=BOTH)

            # create a menubar
            MenuBar = Menu(root)
            MenuBar.config(bg="#292A2D", bd="0", activebackground="#292A2D")
            status_name = False
            root.config(bg="red", menu=MenuBar)
            # File Menu Starts

            FileMenu = Menu(MenuBar, tearoff=0)
            FileMenu.config(bg="#292A2D", bd="0", activebackground="#292A2D")

            # To open new file
            FileMenu.add_command(
                label="New",
                command=newFile,
                foreground="white",
                activebackground="#4B4C4F",
            )

            FileMenu.add_command(
                label="Open",
                command=openFile,
                foreground="white",
                activebackground="#4B4C4F",
            )
            # To save the current file
            FileMenu.add_command(
                label="Save",
                command=lambda: save_file(),
                foreground="white",
                activebackground="#4B4C4F",
            )
            FileMenu.add_command(
                label="Save As",
                command=lambda: save_as_File(),
                foreground="white",
                activebackground="#4B4C4F",
            )
            FileMenu.add_command(
                label="Rename",
                command=lambda: rename_file(),
                foreground="white",
                activebackground="#4B4C4F",
            )
            FileMenu.add_command(
                label="Exit",
                command=quitApp,
                foreground="white",
                activebackground="#4B4C4F",
            )
            MenuBar.add_cascade(
                label="File",
                menu=FileMenu,
                foreground="white",
                activebackground="#4B4C4F",
            )

            # File Menu ends
            def select_font(font):
                size = TextArea["font"]
                num = ""
                for i in size:
                    if i in "1234567890":
                        num += i
                real_size = int(num)
                new_font_size = (font, real_size)
                TextArea.config(font=new_font_size)

            def change_size(size):
                global var
                lb = Label(mainarea, text=var, anchor=E)
                lb.pack(fill=X, side=TOP)
                var = len(str(TextArea.get("1.0", "end-1c")))
                lb.config(text=var)

                def update(event):
                    var = len(str(TextArea.get("1.0", "end-1c")))
                    lb.config(text=var)

                TextArea.bind("<KeyPress>", update)
                TextArea.bind("<KeyRelease>", update)
                original_font = TextArea["font"]
                find_font = ""
                var = ""
                for i in original_font:
                    if i == " " or i.isalpha():
                        var += i
                find_font = var.rstrip()
                new_font = (find_font, size)
                TextArea.configure(font=new_font)

            def change_color():
                my_color = colorchooser.askcolor()[1]
                TextArea.config(fg=my_color)

            def bg_color():
                my_color = colorchooser.askcolor()[1]
                TextArea.config(bg=my_color)

            def highlight_text():
                TextArea.tag_configure(
                    "start", background="#FFFF00", foreground="#292A2D"
                )
                try:
                    TextArea.tag_add("start", "sel.first", "sel.last")
                except TclError:
                    pass

            def secondary(*event):
                replace_window = Toplevel(mainarea)
                replace_window.focus_set()
                replace_window.grab_set()
                replace_window.title("Replace")
                replace_entry = Entry(replace_window)
                find_entry_new = Entry(replace_window)
                find_entry_new.grid(row=0, column=0)
                replace_button = Button(
                    replace_window,
                    text="Replace",
                    command=lambda: replacenfind(
                        find_entry_new.get(), replace_window, str(replace_entry.get())
                    ),
                )
                replace_button.grid(row=1, column=1)
                replace_entry.grid(row=1, column=0)

            def primary(*event):
                find_window = Toplevel(mainarea)
                find_window.geometry("100x50")
                find_window.focus_set()
                find_window.grab_set()
                find_window.title("Find")
                find_entry = Entry(find_window)
                find_button = Button(
                    find_window,
                    text="Find",
                    command=lambda: find(find_entry.get(), find_window),
                )
                find_entry.pack()
                find_button.pack(side="right")

            def replacenfind(value, window, replace_value):
                text_find = str(value)
                index = "1.0"
                TextArea.tag_remove("found", "1.0", END)
                if value:
                    while 1:
                        index = TextArea.search(
                            text_find, index, nocase=1, stopindex=END
                        )
                        if not index:
                            break
                        lastidx = "% s+% d" % (index, len(text_find))
                        TextArea.delete(index, lastidx)
                        TextArea.insert(index, replace_value)
                        lastidx = "% s+% d" % (index, len(replace_value))
                        TextArea.tag_add("found", index, lastidx)
                        index = lastidx
                    TextArea.tag_config("found", foreground="blue")
                window.focus_set()

            def find(value, window):
                text_find = str(value)
                index = "1.0"
                TextArea.tag_remove("found", "1.0", END)
                if value:
                    while 1:
                        index = TextArea.search(
                            text_find, index, nocase=1, stopindex=END
                        )
                        if not index:
                            break
                        lastidx = "% s+% dc" % (index, len(text_find))
                        TextArea.tag_add("found", index, lastidx)
                        index = lastidx
                    TextArea.tag_config("found", foreground="red")
                window.focus_set()

            def popup_menu(e):
                my_menu.tk_popup(e.x_root, e.y_root)

            try:
                f = TextArea.get()
                if f != "":
                    root.title("*untitled-Notepad")
                else:
                    pass
            except:
                root.title("Untitled-Notepad")
            root.bind("<Control-Key-f>", primary)
            root.bind("<Control-Key-h>", secondary)

            EditMenu = Menu(MenuBar, tearoff=0)
            EditMenu.config(bg="#292A2D", bd="0", activebackground="#292A2D")

            my_menu = Menu(mainarea, tearoff=0)
            my_menu.config(bg="#292A2D", bd="0", activebackground="#292A2D")
            my_menu.add_command(
                label="Highlight",
                command=highlight_text,
                foreground="white",
                activebackground="#4B4C4F",
            )
            my_menu.add_command(
                label="Copy",
                command=copy,
                foreground="white",
                activebackground="#4B4C4F",
            )
            my_menu.add_command(
                label="Cut", command=cut, foreground="white", activebackground="#4B4C4F"
            )
            my_menu.add_command(
                label="Paste",
                command=paste,
                foreground="white",
                activebackground="#4B4C4F",
            )
            TextArea.focus_set()

            TextArea.bind("<Button-3>", popup_menu)
            # To give a feature of cut, copy and paste
            highlight_text_button = Button(
                MenuBar, text="highlight", command=highlight_text
            )
            highlight_text_button.grid(row=0, column=5, sticky=W)
            submenu = Menu(EditMenu, tearoff=0)
            submenu_size = Menu(EditMenu, tearoff=0)
            submenu.config(bg="#292A2D", bd="0", activebackground="#292A2D")
            submenu_size.config(bg="#292A2D", bd="0", activebackground="#292A2D")

            submenu.add_command(
                label="MS Sans Serif",
                command=lambda: select_font("MS Sans Serif"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Arial",
                command=lambda: select_font("Arial"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Bahnschrift",
                command=lambda: select_font("Bahnschrift"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Cambria",
                command=lambda: select_font("Cambria"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Consolas",
                command=lambda: select_font("Consolas"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Courier",
                command=lambda: select_font("Courier"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Century",
                command=lambda: select_font("Century"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Calibri",
                command=lambda: select_font("Calibri"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Yu Gothic",
                command=lambda: select_font("Yu Gothic"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Times New Roman",
                command=lambda: select_font("Times New Roman"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Sylfaen",
                command=lambda: select_font("Sylfaen"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Nirmala UI",
                command=lambda: select_font("Nirmala UI"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Ebrima",
                command=lambda: select_font("Ebrima"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Comic Sans MS",
                command=lambda: select_font("Comic Sans MS"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Microsoft PhagsPa",
                command=lambda: select_font("Microsoft PhagsPa"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Lucida  Console",
                command=lambda: select_font("Lucida Console"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Franklin Gothic Medium",
                command=lambda: select_font("Franklin Gothic Medium"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu.add_command(
                label="Cascadia Code",
                command=lambda: select_font("Cascadia Code"),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="6",
                command=lambda: change_size(6),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="7",
                command=lambda: change_size(7),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="8",
                command=lambda: change_size(8),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="9",
                command=lambda: change_size(9),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="10",
                command=lambda: change_size(10),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="11",
                command=lambda: change_size(11),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="12",
                command=lambda: change_size(12),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="13",
                command=lambda: change_size(13),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="14",
                command=lambda: change_size(14),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="15",
                command=lambda: change_size(15),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="16",
                command=lambda: change_size(16),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="17",
                command=lambda: change_size(17),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="18",
                command=lambda: change_size(18),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="19",
                command=lambda: change_size(19),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="20",
                command=lambda: change_size(20),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="21",
                command=lambda: change_size(21),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="22",
                command=lambda: change_size(22),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="23",
                command=lambda: change_size(23),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="24",
                command=lambda: change_size(24),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="25",
                command=lambda: change_size(25),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="26",
                command=lambda: change_size(26),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="27",
                command=lambda: change_size(27),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="28",
                command=lambda: change_size(28),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="29",
                command=lambda: change_size(29),
                foreground="white",
                activebackground="#4B4C4F",
            )
            submenu_size.add_command(
                label="30",
                command=lambda: change_size(30),
                foreground="white",
                activebackground="#4B4C4F",
            )

            EditMenu.add_command(
                label="Text Color",
                command=change_color,
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Background Color",
                command=bg_color,
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Cut",
                command=cut,
                accelerator="(Ctrl+x)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Copy",
                command=copy,
                accelerator="(Ctrl+c)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Paste",
                command=paste,
                accelerator="(Ctrl+v)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Find",
                command=primary,
                accelerator="(Ctrl+f)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Replace",
                command=secondary,
                accelerator="(Ctrl+h)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Undo",
                command=TextArea.edit_undo,
                accelerator="(Ctrl+z)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_command(
                label="Redo",
                command=TextArea.edit_redo,
                accelerator="(Ctrl+y)",
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_cascade(
                label="Font",
                menu=submenu,
                foreground="white",
                activebackground="#4B4C4F",
            )
            EditMenu.add_cascade(
                label="Size",
                menu=submenu_size,
                foreground="white",
                activebackground="#4B4C4F",
            )
            MenuBar.add_cascade(
                label="Edit",
                menu=EditMenu,
                foreground="white",
                activebackground="#4B4C4F",
            )

            def callback(event):
                save_file()

            def second_callback(event):
                file = None
                save_as_File(file)
                # To Open already existing file

            # bindings
            root.bind("<Control-Key-s>", callback)
            root.bind("<Control-Shift-S>", second_callback)
            root.bind("<Control-Key-x>", cut)
            root.bind("<Control-Key-c>", copy)
            root.bind("<Control-Key-v>", paste)
            # Help Menu Starts
            HelpMenu = Menu(
                MenuBar, tearoff=0, bg="#292A2D", bd="0", activebackground="#292A2D"
            )
            HelpMenu.add_command(
                label="About Notepad",
                command=about,
                foreground="white",
                activebackground="#4B4C4F",
            )
            MenuBar.add_cascade(
                label="Help",
                menu=HelpMenu,
                foreground="white",
                activebackground="#4B4C4F",
            )

            # Help Menu Ends
            MenuBar.pack_propagate(0)
            sidebar.pack_propagate(0)
            root.config(menu=MenuBar)
