getting the username
        self.handler = args[0]
        self.username = args[1]
        self.hashed_password = args[2]
        self.object = args[3]
        self.password = args[4]

        self.button = button
        self.subbar = Frame(self, bg="black", width=150, height=1057, relief="sunken", borderwidth=2)
        self.subbar.place(x=0, y=0)
        self.subbar.grid_propagate(False)
        bg_img = tk_image.PhotoImage(image.open(f"{path}log.jpg"))

        scrollbar = ScrolledFrame(self.subbar, width=130, height=661,bg='black')
        

        scrollbar.place(x=0, y=0)
        # configure the canvas
        scrollbar.bind_arrow_keys(self.subbar)
        scrollbar.bind_scroll_wheel(self.subbar)

        # creating another frame
        self.second_frame = scrollbar.display_widget(Frame,bg='#1E1E1E', width=130, height=661)

        # add that new frame to a new window in the canvas
        image_new = tk_image.PhotoImage(image.open(f"{path}add-button.png"))

        self.add_button = Button(
            self.second_frame,
            text="Add",
            fg="white",
            image=image_new,
            compound="top",
            activeforeground="white",
            bg="#292A2D",
            height=80,
            activebackground="#292A2D",
            width=120,
            relief=RAISED,
            font=("Verdana", 9),
            command=lambda: self.addaccount(),
        )
        self.add_button.photo = image_new
        values = []
        with open(f"{self.username}decrypted.bin", "rb") as f:
            try:
                values = p.load(f)
            except:
                pass
        length_list = len(values)
        self.add_button.place(x=0,y=80*length_list)
        self.buttons_blit()

    def buttons_blit(self):

        new = []
        with open(f"{self.username}decrypted.bin", "rb") as f:
                val = p.load(f)
                for i in val:
                    new.append(i[2])
                d = {}
                for i in range(len(new)):
                    if val[i][3] == "":
                        print('f')
                        button_img = tk_image.PhotoImage(
                            image.open(f"{path}side_display.jpg"))
                    else:
                        button_img = tk_image.PhotoImage(image.open(val[i][3]))
                    d[
                        Button(
                            self.second_frame,
                            text=f"{new[i]}",
                            bg="#292A2D",
                            fg="white",
                            activeforeground="white",
                            activebackground="#292A2D",
                            width=120,
                            height=80,
                            font=("Cascadia", 9),
                            image=button_img,
                            compound="top",
                            command=lambda value=new[i]: self.show_account(value))

                    ] = [i, button_img]

                for i in d:
                    i.image = d[i][1]
                    i.place(x=0, y=85*(d[i][0]))
                with open(f"{self.username}decrypted.bin", "rb") as f:
                    try:
                        values = p.load(f)
                    except:
                        values = []
                length_list = len(values)
                self.add_button.place(x=0, y=85*length_list)