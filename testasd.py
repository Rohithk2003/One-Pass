import tkinter as tk

class SampleApp(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.frame = tk.Frame(self)
        self.frame.pack()
        self.button = tk.Button(self.frame, text="click me",
                             command=lambda a=1, b=2, c=3:
                                self.rand_func(a, b, c))
        self.button.pack()
        self.frame.bind("<Return>",
                        lambda event, a=10, b=20, c=30:
                            self.rand_func(a, b, c))
        # make sure the frame has focus so the binding will work
        self.frame.focus_set()

    def rand_func(self, a, b, c):
        print (a+b+c)

app = SampleApp()
app.mainloop()