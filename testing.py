import tkinter as tk
import tkinter.ttk as ttk 
from ttkthemes import ThemedStyle
app = tk.Tk()
app.geometry("200x400")
app.title("Changing Themes")
# Setting Theme
style = ThemedStyle(app)
style.set_theme("scidgrey")
# Button Widgets
Def_Btn = tk.Button(app,text='Default Button')
Def_Btn.pack()
Themed_Btn = ttk.Button(app,text='Themed button')
Themed_Btn.pack()

# Scrollbar Widgets
Def_Scrollbar = tk.Scrollbar(app)
Def_Scrollbar.pack(side='right',fill='y')
Themed_Scrollbar = ttk.Scrollbar(app,orient='horizontal')
Themed_Scrollbar.pack(side='top',fill='x')

# Entry Widgets
Def_Entry = tk.Entry(app)
Def_Entry.pack()
Themed_Entry = ttk.Entry(app)
Themed_Entry.pack()

app.mainloop()
