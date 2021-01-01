from tkscrolledframe import ScrolledFrame
import tkinter as tk

# Create a root window
root = tk.Tk()

frame_top = tk.Frame(root, width=400, height=250)
frame_top.pack(side="top", expand=1, fill="both")

# Create a ScrolledFrame widget
sf = ScrolledFrame(frame_top, width=380, height=240)
sf.pack(side="top", expand=1, fill="both")

# Bind the arrow keys and scroll wheel
sf.bind_arrow_keys(frame_top)
sf.bind_scroll_wheel(frame_top)

frame = sf.display_widget(tk.Frame)

l = tk.Label(frame, text="Test text 1\nTest text 2\nTest text 3\nTest text 4\nTest text 5\nTest text 6\nTest text 7\nTest text 8\nTest text 9", font="-size 20")
l.pack()

root.mainloop()
