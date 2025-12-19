from tkinter import *
from tkinter import ttk
root = Tk()


def answer():
    print("Button clicked!")
    
label = ttk.Label(root, text="Hello World!")
label.pack(pady=20)

entry = ttk.Entry(root, width=20)
entry.pack(pady=20)

Button = ttk.Button(root, text="Submit", command=answer)
Button.pack(pady=20)

Quit = ttk.Button(root, text="Quit", command=root.destroy)
Quit.pack(pady=20)



root.mainloop()