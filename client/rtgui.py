#!/usr/bin/python3

# This script will use gs.py functions in order to create a GUI for the user to interact with the system.

import tkinter as tk
from tkinter import *
import gs
import time
import threading

window = tk.Tk()
window.title("RTGUI for RTMSG")
window.geometry("400x400")

user = tk.StringVar()
#launch = tk.Button(window, text="Authenticate", command=gs.auth)
#launch.pack()

window.mainloop()

