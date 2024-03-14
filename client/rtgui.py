#!/usr/bin/python3

# This script will use gs.py functions in order to create a GUI for the user to interact with the system.

import tkinter as tk
from tkinter import *
import gs
import time
import threading

def assign_username():
    username = entry.get()
    return username

def call_gs():
    username = assign_username()
    logged = gs.auth(username)
    if logged:
        message.config(text="Bienvenue "+username+" !")
    else:
        message.config(text="Impossible de vous authentifier")

window = tk.Tk()
window.title("RTGUI for RTMSG")
window.geometry("400x400")

entry = tk.Entry(window)
entry.pack()
username = entry.get()

message = tk.Label(window, text="")

user = tk.StringVar()
launch = tk.Button(window, text="Authenticate", command=call_gs)
launch.pack()

window.mainloop()

