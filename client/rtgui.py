#!/usr/bin/python3

# This script will use gs.py functions in order to create a GUI for the user to interact with the system.

import tkinter as tk
from tkinter import *
import gs
import time
import threading

window = tk.Tk()
window.title("RTGUI for RTMSG")
window.geometry("600x400")

entry = tk.Entry(window)
entry.pack()
username = entry.get()

user = tk.StringVar()


def assign_username():
    username = entry.get()
    return username

def call_gs():
    username = assign_username()
    logged = gs.auth(username)
    if logged:
        message = tk.Label(window, text="Bienvenue "+username+" !")
        message.pack()
        time.sleep(5)
        user_gui()
    else:
        message = tk.Label(window, text="Impossible de vous authentifier !")
        message.pack()

def user_gui():
    launch.pack_forget()
    message.pack_forget()
    entry.pack_forget()

launch = tk.Button(window, text="Authenticate", command=call_gs)
launch.pack()

window.mainloop()

