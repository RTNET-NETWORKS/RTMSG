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

message = tk.Label(window, text="")

user = tk.StringVar()


def assign_username():
    username = entry.get()
    return username

def call_gs():
    username = assign_username()
    logged = gs.auth(username)
    if logged:
        message.config(text="Bienvenue "+username+" !")
        message.pack()
        user_gui()
    else:
        message.config(text="Impossible de vous authentifier !")
        message.pack()

def clear_gui():
    for widget in window.winfo_children():
        widget.pack_forget()

def send_message_gui():
    clear_gui()
    username = assign_username()
    user_label = tk.Label(window, text="User")
    user_entry = tk.Entry(window)
    message_label = tk.Label(window, text="Message")
    message_entry = tk.Entry(window)
    user_label.pack()
    user_entry.pack()
    message_label.pack()
    message_entry.pack()
    
    # Fonction à exécuter lorsque le bouton est cliqué
    def send_message_button():
        target = user_entry.get()
        message_to_send = message_entry.get()
        gs.send_message(username, target, message_to_send)
        user_gui()
    
    # Création du bouton en utilisant une fonction lambda pour encapsuler l'appel à send_message
    user_button = tk.Button(window, text="Send to this user", command=send_message_button)
    user_button.pack()

def exit_rtmsg():
    exit(0)

def user_gui():
    clear_gui()
    send_button = tk.Button(window, text="Send message", command=send_message_gui)
    exit_button = tk.Button(window, text="Exit RTMSG", command=exit_rtmsg)
    send_button.pack()
    exit_button.pack()

launch = tk.Button(window, text="Authenticate", command=call_gs)
launch.pack()

window.mainloop()

