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
    clear_gui()
    if logged:
        message.config(text="Hello "+username+" !")
        message.pack()
        user_gui()
    else:
        message.config(text="Authentication has failed !")
        message.pack()
        login()

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
        result = gs.send_message(username, target, message_to_send)
        if result == 1:
            clear_gui()
            error_label = tk.Label(window, text="Unknown user !")
            error_return = tk.Button(window, text="Return to main menu", command=user_gui)
            error_label.pack()
            error_return.pack()
        user_gui()
    
    # Création du bouton en utilisant une fonction lambda pour encapsuler l'appel à send_message
    user_button = tk.Button(window, text="Send to this user", command=send_message_button)
    user_button.pack()

def read_message_gui():
    clear_gui()
    label_array = tk.Label(window, text="")
    username = assign_username()
    read_state = tk.BooleanVar()
    case = tk.Checkbutton(window, text="Red messages", variable=read_state)
    case.pack()

    def read_message_button():
        read = read_state.get()
        array = gs.read_message(username,read)
        array_str = "\n".join(array)
        label_array.config(text=array_str)
        label_array.pack()

    check_button = tk.Button(window, text="Check messages", command=read_message_button)
    gui_button = tk.Button(window, text="Return to main menu", command=user_gui)
    check_button.pack()
    gui_button.pack()

def exit_rtmsg():
    exit(0)

def user_gui():
    clear_gui()
    send_button = tk.Button(window, text="Send message", command=send_message_gui)
    read_button = tk.Button(window, text="Read message", command=read_message_gui)
    logout_button = tk.Button(window, text="Logout", command=login)
    exit_button = tk.Button(window, text="Exit RTMSG", command=exit_rtmsg)
    send_button.pack()
    read_button.pack()
    logout_button.pack()
    exit_button.pack()

def login():
    clear_gui()
    entry.pack()
    launch.pack()

window = tk.Tk()
window.title("RTGUI for RTMSG")
window.geometry("600x600")

message = tk.Label(window, text="")

entry = tk.Entry(window, text="Login")
launch = tk.Button(window, text="Authenticate", command=call_gs)
entry.pack()
launch.pack()

window.mainloop()
login()

