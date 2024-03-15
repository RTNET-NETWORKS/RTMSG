#!/usr/bin/python3

# This script will use gs.py functions in order to create a GUI for the user to interact with the system.

import tkinter as tk
from tkinter import *
from tkinter import ttk
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
    if logged == 0:
        message.config(text="Hello "+username+" !")
        user_gui()
    elif logged == 1:
        message.config(text="Authentication has failed !")
        login()
    elif logged == 2:
        invite_check_gui()
    message.pack()

def invite_check_gui():
    clear_gui()
    username = assign_username()
    invite_entry = tk.Entry(window, text="Code d'invitation")

    def invite_check_button():
        invite = invite_entry.get()
        message = tk.Label(window, text="")
        error = gs.verify_invite(username,invite)
        clear_gui()
        if error == 0:
            message.config(text="You have been registered ! Your keys have been generated")
        if error == 1:
            message.config(text="Code is incorrect")
        if error == 2:
            message.config(text="Error")
        return_button = tk.Button(window, text="Return to main menu", command=login)
        message.pack()
        return_button.pack()

    invite_button = tk.Button(window, text="Check activation code", command=invite_check_button)
    invite_entry.pack()
    invite_button.pack()

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

def invite_gui():
    clear_gui()
    username = assign_username()
    target_entry = tk.Entry(window, text="User to invite")
    target_entry.pack()
    

    def send_invite_button():
        clear_gui()
        target = target_entry.get()
        error = gs.invite(username,target)
        message = tk.Label(window, text="")
        return_button = tk.Button(window, text="Return to main menu", command=user_gui)
        if error == 1:
            message.config(text="User already exists !")
        elif error == 2:
            message.config(text="User had already been invited !")
        elif error == 3 or error == 4:
            message.config(text="Forbidden")
        else:
            message.config(text=error)
        message.pack()
        return_button.pack()

    send_button = tk.Button(window, text="Send invitation", command=send_invite_button)
    send_button.pack()

def grant_user_gui():
    clear_gui()
    user_label = tk.Label(window, text="User to grant")
    user_entry = tk.Entry(window, text="User to grant")
    level_label = tk.Label(window, text="Level to grant")
    user_level = tk.Entry(window, text="Level")

    def grant_user_button():
        user_target = user_entry.get()
        level_target = user_level.get()
        level_target = str(level_target)
        username = assign_username()
        error = gs.user_grant(username,user_target,level_target)
        message = tk.Label(window, text="")
        return_button = tk.Button(window, text="Return to main menu", command=user_gui)
        if error == 0:
            clear_gui()
            message.config(text="User has been granted !")
        elif error == 1:
            clear_gui()
            message.config(text="Unknown user")
        elif error == 2:
            clear_gui()
            message.config(text="Forbidden")
        message.pack()
        return_button.pack()

    user_button = tk.Button(window, text="Grant user", command=grant_user_button)
    user_label.pack()
    user_entry.pack()
    level_label.pack()
    user_level.pack()
    user_button.pack()

def drop_user_gui():
    clear_gui()
    user_target = tk.Entry(window, text="User")
    user_label = tk.Label(window, text="User to drop")
    username = assign_username()

    def drop_user_button():
        clear_gui()
        target = user_target.get()
        error = gs.drop_user(username,target)
        message = tk.Label(window, text="")
        if error == 0:
            message.config(text="User has been dropped")
        elif error == 1:
            message.config(text="Unknown user")
        elif error == 2:
            message.config(text="Forbidden")
        return_button = tk.Button(window, text="Return to main menu", command=user_gui)
        message.pack()
        return_button.pack()

    user_button = tk.Button(window, text="Drop user", command=drop_user_button)
    user_label.pack()
    user_target.pack()
    user_button.pack()

def rtkey_gui():
    clear_gui()
    username = assign_username()
    options = ["Store new password","Check password","Remove password"]
    choice_entry = ttk.Combobox(window, values=options)
    label = tk.Label(window, text="What are you planning to do ?")
    choice = choice_entry.get()

    def rtkey_button():
        clear_gui()
        error = gs.rtkey(username,choice)
        message = tk.Label(window, text="")
        if error == 0:
            message.config(text="Password has been stored")
    
    if choice == "Store new password":
        clear_gui()
        name_entry = tk.Entry(window, text="Name associated")
        name_label = tk.Label(window, text="Name associated")
        password_entry = tk.Entry(window, text="Password")
        password_label = tk.Entry(window, text="Password")
        send_button = tk.Button(window, text="Send password", command=rtkey_button)
        name_entry.pack()
        name_label.pack()
        password_entry.pack()
        password_label()
        send_button.pack()


def exit_rtmsg():
    exit(0)

def user_gui():
    clear_gui()
    send_button = tk.Button(window, text="Send message", command=send_message_gui)
    read_button = tk.Button(window, text="Read message", command=read_message_gui)
    invite_button = tk.Button(window, text="Invite a user", command=invite_gui)
    grant_button = tk.Button(window, text="Grant user", command=grant_user_gui)
    drop_button = tk.Button(window, text="Drop user", command=drop_user_gui)
    rtkey_button = tk.Button(window, text="RTKEY", command=rtkey_gui)
    logout_button = tk.Button(window, text="Logout", command=login)
    exit_button = tk.Button(window, text="Exit RTMSG", command=exit_rtmsg)
    send_button.pack()
    read_button.pack()
    invite_button.pack()
    grant_button.pack()
    drop_button.pack()
    rtkey_button.pack()
    logout_button.pack()
    exit_button.pack()

def login():
    clear_gui()
    entry.pack()
    launch.pack()
    exit_button.pack()

window = tk.Tk()
window.title("RTGUI for RTMSG")
window.geometry("600x600")

message = tk.Label(window, text="")

entry = tk.Entry(window, text="Login")
launch = tk.Button(window, text="Authenticate", command=call_gs)
exit_button = tk.Button(window, text="Exit RTMSG", command=exit_rtmsg)
entry.pack()
launch.pack()
exit_button.pack()

window.mainloop()
login()

