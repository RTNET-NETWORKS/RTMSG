#!/usr/bin/python3.11

# This program intends to talk with an ESP32 controller, to send and receive LoRa information for RTMSG.

import tkinter as tk

window = tk.Tk()
window.title("LoRa for RTMSG")
window.geometry("600x600")

def exit_function():
    exit(0)

def serial_connection():
    clear_gui()
    message = tk.Label(window, text='Serial screen')
    exit_button = tk.Button(window, text='Go back to main menu', command=go_main)
    message.pack()
    exit_button.pack()

def clear_gui():
    for widget in window.winfo_children():
        widget.pack_forget()

def go_main():
    clear_gui()
    launch_button.pack()
    exit_button.pack()

launch_button = tk.Button(window, text='Launch serial connection', command=serial_connection)
exit_button = tk.Button(window, text='Exit', command=exit_function)
launch_button.pack()
exit_button.pack()

window.mainloop()