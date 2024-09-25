#!/usr/bin/python3.11

# This program intends to talk with an ESP32 controller, to send and receive LoRa information for RTMSG.

import tkinter as tk
import serial
import glob
import sys

window = tk.Tk()
window.title("LoRa for RTMSG")
window.geometry("600x600")

def exit_function():
    exit(0)

def serial_connection():
    clear_gui()
    if sys.platform.startswith('win'):
        ports = ['COM%s' % (i + 1) for i in range(256)]
    elif sys.platform.startswith('linux') or sys.platform.startswith('cygwin'):
        # this excludes your current terminal "/dev/tty"
        ports = glob.glob('/dev/tty[A-Za-z]*')
    elif sys.platform.startswith('darwin'):
        ports = glob.glob('/dev/tty.*')
    result = []
    for port in ports:
        try:
            s = serial.Serial(port)
            s.close()
            result.append(port)
        except (OSError, serial.SerialException):
            pass
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