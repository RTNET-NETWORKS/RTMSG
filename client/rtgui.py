#!/usr/bin/python3

# This script will use gs.py functions in order to create a GUI for the user to interact with the system.

import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import gs
import base64
import requests
import time
import threading

global token
token = ""

def store_token(token_r):
    token = token_r

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
        error = gs.rtkey(username,choice,name_password,password)
        message = tk.Label(window, text="")
        if error == 0:
            message.config(text="Password has been stored")
    
    def choice_function():
        choice = choice_entry.get()
        if choice == "Store new password":
            clear_gui()
            name_entry = tk.Entry(window, text="Name associated")
            name_label = tk.Label(window, text="Name associated")
            password_entry = tk.Entry(window, text="Password")
            password_label = tk.Label(window, text="Password")
            global password
            global name_password
            name_password = name_entry.get()
            password = password_entry.get()
            send_button = tk.Button(window, text="Send password", command=rtkey_button())
            name_label.pack()
            name_entry.pack()
            password_label.pack()
            password_entry.pack()
            send_button.pack()
        if choice == "Check password":
            choice = "s"
            error = gs.rtkey(username,choice,name_password,password)

    choice_button = tk.Button(window, text="Make a choice", command=choice_function)
    label.pack()
    choice_entry.pack()
    choice_button.pack()

def file_cipher_gui():
    username = assign_username()
    file = filedialog.askopenfilename(initialdir="/", title="Select a file")
    if file:
        clear_gui()
        error = gs.file_cipher(username,file)
        message = tk.Label(window, text="")
        return_button = tk.Button(window, text="Return to the main menu", command=user_gui)
        if error == 0:
            message.config(text="Your encrypted file has been saved in "+file+"_encrypted !")
        elif error == 1:
            message.config(text="An error occured")
        message.pack()
        return_button.pack()

def file_uncipher_gui():
    username = assign_username()
    file = filedialog.askopenfilename(initialdir="/", title="Select a file")
    if file:
        clear_gui()
        error = gs.file_uncipher(username,file)
        message = tk.Label(window, text="")
        return_button = tk.Button(window, text="Return to the main menu", command=user_gui)
        if error == 0:
            message.config(text="Your cleared file has been saved in "+file+"_clear !")
        message.pack()
        return_button.pack()

def aes_cipher_gui():
    username = assign_username()
    file = filedialog.askopenfilename(initialdir="/", title="Select a file")
    if file:
        clear_gui()
        error = gs.hybrid_ciphering(username,file)
        message = tk.Label(window, text="")
        return_button = tk.Button(window, text="Return to the main menu", command=user_gui)
        if error == 0:
            message.config(text="Your encrypted file has been saved in "+file+"_encrypted !")
        elif error == 1:
            message.config(text="An error occured")
        message.pack()
        return_button.pack()

def aes_uncipher_gui():
    username = assign_username()
    file = filedialog.askopenfilename(initialdir="/", title="Select a file")
    if file:
        clear_gui()
        error = gs.hybrid_unciphering(username,file)
        message = tk.Label(window, text="")
        return_button = tk.Button(window, text="Return to the main menu", command=user_gui)
        if error == 0:
            message.config(text="Your clear file has been saved in "+file+"_uncrypted !")
        elif error == 1:
            message.config(text="An error occured")
        message.pack()
        return_button.pack()

def rsa_gen_gui():
    clear_gui()
    username = assign_username()
    name_label = tk.Label(window, text="Name of the key")
    name_entry = tk.Entry(window, text="Name")

    def rsa_gen_button():
        name = name_entry.get()
        send = 2
        error = gs.generate_rsa_key_pair(name,username,send)
        clear_gui()
        message = tk.Label(window, text="")
        return_button = tk.Button(window, text="Return to the main menu", command=user_gui)
        if error == 0:
            message.config(text="The keys have been generated")
        elif error == 1:
            message.config(text="An error occurred")
        message.pack()
        return_button.pack()

    send_button = tk.Button(window, text="Generate the keys", command=rsa_gen_button)
    name_label.pack()
    name_entry.pack()
    send_button.pack()

def send_command(command,content):
    clear_gui()
    username = assign_username()
    response = requests.post(api_url+"/command", json={'user_name': username, 'token': token, 'command': command, 'content': content}, verify=False)
    if response.status_code == 200:
        success = True
    else:
        success = False
    return success

def test_command():
    clear_gui()
    message = tk.Label(window, text="")
    return_button = tk.Button(window, text="Return to the main menu", command=user_gui)
    command = 'testRTMSG'
    content = None
    success = send_command(command,content)
    if success:
        message.config(text="Successful")
    else:
        message.config(text="Error")
    message.pack()
    return_button.pack()

def send_message_api_gui():
    username = assign_username()
    user_label = tk.Label(window, text="User")
    user_entry = tk.Entry(window)
    message_label = tk.Label(window, text="Message")
    message_entry = tk.Entry(window)
    user_label.pack()
    user_entry.pack()
    message_label.pack()
    message_entry.pack()

    def send_message_api_button():
        clear_gui()
        result = tk.Label(window, text="")
        return_button = tk.Button(window, text="Return to the main menu", command=user_gui)
        target = user_entry.get()
        message = message_entry.get()
        command = 'send_message'
        content = [username,target,message]
        success = send_command(command,content)
        if success:
            result.config(text="Message sent !")
        else:
            result.config(text="Failed !")
        result.pack()
        return_button.pack()

    user_label.pack()
    user_entry.pack()
    message_label.pack()
    message_entry.pack()
    send_button = tk.Button(window, text="Send message", command=send_message_api_button)
    send_button.pack()

def exit_rtmsg():
    exit(0)

def user_gui():
    clear_gui()
    send_button = tk.Button(window, text="Send message", command=send_message_gui)
    send_api_button = tk.Button(window, text="Send message (API)", command=send_message_api_gui)
    read_button = tk.Button(window, text="Read message", command=read_message_gui)
    invite_button = tk.Button(window, text="Invite a user", command=invite_gui)
    grant_button = tk.Button(window, text="Grant user", command=grant_user_gui)
    drop_button = tk.Button(window, text="Drop user", command=drop_user_gui)
    rtkey_button = tk.Button(window, text="RTKEY (WIP)", command=rtkey_gui)
    rsa_button = tk.Button(window, text="Generate RSA keys", command=rsa_gen_gui)
    file_button = tk.Button(window, text="Ciphering files (full RSA, up to 241 bytes)", command=file_cipher_gui)
    unfile_button = tk.Button(window, text="Unciphering files (full RSA, up to 241 bytes)", command=file_uncipher_gui)
    aes_cipher_button = tk.Button(window, text="Ciphering files (AES in RSA, unlimited size)", command=aes_cipher_gui)
    aes_uncipher_button = tk.Button(window, text="Unciphering files (AES in RSA, unlimited size)", command=aes_uncipher_gui)
    test_button = tk.Button(window, text="Test command API", command=test_command)
    logout_button = tk.Button(window, text="Logout", command=login)
    exit_button = tk.Button(window, text="Exit RTMSG", command=exit_rtmsg)
    token_label = tk.Label(window,text=token)
    send_button.pack()
    send_api_button.pack()
    read_button.pack()
    invite_button.pack()
    grant_button.pack()
    drop_button.pack()
    rtkey_button.pack()
    rsa_button.pack()
    file_button.pack()
    unfile_button.pack()
    aes_cipher_button.pack()
    aes_uncipher_button.pack()
    test_button.pack()
    token_label.pack()
    logout_button.pack()
    exit_button.pack()

def login():
    clear_gui()
    entry.pack()
    launch.pack()
    launch_api.pack()
    exit_button.pack()

def login_api():
    clear_gui()
    username = assign_username()
    url_label = tk.Label(window, text="IP")
    url_entry = tk.Entry(window, text="IP")

    def login_api_button():
        clear_gui()
        user_name = assign_username()
        global api_url
        api_url = "https://"+url_entry.get()+":5000"
        response = requests.post(api_url+"/login", json={'user_name': user_name}, verify=False)
        message = tk.Label(window, text="")
        return_button = tk.Button(window, text="Return to authentication menu", command=login)

        def decrypt_challenge(challenge_cipher_text):
            challenge_cipher_text = challenge_cipher_text.encode('latin-1')
            print(challenge_cipher_text)
            private_key_path = "private_key_"+username+".pem"
            with open(private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
            decrypted_challenge = private_key.decrypt(
                challenge_cipher_text,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(decrypted_challenge)
            return decrypted_challenge

        if response.status_code == 200:
            # Récupérer le challenge chiffré et le nom de l'utilisateur
            challenge_cipher_text = response.json()['challenge']
            print(challenge_cipher_text)

            # Déchiffrer le challenge avec la clé privée du client (à implémenter)
            decrypted_challenge = decrypt_challenge(challenge_cipher_text)

            # Envoyer la réponse au challenge à l'API
            decrypted_challenge = decrypted_challenge.decode('latin-1')
            verify_url = api_url+'/verify'
            response = requests.post(verify_url, json={'response': decrypted_challenge, 'user_name': user_name}, verify=False)

            if response.status_code == 200:
                print("Authentification réussie !")
                store_token(response.json()['token'].encode('latin-1'))
                user_gui()
            else:
                message.config(text="Server refused your authentication.")
                message.pack()
                return_button.pack()
        else:
            message.config(text="Try to authenticate failed.")
            message.pack()
            return_button.pack()

    send_button = tk.Button(window, text="Authenticate", command=login_api_button)
    return_button = tk.Button(window, text="Return to authentication menu", command=login)
    url_label.pack()
    url_entry.pack()
    send_button.pack()
    return_button.pack()

window = tk.Tk()
window.title("RTGUI for RTMSG")
window.geometry("600x600")

message = tk.Label(window, text="")

entry = tk.Entry(window, text="Login")
launch = tk.Button(window, text="Authenticate", command=call_gs)
launch_api = tk.Button(window, text="Authenticate with API (WIP)", command=login_api)
exit_button = tk.Button(window, text="Exit RTMSG", command=exit_rtmsg)
entry.pack()
launch.pack()
launch_api.pack()
exit_button.pack()

window.mainloop()
login()

