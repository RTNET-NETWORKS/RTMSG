# RTMSG
All the tools to use RTMSG, the message and ciphering utility tool made by RTNET

With RTMSG, you will be able to send messages to others users, while ciphering with their public keys. Every cipher operation is made by your client, on your computer.

Public keys are sent and stored to a database, where every user can access, so they can cipher messages with their peer's public key.

Public keys are also used for authentication.

You can also cipher files on your computer using your keys.

###### Current functionnalities ######
Sending secure mails
Managing mails
RTKEY, the password keeper
Create temporary codes for new users, in order to let them export their key on their own
Permissions levels on users (to grant, delete or invite new users)
Ciphering and unciphering messages
Ciphering and unciphering files

###### Dependencies #####
Python3
Python3-cryptography
Python3-pymysql
Python3-tkinter
Python3-flask
Python3-argparse
Python3-os
Python3-csv
Python3-random
Python3-base64
Python3-string
Python3-jwt
Python3-requests

##### Server instructions #####
Create a CSV file nammed "db.csv", in which you will enter four fields delimited by ";" : DB address, DB user, DB password, DB

To create the database, just import the .sql file, and you will be able to access RTMSG via the "admin" user.
Be sure to delete this one later !

Enjoy !

##### Client instructions #####
After an administrator gave you an invitation code, launch rtgui.py, type your username, and go to "Enter activation code".
It will create a key pair, and you will be able to log !

If you use the new API, be sure to log with "Authenticate with API"
