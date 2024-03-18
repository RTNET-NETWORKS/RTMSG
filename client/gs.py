#!/usr/bin/python3

# Programme créé pour la gestion simplifiée de l'infrastructure système de RTNET
# Fork de GS pour RTMSG

# ChatGPT a été d'une grande aide pour la création de ce programme. Merci à lui !
# Créé par Emerick ROMAN, emerick@rtnet.Fr

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import os
import hashlib
import pymysql
import csv
import random
import string
import base64
import socket
import select
import sys

def text_hash(text : str):
	m = hashlib.sha256()
	m.update(text.encode("utf-8"))
	return m.hexdigest()

def sql_conn():
	donnees = []
	with open('db.csv', newline='') as csvfile:
		lecteur_csv = csv.reader(csvfile, delimiter=';')
		for row in lecteur_csv:
			donnees.append(row)
	db=pymysql.connect(host=donnees[0][0], charset="utf8",user=donnees[0][1], passwd=donnees[0][2],db=donnees[0][3])
	return db

def generate_rsa_key_pair():
	# Générer une paire de clés RSA
	private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
		backend=default_backend()
	)
	with open("private_key.pem", "wb") as f:
		private_key_pem = private_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption()
		)
		f.write(private_key_pem)
    # Obtenir la clé publique
	public_key = private_key.public_key()

    # Sérialiser la clé privée au format PEM
	private_key_pem = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	)

	# Sérialiser la clé publique au format PEM
	public_key_pem = public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)

	return private_key_pem, public_key_pem

def generate_rsa_key_pair(user_t,user,send):
	# Générer une paire de clés RSA
	private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
		backend=default_backend()
	)
	public_key = private_key.public_key()

	# Sérialiser la clé privée au format PEM et l'enregistrer dans un fichier
	with open("private_key_"+user_t+".pem", "wb") as f:
		private_key_pem = private_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption()
		)
		f.write(private_key_pem)

	# Sérialiser la clé publique au format PEM
	public_key_pem = public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)

    # Encoder la clé publique en base64 avant de l'enregistrer dans la base de données
	encoded_public_key = base64.b64encode(public_key_pem).decode()

	# Enregistrer la clé publique dans la base de données (remplacez "user1" par le nom d'utilisateur approprié)
	if send == 0:
		print("Clef privée :")
		print(private_key_pem.decode())
		print("")
		print("Clef publique :")
		print(public_key_pem.decode())
	elif send == 2:
		with open("public_key_"+user_t+".pem", "wb") as f:
			f.write(public_key_pem)
		error = 0
		return error
	else:
		save_public_key_to_database(user, encoded_public_key, user_t)

	return private_key_pem, public_key_pem

def generer_message_aleatoire(longueur):
	caracteres = string.ascii_letters + string.digits + string.punctuation + " "
	message = ''.join(random.choice(caracteres) for _ in range(longueur))
	return message

def save_public_key_to_database(username, encoded_public_key, user_t):
	# Établir la connexion à la base de données
	db = sql_conn()
	c = db.cursor()
	c.execute("select user from users where user = '"+user_t+"';")
	print("")
	if c.fetchone():
		print("Utilisateur existant")
		query = "UPDATE users SET clef = %s WHERE user = %s"
		c.execute(query, (encoded_public_key, user_t))
		c.execute("insert into operation values (DEFAULT, '"+username+"','change_key','"+user_t+"',DEFAULT);")
	else:
		# Exécuter la requête SQL pour insérer la clé publique dans la base de données
		query = "INSERT INTO users (user, clef) VALUES (%s, %s)"
		c.execute(query, (user_t, encoded_public_key))
		c.execute("insert into operation values (DEFAULT, '"+username+"','register_user','"+user_t+"',DEFAULT);")
	# Valider la transaction et fermer le curseur et la connexion
	db.commit()
	c.close()
	db.close()

def load_public_key_from_database(username):
	# Établir la connexion à la base de données
	connection = sql_conn()
	cursor = connection.cursor()

	# Exécuter la requête SQL pour récupérer la clé publique
	query = "SELECT clef FROM users WHERE user = %s"
	cursor.execute(query, (username,))
	result = cursor.fetchone()

	# Fermer le curseur et la connexion
	cursor.close()
	connection.close()

	if result:
		encoded_public_key = result[0]

		# Décoder la clé publique depuis la base64
		decoded_public_key = base64.b64decode(encoded_public_key)

		# Charger la clé publique depuis le format PEM
		public_key = serialization.load_pem_public_key(decoded_public_key, backend=default_backend())

		return public_key
	else:
		return None

def encrypt_message_with_public_key(public_key, message):
	# Chiffrer le message avec la clé publique
	encrypted_message = public_key.encrypt(
		message.encode(),
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)
	return encrypted_message

def user_grant(user,user_g,level):
	db = sql_conn()
	c = db.cursor()
	user = str(user)
	c.execute("select user from users where user = '"+user_g+"';")
	error = 0
	if not c.fetchone():
		print("Utilisateur inconnu")
		c.execute("insert into operation values (DEFAULT, '"+user+"','forbidden','"+user_g+"',DEFAULT);")
		db.commit()
		c.close()
		db.close()
		error = 1
		return error
	c.execute("select user, level from admin where user = '"+user+"';")
	result = c.fetchone()
	if result:
		levelint = int(level)
		if levelint < 1 or levelint > 3:
			print("Opération refusée : niveau d'accès invalide")
			c.execute("insert into operation values (DEFAULT, '"+user+"','forbidden','"+user_g+"',DEFAULT);")
			db.commit()
			c.close()
			db.close()
			error = 2
			return error
		if int(result[1]) == 4:
			c.execute("select user, level from admin where user = '"+user_g+"';")
			result = c.fetchone()
			if result:
				if int(result[1]) == 4:
					print("Opération refusée : l'utilisateur est déjà administrateur")
					c.execute("insert into operation values (DEFAULT, '"+user+"','forbidden','"+user_g+"',DEFAULT);")
					db.commit()
					c.close()
					db.close()
					error = 2
					return error
				else:
					c.execute("update admin set level = "+level+" where user = '"+user_g+"';")
					c.execute("insert into operation values (DEFAULT, '"+user+"','grant','"+user_g+"',DEFAULT);")
					db.commit()
					c.close()
					db.close()
					error = 0
					return error
			else:
				c.execute("insert into admin values (DEFAULT,'"+user_g+"',"+level+",DEFAULT,DEFAULT);")
				c.execute("insert into operation values (DEFAULT, '"+user+"','grant','"+user_g+"',DEFAULT);")
				db.commit()
				c.close()
				db.close()
				error = 0
				return error
		else:
			print("Opération refusée")
			c.execute("insert into operation values (DEFAULT, '"+user+"','forbidden','"+user_g+"',DEFAULT);")
			db.commit()
			c.close()
			db.close()
			error = 2
			return error
	else:
		print("Opération refusée")
		c.execute("insert into operation values (DEFAULT, '"+user+"','forbidden','"+user_g+"',DEFAULT);")
		db.commit()
		c.close()
		db.close()
		error = 2
		return error
	db.commit()
	c.close()
	db.close()
	print("")

def send_message(user,target,message):
	db = sql_conn()
	c = db.cursor()
	print(user)
	print(target)
	print(message)
	c.execute("select clef from users where user = '"+target+"';")
	result = c.fetchone()
	if result is None:
		c.execute("insert into operation values (DEFAULT, '"+user+"','bad_target','"+target+"',DEFAULT);")
		unknown_user = 1
		return unknown_user
	else:
		public_key_encoded = result[0]
		decoded_public_key = base64.b64decode(public_key_encoded)
		public_key = serialization.load_pem_public_key(decoded_public_key, backend=default_backend())
		encrypted_message = encrypt_message_with_public_key(public_key, message)
#		print("Message chiffré :", base64.b64encode(encrypted_message).decode())
		c.execute("insert into operation values (DEFAULT, '"+user+"','send_message','"+target+"',DEFAULT);")
		c.execute("insert into messages values (DEFAULT, '"+user+"','"+target+"','"+base64.b64encode(encrypted_message).decode()+"',DEFAULT);")
	db.commit()
	c.close()
	db.close()

def read_message(user,read):
	db = sql_conn()
	c = db.cursor()
	if not read:
		c.execute("select user from users where user = '"+user+"';")
		result = c.fetchone()
		if result:
			fini = 0
			messages = []
			while fini != 1:
				c.execute("select * from messages where target = '"+user+"' and message_read = 0;")
				result = c.fetchone()
				if result:
					message_decode = decrypt_message_with_private_key("private_key_"+user+".pem", result[3])
					final = "Message de "+result[1]+" : "+message_decode
					c.execute("update messages set message_read = 1 where id = "+str(result[0])+";")
					messages.append(final)
				else:
					fini = 1
	else:
		c.execute("select user from users where user = '"+user+"';")
		result = c.fetchone()
		messages = []
		if result:
			c.execute("select * from messages where target = '"+user+"' and message_read = 1;")
			result = c.fetchall()
			if result:
				for message_individuel in result:
					message_decode = decrypt_message_with_private_key("private_key_"+user+".pem", message_individuel[3])
					final ="Message de "+message_individuel[1]+" : "+message_decode
					messages.append(final)
	db.commit()
	c.close()
	db.close()
	return messages

def decrypt_message_with_private_key(private_key_path, encrypted_message):
    # Charger la clé privée depuis le fichier PEM
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Décoder le message chiffré depuis la base64
    decoded_encrypted_message = base64.b64decode(encrypted_message)

    # Déchiffrer le message avec la clé privée
    decrypted_message = private_key.decrypt(
        decoded_encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_message.decode()

def drop_user(user,target):
	db = sql_conn()
	c = db.cursor()
	c.execute("select level from admin where user = '"+user+"';")
	result = c.fetchone()
	if result is None:
		print("Opération refusée")
		c.execute("insert into operation values (DEFAULT, '"+user+"','forbidden','"+target+"',DEFAULT);")
		db.commit()
		c.close()
		db.close()
		error = 2
		return error
	else:
		if int(result[0]) == 4:
			c.execute("select user from users where user = '"+target+"';")
			result = c.fetchone()
			if result:
				c.execute("select level from admin where user = '"+target+"';")
				result = c.fetchone()
				if result is None:
					c.execute("delete from users where user = '"+target+"';")
					c.execute("insert into operation values (DEFAULT, '"+user+"','drop_user','"+target+"',DEFAULT);")
					print("Utilisateur supprimé")
					db.commit()
					c.close()
					db.close()
					error = 0
					return error
				elif int(result[0]) == 4:
					print("Opération refusée : vous ne pouvez pas supprimer un administrateur")
					c.execute("insert into operation values (DEFAULT, '"+user+"','forbidden','"+target+"',DEFAULT);")
					db.commit()
					c.close()
					db.close()
					error = 2
					return error
				else:
					c.execute("delete from users where user = '"+target+"';")
					c.execute("delete from admin where user = '"+target+"';")
					c.execute("insert into operation values (DEFAULT, '"+user+"','drop_user','"+target+"',DEFAULT);")
					print("Utilisateur supprimé")
					db.commit()
					c.close()
					db.close()
					error = 0
					return error
			else:
				print("Utilisateur inconnu")
				c.execute("insert into operation values (DEFAULT, '"+user+"','bad_target','"+target+"',DEFAULT);")
				db.commit()
				c.close()
				db.close()
				error = 1
				return error
		else:
			print("Opération refusée")
			c.execute("insert into operation values (DEFAULT, '"+user+"','forbidden','"+target+"',DEFAULT);")
			db.commit()
			c.close()
			db.close()
			error = 2
			return error

def real_time(user):
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	IP_srv = str(input("Adresse IP du serveur : "))
	Port_srv = int(input("Port du serveur : "))
	target = str(input("Utilisateur : "))
	public_key = load_public_key_from_database(target)
	server.connect((IP_srv, Port_srv))
	comm = 0
	while comm == 0:
 
	# maintains a list of possible input streams
		sockets_list = [sys.stdin, server]
		read_sockets,write_socket, error_socket = select.select(sockets_list,[],[])
 
		for socks in read_sockets:
			if socks == server:
				message = socks.recv(2048)
				print(message.decode())
			else:
				message = sys.stdin.readline()
				if message == "exit" or message == "quit":
					server.close()
					comm = 1
				encrypted_message = encrypt_message_with_public_key(public_key, message)
				server.send(encrypted_message)
				sys.stdout.write("<You>")
				sys.stdout.write(message)
				sys.stdout.flush()
	server.close()

def file_cipher(user,file):
	db = sql_conn()
	c = db.cursor()
	c.execute("select clef from users where user = '"+user+"';")
	result = c.fetchone()
	if result is None:
		c.execute("insert into operation values (DEFAULT, '"+user+"','bad_target','"+user+"',DEFAULT);")
		db.commit()
		c.close()
		db.close()
		unknown_user = 1
		return unknown_user
	else:
		public_key_encoded = result[0]
		decoded_public_key = base64.b64decode(public_key_encoded)
		public_key = serialization.load_pem_public_key(decoded_public_key, backend=default_backend())

	bloc_size = 256
	encrypted_data = b""
	with open(file, "rb") as f:
		clear_data = f.read(bloc_size)
	encrypted_data += public_key.encrypt(
        clear_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
	encrypted_file = file+"_encrypted"
	with open(encrypted_file, "wb") as f:
		f.write(encrypted_data)
	db.commit()
	c.close()
	db.close()
	unknown_user = 0
	return unknown_user

def file_uncipher(user,file):
	private_key = "private_key_"+user+".pem"
	with open(private_key, "rb") as private_key_file:
		private_key_bytes = private_key_file.read()
		private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=None,
            backend=default_backend()
        )
	bloc_size = 256
	clear_data = b""
	with open(file, "rb") as f:
		while True:
			encrypted_data = f.read(bloc_size)
			if not encrypted_data:
				break
			clear_data += private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

	clear_file = file+"_clear"
	with open(clear_file, "wb") as f:
		f.write(clear_data)

	error = 0
	return error

def rtkey(user,choice,name,passwd):
	if choice == "s":
		db = sql_conn()
		c = db.cursor()
		c.execute("select clef from users where user = '"+user+"';")
		result = c.fetchone()
		if result:
			public_key_encoded = result[0]
			decoded_public_key = base64.b64decode(public_key_encoded)
			public_key = serialization.load_pem_public_key(decoded_public_key, backend=default_backend())
			send_passwd = encrypt_message_with_public_key(public_key, passwd)
			# Envoyer à la base de données le mot de passe chiffré
			c.execute("insert into passwd values (DEFAULT, '"+user+"',DEFAULT,'"+base64.b64encode(send_passwd).decode()+"','"+name+"');")
			c.execute("insert into operation values (DEFAULT, '"+user+"','rtkey_send_passwd','"+user+"',DEFAULT);")
			print("Mot de passe envoyé")
			db.commit()
			c.close()
			db.close()
	elif choice == "C" or choice == "c":
		print("Liste des mots de passes :")
		print("")
		db = sql_conn()
		c = db.cursor()
		c.execute("select name from passwd where user = '"+user+"';")
		resultat = c.fetchall()
		for i in resultat:
			print(i[0])
		print("")
		choix = str(input("Choix : "))
		print("")
		c.execute("select clef from users where user = '"+user+"';")
		result = c.fetchone()
		if result:
			public_key_encoded = result[0]
			decoded_public_key = base64.b64decode(public_key_encoded)
			public_key = serialization.load_pem_public_key(decoded_public_key, backend=default_backend())
			c.execute("select password from passwd where user = '"+user+"' and name = '"+choix+"';")
			result = c.fetchone()
			if result:
				decrypted_message = decrypt_message_with_private_key("private_key_"+user+".pem", result[0])
				print("Mot de passe : "+decrypted_message)
				c.execute("insert into operation values (DEFAULT, '"+user+"','rtkey_check_passwd','"+user+"',DEFAULT);")
			else:
				print("Mot de passe introuvable")
				c.execute("insert into operation values (DEFAULT, '"+user+"','rtkey_bad_passwd','"+user+"',DEFAULT);")
		c.execute("insert into operation values (DEFAULT, '"+user+"','rtkey_check_passwd','"+user+"',DEFAULT);")
		db.commit()
		c.close()
		db.close()
	elif choice == "R" or choice == "r":
		print("Liste des mots de passes :")
		print("")
		db = sql_conn()
		c = db.cursor()
		c.execute("select name from passwd where user = '"+user+"';")
		resultat = c.fetchall()
		for i in resultat:
			print(i[0])
		print("")
		choix = str(input("Choix : "))
		print("")
		c.execute("select clef from users where user = '"+user+"';")
		result = c.fetchone()
		if result:
			public_key_encoded = result[0]
			decoded_public_key = base64.b64decode(public_key_encoded)
			public_key = serialization.load_pem_public_key(decoded_public_key, backend=default_backend())
			c.execute("select password from passwd where user = '"+user+"' and name = '"+choix+"';")
			result = c.fetchone()
			if result:
				decrypted_message = decrypt_message_with_private_key("private_key_"+user+".pem", result[0])
				print("Mot de passe : "+decrypted_message)
				c.execute("insert into operation values (DEFAULT, '"+user+"','rtkey_check_passwd','"+user+"',DEFAULT);")
				choix2 = str(input("Supprimer ? O/N : "))
				print("")
				if choix2 == "O" or choix2 == "o":
					c.execute("delete from passwd where user = '"+user+"' and name = '"+choix+"';")
					c.execute("insert into operation values (DEFAULT, '"+user+"','rtkey_delete_passwd','"+user+"',DEFAULT);")
					print("Mot de passe supprimé")
				else:
					print("Opération annulée")
			else:
				print("Mot de passe introuvable")
				c.execute("insert into operation values (DEFAULT, '"+user+"','rtkey_bad_passwd','"+user+"',DEFAULT);")
		c.execute("insert into operation values (DEFAULT, '"+user+"','rtkey_check_passwd','"+user+"',DEFAULT);")
		db.commit()
		c.close()
		db.close()

def generate_aes_key():
	return os.urandom(32)

def aes_cipher(key,data):
	iv = os.urandom(16)
	cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	encrypted_data = encryptor.update(data) + encryptor.finalize()
	return iv + encrypted_data

def aes_uncipher(key,encrypted_data):
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    data = decryptor.update(encrypted_data) + decryptor.finalize()
    return data

def hybrid_ciphering(user,file):
	secret_key = generate_aes_key()
	db = sql_conn()
	c = db.cursor()
	c.execute("select clef from users where user = '"+user+"';")
	result = c.fetchone()
	if result is None:
		c.execute("insert into operation values (DEFAULT, '"+user+"','bad_target','"+user+"',DEFAULT);")
		db.commit()
		c.close()
		db.close()
		unknown_user = 1
		return unknown_user
	else:
		public_key_encoded = result[0]
		decoded_public_key = base64.b64decode(public_key_encoded)
		public_key = serialization.load_pem_public_key(decoded_public_key, backend=default_backend())
	
	with open(file, "rb") as f:
		clear_data = f.read()
	aes_data = aes_cipher(secret_key,clear_data)

	secret_key_encrypted = public_key.encrypt(
		secret_key,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
        )
    )

	encrypted_file = file+"_encrypted"
	with open(encrypted_file, "wb") as f:
		f.write(secret_key_encrypted+aes_data)

	db.commit()
	c.close()
	db.close()
	unknown_user = 0
	return unknown_user

def hybrid_unciphering(user,file):
	private_key = "private_key_"+user+".pem"
	with open(private_key, "rb") as private_key_file:
		private_key_bytes = private_key_file.read()
		private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=None,
            backend=default_backend()
        )
	
	with open(file, "rb") as f:
		secret_key_encrypted = f.read(256)
		aes_data = f.read()

	secret_key = private_key.decrypt(
		secret_key_encrypted,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
        )
    )

	clear_data = aes_uncipher(secret_key,aes_data)

	clear_file = file+"_unencrypted"
	with open(clear_file, "wb") as f:
		f.write(clear_data)

	error = 0
	return error

def invite(user,target):
	# Vérifier le niveau de permission de l'utilisateur
	db = sql_conn()
	c = db.cursor()
	c.execute("select level from admin where user = '"+user+"';")
	result = c.fetchone()
	error = 0
	if result:
		if int(result[0]) >= 3:
			# Vérifier si l'utilisateur existe déjà
			c.execute("select user from users where user = '"+target+"';")
			result = c.fetchone()
			if result:
				print("Utilisateur déjà existant")
				c.execute("insert into operation values (DEFAULT, '"+user+"','bad_invitation','"+target+"',DEFAULT);")
				error = 1
			else:
				c.execute("select target from invitation where target = '"+target+"';")
				result = c.fetchone()
				if result:
					print("Utilisateur déjà invité")
					c.execute("insert into operation values (DEFAULT, '"+user+"','bad_invitation','"+target+"',DEFAULT);")
					error = 2
				else:
        			# Générer un code d'invitation aléatoire
					code = generer_message_aleatoire(6)
					c.execute("insert into invitation values (DEFAULT,'"+user+"','"+target+"','"+code+"')")
					c.execute("insert into operation values (DEFAULT, '"+user+"','invitation','"+target+"',DEFAULT);")
					final = "Code d'invitation créé : "+code
					db.commit()
					c.close()
					db.close()
					return final
		else:
			print("Opération refusée")
			c.execute("insert into operation values (DEFAULT, '"+user+"','forbidden','"+target+"',DEFAULT);")
			error = 3
	else:
		print("Opération refusée")
		c.execute("insert into operation values (DEFAULT, '"+user+"','forbidden','"+target+"',DEFAULT);")
		error = 4
	print("")
	db.commit()
	c.close()
	db.close()
	return error

def verify_invite(user,invite):
	db = sql_conn()
	c = db.cursor()
	c.execute("select code from invitation where target = '"+user+"';")
	result = c.fetchone()
	if result:
		if result[0] == invite:
			print("Code valide")
			c.execute("delete from invitation where target = '"+user+"';")
			send = 1
			generate_rsa_key_pair(user,user,send)
			error = 0
			db.commit()
			c.close()
			db.close()
			return error
		else:
			print("Code invalide")
			error = 1
			c.close()
			db.close()
			return error
	else:
		error = 2
		c.close()
		db.close()
		return 2


def auth(user):
	db = sql_conn()
	c = db.cursor()
	public_key = load_public_key_from_database(user)
	if public_key is None:
		c.execute("select target from invitation where target = '"+user+"';")
		result = c.fetchone()
		if result:
			print("Utilisateur invité")
			logged = 2
			return logged
#		print(f"Clé publique introuvable pour l'utilisateur '{user}'.")
#	c.execute("select clef from users where user = '"+user+"';")
#	result = c.fetchone()
#	if result:
#		public_key_encoded = result[0]
#		decoded_public_key = base64.b64decode(public_key_encoded)
#	public_key = serialization.load_pem_public_key(decoded_public_key, backend=default_backend())
#	message = generer_message_aleatoire(32)
#	message_chiffre = public_key.encrypt(message.encode(),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
#	receive = input(str("Déchiffrez ce message avec votre clef privée"))
#	resultat = private_key.decrypt(receive,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
	if public_key is not None:
		longueur_message = 32
		message_to_encrypt = generer_message_aleatoire(longueur_message)
		# Chiffrer le message avec la clé publique
		encrypted_message = encrypt_message_with_public_key(public_key, message_to_encrypt)
		# Afficher le message chiffré (représenté en bytes)
#		print("Message chiffré :", base64.b64encode(encrypted_message).decode())
#		print("")
		# Demander à l'utilisateur de saisir le message déchiffré
#		decrypted_message = input("Déchiffrez ce message avec votre clef privée : ")
		try:
			decrypted_message = decrypt_message_with_private_key("private_key_"+user+".pem", base64.b64encode(encrypted_message).decode())
		except Exception as e:
			print("Erreur lors du déchiffrement :", e)
			exit(2)
		if decrypted_message == message_to_encrypt:
			db = sql_conn()
			c = db.cursor()
			c.execute("insert into operation values (DEFAULT, '"+user+"','authentication',NULL,DEFAULT);")
			db.commit()
			c.close()
			db.close()
			logged = 0
			return logged
		else:
			db = sql_conn()
			c = db.cursor()
			c.execute("insert into operation values (DEFAULT, '"+user+"','failed_authentication',NULL,DEFAULT);")
			db.commit()
			c.close()
			db.close()
			logged = 1
			return logged
	else:
		logged = 1
		return logged
	c.close()
	db.close()

def dial(user):
	print("")
	while True:
		print("Options disponibles :")
		print("")
		print("exit : quitter le programme")
		print("logout : se déconnecter")
		print("rsa : générerer une paire de clefs RSA, et enregistrer dans la DB avec l'utilisateur associé, ou modifier un utilisateur existant")
		print("grant : accorder un niveau d'accès à un utilisateur")
		print("drop : supprimer un utilisateur")
		print("decrypt : déchiffrer un message quelconque avec votre clef privée ou celle d'un autre")
		print("encrypt : chiffrer un message quelconque avec une clef publique")
		print("realtime : initier une conversation en temps réel avec quelqu'un")
		print("rtkey : système de stockage sécurisé de mots de passes")
		print("invite : inviter un nouvel utilisateur à rejoindre RTMSG")
		print("send : envoyer un message à quelqu'un")
		print("read : lire les messages non-lus")
		print("")
		query = input(str("># "))
		if query == "exit" or query == "quit":
			print("")
			print("Au revoir !")
			db = sql_conn()
			c = db.cursor()
			c.execute("insert into operation values (DEFAULT, '"+user+"','deconnection',NULL,DEFAULT);")
			db.commit()
			c.close()
			db.close()
			exit(0)
		elif query == "logout":
			print("")
			print("Déconnexion...")
			db = sql_conn()
			c = db.cursor()
			c.execute("insert into operation values (DEFAULT, '"+user+"','deconnection',NULL,DEFAULT);")
			db.commit()
			c.close()
			db.close()
			auth(user)
		elif query == "rsa":
			reponse = input(str("Générer une paire de clefs RSA pour un autre utilisateur et l'exporter dans la DB ? Ou générer une paire de clefs RSA pour vous-même ? (D/V) "))
			print("")
			if reponse == "d" or reponse == "D":
				user_rsa = input(str("Lier la clef à quel utilisateur : "))
				print("")
				if user_rsa != user:
					db = sql_conn()
					c = db.cursor()
					c.execute("select user, level from admin where user = '"+user+"';")
					result = c.fetchone()
					if result:
						if int(result[1]) >= 3:
							send = 1
							generate_rsa_key_pair(user_rsa,user,send)
						else:
							print("Opération refusée")
							c.execute("insert into operation values (DEFAULT, '"+user+"','forbidden','"+user_rsa+"',DEFAULT);")
					else:
						print("Opération refusée")
						c.execute("insert into operation values (DEFAULT, '"+user+"','forbidden','"+user_rsa+"',DEFAULT);")
					print("")
					db.commit()
					c.close()
					db.close()
				else:
					send = 1
					generate_rsa_key_pair(user,user,send)
			elif reponse == "v" or reponse == "V":
				send = 0
				generate_rsa_key_pair(user,user,send)
		elif query == "grant":
			user_g = input(str("Utilisateur à promouvoir : "))
			user_grant(user,user_g)
		elif query == "send":
			send_message(user)
		elif query == "read":
			read_message(user)
		elif query == "drop":
			target = input(str("Utilisateur à supprimer : "))
			drop_user(user,target)
		elif query == "decrypt":
			print("")
			reponse = input(str("Déchiffrer avec votre clef ? y/n : "))
			if reponse == "y" or reponse == "Y":
				key = "private_key_"+user+".pem"
			else:
				key = input(str("Nom de la clef privée : "))
			print("Déchiffrement d'un message")
			print("")
			message = input(str("Message à déchiffrer : "))
			print("")
			try:
				message_decode = decrypt_message_with_private_key(key, message)
				print("Message déchiffré :", message_decode)
			except Exception as e:
				print("Erreur lors du déchiffrement :", e)
			print("")
		elif query == "encrypt":
			print("")
			reponse = input(str("Quelle clef utiliser ? La vôtre ou celle d'un autre ? y/n : "))
			db = sql_conn()
			c = db.cursor()
			if reponse == "y" or reponse == "Y":
				c.execute("select clef from users where user = '"+user+"';")
				result = c.fetchone()
				if result:
					public_key_encoded = result[0]
					decoded_public_key = base64.b64decode(public_key_encoded)
					public_key = serialization.load_pem_public_key(decoded_public_key, backend=default_backend())
					message = input(str("Message à chiffrer : "))
					print("")
					encrypted_message = encrypt_message_with_public_key(public_key, message)
					print("Message chiffré :", base64.b64encode(encrypted_message).decode())
					print("")
				else:
					print("Clef introuvable")
			else:
				target = input(str("Utilisateur : "))
				c.execute("select clef from users where user = '"+target+"';")
				result = c.fetchone()
				if result:
					public_key_encoded = result[0]
					decoded_public_key = base64.b64decode(public_key_encoded)
					public_key = serialization.load_pem_public_key(decoded_public_key, backend=default_backend())
					message = input(str("Message à chiffrer : "))
					print("")
					encrypted_message = encrypt_message_with_public_key(public_key, message)
					print("Message chiffré :", base64.b64encode(encrypted_message).decode())
					print("")
				else:
					print("Clef introuvable")
			print("")
		elif query == "realtime":
			real_time(user)
		elif query == "rtkey":
			rtkey(user)
		elif query == "invite":
			target = input(str("Utilisateur à inviter : "))
			invite(user,target)
		else:
			print("")
			print("Commande inconnue")

#auth()
