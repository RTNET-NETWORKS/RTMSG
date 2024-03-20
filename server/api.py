#!/usr/bin/python3

# This script intends to provide an API for the access to the database
# The legacy way for RTMSG to work was to give a direct access to the database, with the credentials

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import argparse
import os
import csv
import jwt
import pymysql
import base64

def sql_conn():
	donnees = []
	with open('db.csv', newline='') as csvfile:
		lecteur_csv = csv.reader(csvfile, delimiter=';')
		for row in lecteur_csv:
			donnees.append(row)
	db=pymysql.connect(host=donnees[0][0], charset="utf8",user=donnees[0][1], passwd=donnees[0][2],db=donnees[0][3])
	return db

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

app = Flask(__name__)

challenges = {}
tokens = {}

with open("public_key_api.pem", "rb") as key_file:
    api_public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=None
    )

with open("private_key_api.pem", "rb") as key_file:
    api_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=None
    )

def generate_random():
	return os.urandom(32)

def generate_token(username):
     token = generate_random()
     tokens[username] = token
     return token

def get_token(username):
	if username in tokens:
		return tokens.get(username)

def remove_token(username):
     if username in tokens:
          del tokens[username]
          return True
     return False

# Fonction pour générer un challenge aléatoire et le chiffrer avec la clé publique de l'utilisateur
def generate_random_and_encrypt(user_public_key):
    challenge = generate_random()
    cipher_text = user_public_key.encrypt(
        challenge,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return challenge, cipher_text

def store_challenge(username,challenge):
    challenges[username] = challenge
    return challenge

def remove_challenge(username):
    if username in challenges:
        del challenges[username]
        return True
    return False

def find_challenge_by_username(username):
    return challenges.get(username)

def get_challenge(username):
    return challenges.get(username)

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

def send_message(content):
	user = content[0]
	target = content[1]
	message = content[2]
	db = sql_conn()
	c = db.cursor()
	c.execute("select clef from users where user = '"+target+"';")
	result = c.fetchone()
	if result is None:
		c.execute("insert into operation values (DEFAULT, '"+user+"','bad_target','"+target+"',DEFAULT);")
		unknown_user = True
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
	unknown_user = False
	return unknown_user

@app.route('/login', methods=['POST'])
def login():
    user_name = request.json.get('user_name')
    if user_name is not None:
        print("User trouvé !")
        # Récupérer la clé publique de l'utilisateur à partir de son nom dans la base de données
        user_public_key = load_public_key_from_database(user_name)
        if user_public_key is not None:
            print("Clef trouvée")
            # Générer un challenge aléatoire et le chiffrer avec la clé publique de l'utilisateur
            challenge = os.urandom(32)
            store_challenge(user_name,challenge)
            print(challenge)
            cipher_text = user_public_key.encrypt(
                challenge,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(cipher_text)
            return jsonify({'challenge': cipher_text.decode('latin-1'), 'user_name': user_name})
        else:
            print("User pas trouvé")
            return jsonify({'message': 'User not found'}), 404
    else:
        print("y'a pas de user")
        return jsonify({'message': 'User name is missing'}), 400

# Route pour vérifier la réponse au challenge
@app.route('/verify', methods=['POST'])
def verify():
    user_response = request.json.get('response')
    user_name = request.json.get('user_name')
    user_response = user_response.encode('latin-1')
    if user_response is not None and user_name is not None:
        # Récupérer la clé publique de l'utilisateur à partir de son nom dans la base de données
        user_public_key = load_public_key_from_database(user_name)
        if user_public_key is not None:
            # Vérifier si la réponse correspond au challenge original
            print(find_challenge_by_username(user_name))
            print("response")
            print(user_response)
            if user_response == find_challenge_by_username(user_name):
                print("User authentifié !")
                remove_challenge(user_name)
                remove_token(user_name)
                token = generate_token(user_name).decode('latin-1')
                return jsonify({'message': 'Authentication successful', 'token': token})
            else:
                return jsonify({'message': 'Authentication failed'}), 401
        else:
            return jsonify({'message': 'User not found'}), 404
    else:
        return jsonify({'message': 'Response or user name is missing'}), 400

@app.route('/command', methods=['POST'])
def command():
	user = request.json.get('user_name')
	token = request.json.get('token')
	command = request.json.get('command')
	content = request.json.get('content')
	token_t = get_token(user)
	print(token_t)
	token = token.encode('latin-1')
	print("User : "+user)
	print("Token : "+token)
	print("Command : "+command)
	if content is not None:
		print("Content : "+content)
	else:
		print("No content")
	if token_t == token:
		if command == "send_message":
			result = send_message(content)
			if result:
				print("Error sending message")
				return jsonify({'message': 'Error'}), 401
			else:
				return jsonify({'message': 'Successful'})
		elif command == "testRTMSG":
			print("Test Ok")
			return jsonify({'message': 'Successful'})
	else:
		return jsonify({'message': 'Error'}), 401

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run Flask API with custom IP address')
    parser.add_argument('ip_address', type=str, help='IP address to listen on')
    args = parser.parse_args()

    ip_address = args.ip_address

    app.run(host=ip_address, ssl_context='adhoc')