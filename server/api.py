#!/usr/bin/python3

# This script intends to provide an API for the access to the database
# The legacy way for RTMSG to work was to give a direct access to the database, with the credentials

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import jwt

app = Flask(__name__)

with open("api_public_key.pem", "rb") as key_file:
    api_public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=None
    )

# Clé privée de l'API (utilisée pour signer les tokens)
with open("api_private_key.pem", "rb") as key_file:
    api_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=None
    )

# Fonction pour générer un token d'authentification
def generate_token(user_id):
    payload = {'user_id': user_id}
    token = jwt.encode(payload, api_private_key, algorithm='RS256')
    return token

# Fonction pour vérifier et décoder un token
def decode_token(token):
    try:
        payload = jwt.decode(token, api_public_key, algorithms=['RS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Route pour l'authentification des utilisateurs
@app.route('/login', methods=['POST'])
def login():
    # Ici, vous vérifiez les informations d'authentification de l'utilisateur (par exemple, la clé publique)
    user_public_key = request.json.get('public_key')
    if user_public_key is not None:
        # Authentification réussie, générez un token d'authentification
        token = generate_token(user_public_key)
        return jsonify({'token': token.decode('utf-8')})
    else:
        return jsonify({'message': 'Authentication failed'}), 401

# Route pour les requêtes des utilisateurs authentifiés
@app.route('/request_data', methods=['GET'])
def request_data():
    token = request.headers.get('Authorization')
    if token is not None:
        token = token.split(' ')[1]  # Extraction du token de l'en-tête
        payload = decode_token(token)
        if payload is not None:
            user_id = payload['user_id']
            # Ici, vous traitez la requête de l'utilisateur (par exemple, accès à la base de données)
            return jsonify({'message': f'Request data for user {user_id}'})
        else:
            return jsonify({'message': 'Invalid or expired token'}), 401
    else:
        return jsonify({'message': 'Token is missing'}), 401

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # Exécution de l'API en mode HTTPS