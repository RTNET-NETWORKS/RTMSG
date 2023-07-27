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
import getpass
import hashlib
import mysql.connector
import csv
import random
import string
import base64

def text_hash(text: str):
    m = hashlib.sha256()
    m.update(text.encode("utf-8"))
    return m.hexdigest()

def read_db_credentials():
    with open('db.csv', newline='') as csvfile:
        lecteur_csv = csv.reader(csvfile, delimiter=';')
        return next(lecteur_csv)  # Renvoie la première ligne

def connect_to_database():
    host, user, password, database = read_db_credentials()
    try:
        connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database
        )
        if connection.is_connected():
            print("Connexion réussie à la base de données.")
            return connection
        else:
            print("Échec de la connexion à la base de données.")
            return None
    except mysql.connector.Error as e:
        print(f"Erreur lors de la connexion à la base de données: {e}")
        return None


def register_user():
    print("/!\\")
    print("A tout moment vous pouvez annuler la création d'un utilisateur en écrivant 'sss' (les valeurs sont vérifiées à la fin des questions)")
    print("/!\\")

    register_name = input("Nom de l'utilisateur : ")
    register_pass = getpass.getpass()
    register_mail = input("E-mail de l'utilisateur : ")
    register_rank = input("Permissions de l'utilisateur : user/system/admin : ")

    # Annulation
    if register_name == "sss" or register_pass == "sss" or register_mail == "sss" or register_rank == "sss":
        print("Annulation...")
        return

    # Vérification du niveau de permissions
    if register_rank not in ["user", "system", "admin"]:
        print("Niveau de permissions incorrect ! Annulation")
        return

    # Création d'utilisateur
    register_pass = text_hash(register_pass)
    db = connect_to_database()
    if db:
        cursor = db.cursor()
        cursor.execute("INSERT INTO users (name, email, password, rank) VALUES (%s, %s, %s, %s)",
                       (register_name, register_mail, register_pass, register_rank))
        print("Utilisateur créé")
        db.commit()
        db.close()



def privilege_user():
	print("/!\\")
	print("A tout moment vous pouvez annuler la création d'un utilisateur en écrivant 'sss' (les valeurs sont vérifiées à la fin des questions)")
	print("/!\\")
	modify_name = input(str("Nom de l'utilisateur : "))
	modify_rank = input(str("Rang choisi : user/system/admin : "))
	incorrect = 0
	if modify_rank != "user" and modify_rank != "system" and modify_rank != "admin":
		print("Niveau de permissions incorrect ! Annulation")
		incorrect = 1
	if incorrect != 1:
		db = connect_to_database()
		if db:
			c = db.cursor()
			c.execute("UPDATE users SET rank = %s WHERE name = %s", (modify_rank, modify_name))
			db.commit()
			db.close()
			print("Niveau de permissions de l'utilisateur modifié")

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

def generate_rsa_key_pair(user):
    # Générer une paire de clés RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Sérialiser la clé privée au format PEM et l'enregistrer dans un fichier
    with open("private_key.pem", "wb") as f:
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
    save_public_key_to_database(user, encoded_public_key)

    return private_key_pem, public_key_pem

def generer_message_aleatoire(longueur):
	caracteres = string.ascii_letters + string.digits + string.punctuation + " "
	message = ''.join(random.choice(caracteres) for _ in range(longueur))
	return message

def save_public_key_to_database(username, encoded_public_key):
    # Établir la connexion à la base de données
    db = connect_to_database()
    if db:
        c = db.cursor()

        # Exécuter la requête SQL pour insérer la clé publique dans la base de données
        query = "INSERT INTO users (user, clef) VALUES (%s, %s)"
        c.execute(query, (username, encoded_public_key))

        # Valider la transaction et fermer le curseur et la connexion
        db.commit()
        c.close()
        db.close()

def load_public_key_from_database(username):
    # Établir la connexion à la base de données
    db = connect_to_database()
    if db:
        cursor = db.cursor()

        # Exécuter la requête SQL pour récupérer la clé publique
        query = "SELECT clef FROM users WHERE user = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()

        # Fermer le curseur et la connexion
        cursor.close()
        db.close()

        if result:
            encoded_public_key = result[0]
            decoded_public_key = base64.b64decode(encoded_public_key)
            public_key = serialization.load_pem_public_key(decoded_public_key, backend=default_backend())
            return public_key
        else:
            return None
        
# Ajout de la fonction encrypt_message_with_public_key
def encrypt_message_with_public_key(public_key, message):
    return public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def dial():
    print("\nBienvenue sur GS ! Identifiez-vous")
    user = input("Utilisateur : ")

    db = connect_to_database()
    if db:
        c = db.cursor()

        public_key = load_public_key_from_database(user)
        if public_key is not None:
            print("Clef publique identifiée")
            print("Vous allez devoir résoudre un challenge pour vous authentifier\n")

            longueur_message = 32
            message_to_encrypt = generer_message_aleatoire(longueur_message)
            encrypted_message = encrypt_message_with_public_key(public_key, message_to_encrypt)

            print("Message chiffré :", base64.b64encode(encrypted_message).decode(), "\n")
            decrypted_message = input("Déchiffrez ce message avec votre clef privée : ")

            if decrypted_message == message_to_encrypt:
                print("\nAuthentification réussie !\n")
            else:
                print("Authentification échouée !")
                exit(2)
        else:
            print("Clef introuvable pour cet utilisateur")
            exit(2)
        c.close()
        db.close()

    while True:
        print("\nOptions disponibles :\n")
        print("exit : quitter le programme")
        print("logout : se déconnecter")
        print("rsa : générerer une paire de clefs RSA")
        print("register : enregistrer un nouvel utilisateur")
        print("privilege : modifier le rang d'un utilisateur\n")

        query = input("># ")
        if query in ["exit", "quit"]:
            print("\nAu revoir !")
            exit(0)
        elif query == "logout":
            print("\nDéconnexion...")
            dial()
        elif query == "register":
            register_user()
        elif query == "privilege":
            privilege_user()
        elif query == "rsa":
            user_rsa = input("Lier la clef à quel utilisateur : ")
            generate_rsa_key_pair(user_rsa)
        else:
            print("Commande non-reconnue")


dial()
