#!/usr/bin/python3

# Programme créé pour la gestion simplifiée de l'infrastructure système de RTNET

# ChatGPT a été d'une grande aide pour la création de ce programme. Merci à lui !
# Créé par Emerick ROMAN, emerick@rtnet.Fr

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64

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

def main():
    # Chemin vers le fichier PEM contenant la clé privée
    private_key_path = "private_key.pem"

    # Demander à l'utilisateur de copier-coller le message chiffré
    encrypted_message = input("Collez le message chiffré (base64) ici : ")

    try:
        # Déchiffrer le message avec la clé privée
        decrypted_message = decrypt_message_with_private_key(private_key_path, encrypted_message)

        # Afficher le message déchiffré
        print("Message déchiffré :", decrypted_message)
    except Exception as e:
        print("Erreur lors du déchiffrement :", e)

if __name__ == '__main__':
    main()