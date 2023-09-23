# RTMSG
Logiciels clients et serveurs pour utiliser le service RTMSG

Cet utilitaire a pour but de permettre à l'utilisateur de se connecter et d'accéder à diverses ressources lui permettant d'utiliser la méthode de télécommunications alternative RTMSG.

###### Fonctionnalités disponibles ######
Envoi de courriels chiffrés
Lecture et gestion des courriels reçus
RTKEY, utilitaire de gestion de mots de passes
Création de codes d'invitations pour nouveaux utilisateurs
Gestion des permissions des utilisateurs
Chiffrement et déchiffrement de messages avec des clefs

###### Paquets nécessaires #####
Python3
Python3-cryptography
Python3-pymysql

##### Instructions #####
Créez un fichier csv nommé "db.csv", dans lequel vous entrerez quatre champs séparés par des ";" dans l'ordre respectif : Adresse de la BDD, utilisateur de la BDD, mot de passe de la BDD, BDD
Assurez-vous de placer votre clef privée dans le même répertoire que le programme et de la nommer "private_key_USER.pem"
Lancez le programme, entrez votre nom d'utilisateur, et vous serez connecté
Profitez !
