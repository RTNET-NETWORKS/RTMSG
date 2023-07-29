# RTMSG
Logiciels clients et serveurs pour utiliser le service RTMSG

Cet utilitaire a pour but de permettre à l'utilisateur de se connecter et d'accéder à diverses ressources lui permettant d'utiliser la méthode de télécommunications alternative RTMSG.

----- Paquets nécessaires -----
-Python3
-Python3-cryptography
-Python3-pymysql

----- Instructions -----
-Créez un fichier csv nommé "db.csv", dans lequel vous entrerez quatre champs séparés par des ";" dans l'ordre respectif : Adresse de la BDD, utilisateur de la BDD, mot de passe de la BDD, BDD
-Lancer deux terminaux (ou utilisez screen), lancez gs.py, entrez votre nom d'utilisateur, le programme récupèrera votre clef publique dans la BDD et chiffrera un message aléatoire de 32 caractères avec cette clef.
-Lancez decrypt.gs, indiquez le chemin de votre clef privée, et collez le message chiffré, et le programme vous renverra le résultat déchiffré. Collez ce résultat dans l'invite du premier programme.
-Profitez !
