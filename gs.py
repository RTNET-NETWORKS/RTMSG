#!/usr/bin/python3

# Programme créé pour la gestion simplifiée de l'infrastructure système de RTNET
# Créé par Emerick ROMAN, emerick@rtnet.Fr

import getpass
import hashlib
import pymysql

def text_hash(text : str):
	m = hashlib.sha256()
	m.update(text.encode("utf-8"))
	return m.hexdigest()

def sql_conn():
	db=pymysql.connect(host="10.10.86.30", charset="utf8",user="check", passwd="SalutCestCool",db="authdb")
	return db

def register_user():
	print("/!\\")
	print("A tout moment vous pouvez annuler la création d'un utilisateur en écrivant 'sss' (les valeurs sont vérifiées à la fin des questions)")
	print("/!\\")
	register_name = input(str("Nom de l'utilisateur : "))
	register_pass = getpass.getpass()
	register_mail = input(str("E-mail de l'utilisateur : "))
	register_rank = input(str("Permissions de l'utilisateur : user/system/admin : "))
	incorrect = 0
	if register_name == "sss" or register_pass == "sss" or register_mail == "sss" or register_rank == "sss":
		print("Annulation...")
	if register_rank != "user" and register_rank != "system" and register_rank != "admin":
		print("Niveau de permissions incorrect ! Annulation")
		incorrect = 1
	if incorrect != 1:
		register_pass = text_hash(register_pass)
		db = sql_conn()
		c = db.cursor()
		c.execute("insert into users values (DEFAULT,'"+register_name+"','"+register_mail+"','"+register_pass+"',DEFAULT,'"+register_rank+"');")
		c.fetchone()
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
		db = sql_conn()
		c = db.cursor()
		c.execute("UPDATE users SET rank = '"+modify_rank+"' WHERE username = '"+modify_name+"';")
		c.fetchone()
		db.commit()
		db.close()
		print("Niveau de permissions de l'utilisateur modifié")

def dial():
	print("");
	print("Bienvenue sur GS ! Identifiez-vous")
	user = input(str("Utilisateur : "))
	password = getpass.getpass()
	db = sql_conn()
	c = db.cursor()
	c.execute("select username from users where password = '"+text_hash(password)+"';")
	if c.fetchone():
		print("Connecté")
	else:
		print("Connexion échouée")
		exit(2)
	c.close()
	db.close()
	print("")
	while True:
		print("Options disponibles :")
		print("")
		print("exit : quitter le programme")
		print("logout : se déconnecter")
		db = sql_conn()
		c = db.cursor()
		c.execute("select rank from users where username = '"+user+"' AND rank = 'admin';")
		resultat = c.fetchone()
		if resultat is not None:
			print("register : enregistrer un nouvel utilisateur")
			print("privilege : modifier le rang d'un utilisateur")
			print("")
			query = input(str("># "))
		else:
			c.execute("select rank from users where username = '"+user+"' AND rank = 'superuser';")
			resultat = c.fetchone()
			if resultat is not None:
				print("register : enregistrer un nouvel utilisateur")
				print("privilege : modifier le rang d'un utilisateur")
				print("")
				query = input(str("># "))
			else:
				query = input(str(">$ "))
		db.close()
		if query == "exit" or query == "quit":
			print("")
			print("Au revoir !")
			exit(0)
		elif query == "logout":
			print("")
			print("Déconnexion...")
			dial()
		elif query == "register":
			register_user()
		elif query == "privilege":
			privilege_user()
		else:
			print("Commande non-reconnue")

dial()
