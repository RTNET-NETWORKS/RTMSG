#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define KEY_LENGTH 2048
#define CHALLENGE_LENGTH 32
#define MAX_USERS 100

// Structure pour un utilisateur
typedef struct {
    char login[50];
    RSA *public_key;
} Utilisateur;

Utilisateur utilisateurs[MAX_USERS];
int nombre_utilisateurs = 0;
char utilisateur_actuel[50] = "";

// Génération d'une clé RSA et sauvegarde dans des fichiers PEM
int generate_rsa_keys(const char *login) {
    RSA *key_pair = RSA_generate_key(KEY_LENGTH, RSA_F4, NULL, NULL);
    if (!key_pair) {
        fprintf(stderr, "Erreur lors de la génération de la clé RSA\n");
        return 0;
    }

    // Sauvegarder la clé privée
    char private_key_filename[100];
    snprintf(private_key_filename, sizeof(private_key_filename), "private_key_%s.pem", login);
    FILE *private_key_file = fopen(private_key_filename, "wb");
    if (!private_key_file) {
        fprintf(stderr, "Erreur d'ouverture du fichier pour la clé privée\n");
        RSA_free(key_pair);
        return 0;
    }
    PEM_write_RSAPrivateKey(private_key_file, key_pair, NULL, NULL, 0, NULL, NULL);
    fclose(private_key_file);

    // Sauvegarder la clé publique
    char public_key_filename[100];
    snprintf(public_key_filename, sizeof(public_key_filename), "public_key_%s.pem", login);
    FILE *public_key_file = fopen(public_key_filename, "wb");
    if (!public_key_file) {
        fprintf(stderr, "Erreur d'ouverture du fichier pour la clé publique\n");
        RSA_free(key_pair);
        return 0;
    }
    PEM_write_RSA_PUBKEY(public_key_file, key_pair);
    fclose(public_key_file);

    RSA_free(key_pair);
    return 1;
}

// Fonction pour enregistrer un nouvel utilisateur avec génération de clé
void register_user() {
    if (nombre_utilisateurs >= MAX_USERS) {
        printf("Nombre maximum d'utilisateurs atteint.\n");
        return;
    }

    Utilisateur new_user;
    printf("Entrez le login : ");
    scanf("%s", new_user.login);

    // Génération des clés et sauvegarde dans des fichiers
    if (!generate_rsa_keys(new_user.login)) {
        printf("Erreur lors de la génération des clés pour l'utilisateur %s.\n", new_user.login);
        return;
    }

    // Charger la clé publique dans la structure Utilisateur
    char public_key_filename[100];
    snprintf(public_key_filename, sizeof(public_key_filename), "public_key_%s.pem", new_user.login);
    FILE *public_key_file = fopen(public_key_filename, "rb");
    if (!public_key_file) {
        fprintf(stderr, "Erreur d'ouverture du fichier de la clé publique\n");
        return;
    }
    new_user.public_key = PEM_read_RSA_PUBKEY(public_key_file, NULL, NULL, NULL);
    fclose(public_key_file);

    utilisateurs[nombre_utilisateurs++] = new_user;
    printf("Utilisateur enregistré avec succès.\n");
}

// Génération d'un challenge aléatoire
void generate_random_challenge(char *challenge) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < CHALLENGE_LENGTH; i++) {
        challenge[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    challenge[CHALLENGE_LENGTH] = '\0';
}

// Fonction de connexion
void login_user() {
    char login[50];
    char challenge[CHALLENGE_LENGTH + 1];
    unsigned char encrypted[KEY_LENGTH / 8];
    unsigned char decrypted[KEY_LENGTH / 8];

    printf("Entrez le login : ");
    scanf("%s", login);

    // Recherche de l'utilisateur dans le tableau
    RSA *public_key = NULL;
    for (int i = 0; i < nombre_utilisateurs; i++) {
        if (strcmp(utilisateurs[i].login, login) == 0) {
            public_key = utilisateurs[i].public_key;
            break;
        }
    }
    if (!public_key) {
        printf("Utilisateur non trouvé.\n");
        return;
    }

    // Charger la clé privée depuis le fichier
    char private_key_filename[100];
    snprintf(private_key_filename, sizeof(private_key_filename), "private_key_%s.pem", login);
    FILE *private_key_file = fopen(private_key_filename, "rb");
    if (!private_key_file) {
        fprintf(stderr, "Erreur d'ouverture du fichier de la clé privée\n");
        return;
    }
    RSA *private_key = PEM_read_RSAPrivateKey(private_key_file, NULL, NULL, NULL);
    fclose(private_key_file);
    if (!private_key) {
        fprintf(stderr, "Erreur de chargement de la clé privée\n");
        return;
    }

    // Générer un challenge aléatoire
    generate_random_challenge(challenge);
    printf("Challenge généré : %s\n", challenge);

    // Chiffrer le challenge avec la clé publique
    int encrypted_length = RSA_public_encrypt(strlen(challenge), (unsigned char *)challenge, encrypted, public_key, RSA_PKCS1_OAEP_PADDING);
    if (encrypted_length == -1) {
        fprintf(stderr, "Erreur lors du chiffrement du challenge\n");
        RSA_free(private_key);
        return;
    }

    // Déchiffrer le challenge avec la clé privée
    int decrypted_length = RSA_private_decrypt(encrypted_length, encrypted, decrypted, private_key, RSA_PKCS1_OAEP_PADDING);
    RSA_free(private_key);

    if (decrypted_length == -1 || strncmp((char *)decrypted, challenge, CHALLENGE_LENGTH) != 0) {
        printf("Échec de l'authentification : challenge incorrect.\n");
    } else {
        strcpy(utilisateur_actuel, login);
        printf("Connexion réussie. Utilisateur actuel : %s\n", utilisateur_actuel);
    }
}

// Fonction pour afficher l'utilisateur actuel
void who() {
    if (strlen(utilisateur_actuel) > 0) {
        printf("Utilisateur actuel : %s\n", utilisateur_actuel);
    } else {
        printf("Aucun utilisateur connecté.\n");
    }
}

// Fonction principale
int main() {
    char command[50];
    int running = 1;

    printf("Bienvenue dans le CLI. Tapez 'exit' pour quitter.\n");

    while (running) {
        printf("cli> ");
        scanf("%s", command);

        if (strcmp(command, "exit") == 0) {
            printf("Fermeture du programme.\n");
            running = 0;
        } else if (strcmp(command, "register") == 0) {
            register_user();
        } else if (strcmp(command, "login") == 0) {
            login_user();
        } else if (strcmp(command, "who") == 0) {
            who();
        } else {
            printf("Commande inconnue : %s\n", command);
        }
    }

    return 0;
}
