#include <WiFi.h>

const char* mySSID = "joseph1AP";  // Nouveau nom pour éviter tout conflit
const char* myPassword = "password"; 
const int channel = 6;  // J'ai changé le canal pour le mettre au milieu (vous pouvez le laisser à 10 si vous préférez)
const bool hideSSID = false;
const int maxConnections = 2;

void setup() {
  Serial.begin(115200);
  
  // Configuration du mode d'accès point pour l'ESP32
  WiFi.mode(WIFI_AP);

  // Création de l'accès point
  if(WiFi.softAP(mySSID, myPassword, channel, hideSSID, maxConnections)) {
    Serial.println("Point d'accès créé avec succès !");
    Serial.print("Adresse IP du point d'accès : ");
    Serial.println(WiFi.softAPIP());
  } else {
    Serial.println("Erreur lors de la création du point d'accès.");
  }
}

void loop() {
  // Rien à faire ici pour cet exemple simple
}
