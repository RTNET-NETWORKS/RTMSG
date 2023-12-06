#include <WiFi.h>

const char* mySSID = "joseph2AP";
const char* myPassword = "password";
const int channel = 6;

void setup() {
  Serial.begin(115200);

  WiFi.mode(WIFI_AP);
  
  // Configurer le point d'accès pour utiliser une largeur de bande de 20 MHz
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0), channel, WIFI_AUTH_WPA2_PSK, WIFI_BW_HT20);
  
  // Création de l'accès point
  if(WiFi.softAP(mySSID, myPassword)) {
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
