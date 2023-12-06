#include <WiFi.h>
#include <WiFiClient.h>
#include <WebServer.h>
#include <LoRa.h>

const char* ssid = "ESP32-Access-Point";
const char* password = "123456789";

WebServer server(80);

String message = "";

void handleRoot() {
  String html = "<form action=\"/message\" method=\"post\"><input type=\"text\" name=\"message\"><input type=\"submit\"></form>";
  server.send(200, "text/html", html);
}

void handleMessage() {
  if (server.hasArg("message")) {
    message = server.arg("message");
    LoRa.beginPacket();
    LoRa.print(message);
    LoRa.endPacket();
    server.send(200, "text/plain", "Message sent over LoRa: " + message);
  } else {
    server.send(400, "text/plain", "400: Invalid Request – message parameter not found");
  }
}

void setup() {
  Serial.begin(115200);
  
  // Initialise le module LoRa
  if (!LoRa.begin(868E6)) {
    Serial.println("Starting LoRa failed!");
    while (1);
  }

  // Crée un point d'accès WiFi
  WiFi.softAP(ssid, password);
  IPAddress IP = WiFi.softAPIP();
  Serial.print("AP IP address: ");
  Serial.println(IP);
  
  // Serveur web pour saisir le message
  server.on("/", HTTP_GET, handleRoot);
  server.on("/message", HTTP_POST, handleMessage);
  server.begin();
}

void loop() {
  server.handleClient();
}
