#include <WiFi.h>
#include <WebServer.h>

const char* ssid = "joseph";
const char* password = "12345678";

WebServer server(80);

const int ledPin = 2;  // La LED intégrée de l'ESP32 est généralement connectée à la broche GPIO 2

void setup() {
  Serial.begin(115200);

  pinMode(ledPin, OUTPUT);
  digitalWrite(ledPin, LOW);

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  Serial.println("Connected to WiFi");

  server.on("/", HTTP_GET, handleRoot);
  server.on("/LEDON", HTTP_GET, handleLEDOn);
  server.on("/LEDOFF", HTTP_GET, handleLEDOff);

  server.begin();
}

void loop() {
  server.handleClient();
}

void handleRoot() {
  String html = "<html><body>";
  html += "<h2>ESP32 Web Server</h2>";
  html += "<button onclick=\"location.href='/LEDON'\" type='button'>Turn ON</button><br><br>";
  html += "<button onclick=\"location.href='/LEDOFF'\" type='button'>Turn OFF</button><br><br>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

void handleLEDOn() {
  digitalWrite(ledPin, HIGH);
  server.send(200, "text/plain", "LED Turned ON");
}

void handleLEDOff() {
  digitalWrite(ledPin, LOW);
  server.send(200, "text/plain", "LED Turned OFF");
}
