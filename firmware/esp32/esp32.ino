// Throwaway spike: unencrypted HTTP button counter, used only to validate the
// ESP32 -> server path. None of the SIOT wire protocol lives here yet.

#include <WiFi.h>
#include <HTTPClient.h>

#include "secrets.h"  // copy secrets.example.h -> secrets.h; gitignored

const int buttonPin = 12;
const String endpointURL = SIOT_ENDPOINT;
const String buttonPath = "/button";

const char* wifiSSID = WIFI_SSID;
const char* wifiPassword = WIFI_PASSWORD;

void setup() {
  Serial.begin(115200);

  pinMode(buttonPin, INPUT_PULLUP);

  WiFi.begin(wifiSSID, wifiPassword);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.println("Connecting to WiFi...");
  }
  Serial.println("Connected to WiFi");
}

bool buttonPressed = false;
unsigned long lastDebounceTime = 0;
const unsigned long debounceDelay = 50;

void loop() {
  bool reading = digitalRead(buttonPin) == LOW;

  if (reading != buttonPressed && millis() - lastDebounceTime > debounceDelay) {
    buttonPressed = reading;
    lastDebounceTime = millis();

    if (buttonPressed) {
      sendButtonPress();
    }
  }
}

void sendButtonPress() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected, skipping button press");
    return;
  }

  HTTPClient http;
  http.begin(endpointURL + buttonPath);
  int httpCode = http.POST("");

  if (httpCode > 0) {
    Serial.printf("Button press sent, response code: %d\n", httpCode);
  } else {
    Serial.printf("Button press failed: %s\n", http.errorToString(httpCode).c_str());
  }

  http.end();
}