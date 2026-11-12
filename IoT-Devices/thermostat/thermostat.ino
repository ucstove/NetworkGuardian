#include <WiFi.h>
#include <PubSubClient.h>
#include <Arduino.h>
unsigned long lastMsgTime = 0;
const unsigned long interval = 1000; // 1000 ms = 1 second
// Configure WiFi
const char *ssid = "iot-research-network"; // Enter your Wi-Fi name
const char *password = "K9#v2$Lp"; // Enter Wi-Fi password

// Configure MQTT Broker
const char *mqtt_broker = "192.168.4.1"; // IP address of broker
const char *topic = "temp1";
const char *mqtt_username = "lamp01"; //or ids_pi
const char *mqtt_password = "cTAu9Fkz"; //Mosquitto Password
const int mqtt_port = 1883; // Standard MQTT port

WiFiClient espClient;
PubSubClient client(espClient);
unsigned long lastReconnectAttempt = 0;

// Forward declaration of callback
void callback(char *topic, byte *payload, unsigned int length);

void setup() {
  Serial.begin(115200);

  // Connecting to a WiFi network
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.println("Connecting to WiFi...");
  }
  Serial.println("Connected to the Wi-Fi network");

  // Connecting to an MQTT broker
  client.setServer(mqtt_broker, mqtt_port);
  client.setCallback(callback);

  reconnectMQTT();
}

void callback(char *topic, byte *payload, unsigned int length) {
  Serial.print("Message arrived in topic: ");
  Serial.println(topic);
  Serial.print("Message:");
  for (int i = 0; i < length; i++) {
    Serial.print((char) payload[i]);
  }
  Serial.println();
  Serial.println("-----------------------");
}

void reconnectMQTT() {
  // Loop until we are reconnected
  while (!client.connected()) {
    // Check WiFi status first
    if (WiFi.status() != WL_CONNECTED) {
      Serial.println("WiFi disconnected, waiting for WiFi before MQTT reconnect...");
      delay(1000);
      continue;
    }

    String client_id = "Thermostat1";
    client_id += String(WiFi.macAddress());
    Serial.printf("The client %s connects to the MQTT broker\n", client_id.c_str());

    if (client.connect(client_id.c_str(), mqtt_username, mqtt_password)) {
      Serial.println("MQTT broker connected");
      // Resubscribe upon connection
      client.publish(topic, "Hi, I'm Thermostat1");
      client.subscribe(topic);
    } else {
      Serial.print("failed with state ");
      Serial.print(client.state());
      Serial.println(" trying again in 5 seconds");
      delay(5000);
    }
  }
}

void verifyConnectionsNonBlocking() {
  // Non-blocking reconnection check for loop()
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi lost. Reconnecting...");
    WiFi.disconnect();
    WiFi.begin(ssid, password);
    return;
  }

  if (!client.connected()) {
    unsigned long now = millis();
    // Attempt connection every 5 seconds without blocking the loop
    if (now - lastReconnectAttempt > 5000) {
      lastReconnectAttempt = now;
      
      String client_id = "Thermostat1";
      client_id += String(WiFi.macAddress());
      
      if (client.connect(client_id.c_str(), mqtt_username, mqtt_password)) {
        Serial.println("MQTT reconnected (Non-Blocking)");
        client.publish(topic, "Hi, I'm Thermostat1 reconnected");
        client.subscribe(topic);
      } else {
        Serial.printf("MQTT reconnect failed, state: %d\n", client.state());
      }
    }
  }
}

char* getRandomString(long min, long max) {
  // 1. Generate the hardware random number
  long num = random(min, max);

  // 2. Create a persistent buffer large enough for a long integer + null terminator
  static char buffer[12]; 

  // 3. Format the integer into the character array safely
  snprintf(buffer, sizeof(buffer), "%ld", num);

  // 4. Return the pointer to the character array
  return buffer; 
}


void loop() {
    // Keep connections alive without using blocking delay()
  verifyConnectionsNonBlocking();
  
  if (client.connected()) {
    client.loop();
    // --- Thermostat Simulation Engine ---
      unsigned long currentMillis = millis();

      // 5. Publish to your MQTT broker
      
        if (currentMillis - lastMsgTime >= interval) {
        lastMsgTime = currentMillis; // Save the last time you sent a packet
        //Serial.println(client.state());
        //Serial.println(client.connected());
        // Send your 1 MQTT packet here
        //client.publish(topic, getRandomString(65, 75));
        client.publish(topic, "1");
      }
    }
  }

