
#include <WiFi.h>
#include <WebServer.h>
#include <PubSubClient.h>

#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SH110X.h>
#include <DHT.h>

// =====================================================
// Config.h - Wi-Fi & MQTT
// =====================================================
const char* ssid = "Kali";
const char* password = "111222333";

const char* mqtt_server = "10.70.21.154";
const int mqtt_port = 1883;

const char* MQTT_EVENTS_TOPIC  = "iot/honeypot/events";
const char* MQTT_STATUS_TOPIC  = "iot/honeypot/status";
const char* MQTT_SENSORS_TOPIC = "iot/honeypot/sensors";

const unsigned long MQTT_RECONNECT_INTERVAL = 5000;
const unsigned long SENSOR_MQTT_INTERVAL = 10000;

// =====================================================
// Config.h - DHT11
// =====================================================
#define DHT_PIN 22
#define DHT_TYPE DHT11

// =====================================================
// Config.h - OLED SH1106
// =====================================================
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_ADDRESS 0x3C

// =====================================================
// Config.h - LEDs
// =====================================================
#define GREEN_LED 23
#define RED_LED 4

// =====================================================
// Config.h - Buzzer
// =====================================================
#define BUZZER_PIN 18

const unsigned long WARNING_BUZZER_ON_TIME  = 200;
const unsigned long WARNING_BUZZER_OFF_TIME = 1000;
const unsigned long ATTACK_BUZZER_ON_TIME   = 200;
const unsigned long ATTACK_BUZZER_OFF_TIME  = 200;

// =====================================================
// Config.h - Detection thresholds
// =====================================================
const unsigned long LOGIN_WINDOW = 30000;
const int LOGIN_WARNING_THRESHOLD = 3;
const int LOGIN_ATTACK_THRESHOLD  = 5;

const unsigned long RECON_WINDOW = 20000;
const int RECON_WARNING_THRESHOLD = 2;
const int RECON_ATTACK_THRESHOLD  = 4;

const unsigned long FLOOD_WINDOW = 5000;
const int FLOOD_WARNING_THRESHOLD = 10;
const int FLOOD_ATTACK_THRESHOLD  = 20;

const int MAX_EVENTS = 20;

// =====================================================
// Types.h
// =====================================================
enum SecurityState {
  STATE_NORMAL,
  STATE_WARNING,
  STATE_ATTACK
};

struct SecurityEvent {
  unsigned long id;
  String timestamp;
  String sourceIP;
  String type;
  String severity;
  int count;
  String details;
};

// =====================================================
// Main objects
// =====================================================
WebServer server(80);

WiFiClient espClient;
PubSubClient mqttClient(espClient);

DHT dht(DHT_PIN, DHT_TYPE);

Adafruit_SH1106G display(
  SCREEN_WIDTH,
  SCREEN_HEIGHT,
  &Wire,
  -1
);

// =====================================================
// General variables
// =====================================================
unsigned long lastMQTTReconnectAttempt = 0;
unsigned long lastSensorMQTTPublish = 0;
unsigned long lastSensorRead = 0;

float temperature = 0;
float humidity = 0;

// =====================================================
// Buzzer variables
// =====================================================
bool buzzerState = false;
unsigned long lastBuzzerChange = 0;

// =====================================================
// Security state
// =====================================================
SecurityState currentSecurityState = STATE_NORMAL;

// =====================================================
// Brute Force variables
// =====================================================
int failedLoginAttempts = 0;
unsigned long firstLoginAttemptTime = 0;

// =====================================================
// Reconnaissance variables
// =====================================================
int suspiciousPathAttempts = 0;
unsigned long firstSuspiciousPathTime = 0;

// =====================================================
// Request Flood variables
// =====================================================
int requestFloodCount = 0;
unsigned long firstFloodRequestTime = 0;
String floodSourceIP = "";

// =====================================================
// Security Events
// =====================================================
SecurityEvent securityEvents[MAX_EVENTS];
int eventCount = 0;
int eventWriteIndex = 0;
unsigned long nextEventID = 1;

// =====================================================
// Function declarations
// =====================================================
String getTimestamp();
String htmlEscape(String value);
String jsonEscape(String value);

void connectMQTT();
void maintainMQTT();
void publishSecurityEvent(SecurityEvent event);
void publishStatus();
void publishSensorData();

void updateOLED();
void updateBuzzer();

void setSecurityState(SecurityState state);
void evaluateSecurityState();
void registerSuspiciousPath(String path);
void registerRequestForFlood(String path);
void logSecurityEvent(String type, String severity, String sourceIP, int count, String details);

String getMainPage();
String getSecurityLogsPage();

void handleRoot();
void handleLogin();
void handleAuthentication();
void handleAdmin();
void handleSecurityLogs();
void handleNotFound();

// =====================================================
// Setup
// =====================================================
void setup() {
  Serial.begin(115200);
  delay(500);

  // LEDs
  pinMode(GREEN_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);
  digitalWrite(GREEN_LED, LOW);
  digitalWrite(RED_LED, LOW);

  // Buzzer
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);
  buzzerState = false;
  lastBuzzerChange = millis();

  // DHT sensor
  dht.begin();

  // OLED
  Wire.begin(5, 21);

  if (!display.begin(OLED_ADDRESS, true)) {
    Serial.println("OLED initialization failed!");
    while (1) {
      // Stop here if OLED initialization fails.
    }
  }

  display.clearDisplay();
  display.setTextColor(SH110X_WHITE);
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.println("ESP32 IoT Honeypot");
  display.println("Connecting WiFi...");
  display.display();

  // Wi-Fi connection
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  Serial.print("Connecting to WiFi");

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println();
  Serial.println("WiFi connected!");
  Serial.print("ESP32 IP Address: ");
  Serial.println(WiFi.localIP());

  // First sensor reading
  delay(1000);

  float initialTemperature = dht.readTemperature();
  float initialHumidity = dht.readHumidity();

  if (!isnan(initialTemperature)) {
    temperature = initialTemperature;
  }

  if (!isnan(initialHumidity)) {
    humidity = initialHumidity;
  }

  setSecurityState(STATE_NORMAL);

  // MQTT
  mqttClient.setServer(mqtt_server, mqtt_port);
  mqttClient.setBufferSize(768);
  connectMQTT();

  // Web routes
  server.on("/", HTTP_GET, handleRoot);
  server.on("/login", HTTP_GET, handleLogin);
  server.on("/authenticate", HTTP_POST, handleAuthentication);
  server.on("/admin", HTTP_GET, handleAdmin);
  server.on("/security-logs", HTTP_GET, handleSecurityLogs);
  server.onNotFound(handleNotFound);

  server.begin();

  Serial.println("Honeypot Web Server started.");
  Serial.println("Security Logger ready.");
}

// =====================================================
// Main Loop
// =====================================================
void loop() {
  // Web Server
  server.handleClient();

  // MQTT
  maintainMQTT();

  // Buzzer alarm (non-blocking)
  updateBuzzer();

  // Read DHT sensor every 2 seconds
  if (millis() - lastSensorRead >= 2000) {
    lastSensorRead = millis();

    float newTemperature = dht.readTemperature();
    float newHumidity = dht.readHumidity();

    if (!isnan(newTemperature)) {
      temperature = newTemperature;
    }

    if (!isnan(newHumidity)) {
      humidity = newHumidity;
    }

    updateOLED();
  }

  // Send sensor values to MQTT every 10 seconds
  if (millis() - lastSensorMQTTPublish >= SENSOR_MQTT_INTERVAL) {
    lastSensorMQTTPublish = millis();
    publishSensorData();
  }

  // Reset Brute Force window
  if (failedLoginAttempts > 0 &&
      millis() - firstLoginAttemptTime > LOGIN_WINDOW) {

    failedLoginAttempts = 0;
    Serial.println("Brute Force window reset.");
    evaluateSecurityState();
  }

  // Reset Recon window
  if (suspiciousPathAttempts > 0 &&
      millis() - firstSuspiciousPathTime > RECON_WINDOW) {

    suspiciousPathAttempts = 0;
    Serial.println("Recon window reset.");
    evaluateSecurityState();
  }

  // Reset Flood window
  if (requestFloodCount > 0 &&
      millis() - firstFloodRequestTime > FLOOD_WINDOW) {

    requestFloodCount = 0;
    floodSourceIP = "";
    Serial.println("Request Flood window reset.");
    evaluateSecurityState();
  }
}

// =====================================================
// 01_Utilities
// =====================================================
String getTimestamp() {
  unsigned long totalSeconds = millis() / 1000;
  unsigned long hours = totalSeconds / 3600;
  unsigned long minutes = (totalSeconds % 3600) / 60;
  unsigned long seconds = totalSeconds % 60;

  char buffer[20];
  snprintf(
    buffer,
    sizeof(buffer),
    "T+%02lu:%02lu:%02lu",
    hours,
    minutes,
    seconds
  );

  return String(buffer);
}

String htmlEscape(String value) {
  value.replace("&", "&amp;");
  value.replace("<", "&lt;");
  value.replace(">", "&gt;");
  value.replace("\"", "&quot;");
  return value;
}

String jsonEscape(String value) {
  value.replace("\\", "\\\\");
  value.replace("\"", "\\\"");
  value.replace("\n", "\\n");
  value.replace("\r", "");
  return value;
}

// =====================================================
// 02_MQTT
// =====================================================
void connectMQTT() {
  if (mqttClient.connected()) {
    return;
  }

  Serial.println();
  Serial.print("Connecting to MQTT Broker: ");
  Serial.println(mqtt_server);

  String clientID = "ESP32-Honeypot-";
  clientID += String((uint32_t)ESP.getEfuseMac(), HEX);

  const char* offlineMessage =
    "{\"device\":\"ESP32-Honeypot-01\",\"online\":false}";

  bool connected = mqttClient.connect(
    clientID.c_str(),
    MQTT_STATUS_TOPIC,
    0,
    true,
    offlineMessage
  );

  if (connected) {
    Serial.println("MQTT CONNECTED!");
    publishStatus();
  } else {
    Serial.print("MQTT connection failed. State: ");
    Serial.println(mqttClient.state());
  }
}

void maintainMQTT() {
  if (WiFi.status() != WL_CONNECTED) {
    return;
  }

  if (mqttClient.connected()) {
    mqttClient.loop();
    return;
  }

  unsigned long now = millis();

  if (lastMQTTReconnectAttempt == 0 ||
      now - lastMQTTReconnectAttempt >= MQTT_RECONNECT_INTERVAL) {

    lastMQTTReconnectAttempt = now;
    connectMQTT();
  }
}

void publishSecurityEvent(SecurityEvent event) {
  if (!mqttClient.connected()) {
    Serial.println("MQTT offline - event kept in local RAM only.");
    return;
  }

  String payload = "{";
  payload += "\"device\":\"ESP32-Honeypot-01\",";
  payload += "\"event_id\":" + String(event.id) + ",";
  payload += "\"timestamp\":\"" + jsonEscape(event.timestamp) + "\",";
  payload += "\"source_ip\":\"" + jsonEscape(event.sourceIP) + "\",";
  payload += "\"type\":\"" + jsonEscape(event.type) + "\",";
  payload += "\"severity\":\"" + jsonEscape(event.severity) + "\",";
  payload += "\"count\":" + String(event.count) + ",";
  payload += "\"details\":\"" + jsonEscape(event.details) + "\"";
  payload += "}";

  bool result = mqttClient.publish(
    MQTT_EVENTS_TOPIC,
    payload.c_str()
  );

  if (result) {
    Serial.println("MQTT EVENT PUBLISHED");
    Serial.print("Topic: ");
    Serial.println(MQTT_EVENTS_TOPIC);
    Serial.print("Payload: ");
    Serial.println(payload);
  } else {
    Serial.println("MQTT publish failed!");
  }
}

void publishStatus() {
  if (!mqttClient.connected()) {
    return;
  }

  String state;

  if (currentSecurityState == STATE_NORMAL) {
    state = "NORMAL";
  } else if (currentSecurityState == STATE_WARNING) {
    state = "WARNING";
  } else {
    state = "ATTACK";
  }

  String payload = "{";
  payload += "\"device\":\"ESP32-Honeypot-01\",";
  payload += "\"online\":true,";
  payload += "\"state\":\"" + state + "\",";
  payload += "\"ip\":\"" + WiFi.localIP().toString() + "\"";
  payload += "}";

  mqttClient.publish(
    MQTT_STATUS_TOPIC,
    payload.c_str(),
    true
  );
}

void publishSensorData() {
  if (!mqttClient.connected()) {
    return;
  }

  String payload = "{";
  payload += "\"device\":\"ESP32-Honeypot-01\",";
  payload += "\"temperature\":" + String(temperature, 1) + ",";
  payload += "\"humidity\":" + String(humidity, 0);
  payload += "}";

  mqttClient.publish(
    MQTT_SENSORS_TOPIC,
    payload.c_str()
  );
}

// =====================================================
// 03_Sensors_OLED
// =====================================================
void updateOLED() {
  display.clearDisplay();
  display.setTextColor(SH110X_WHITE);
  display.setTextSize(1);
  display.setCursor(0, 0);

  display.println("ESP32 IoT Honeypot");
  display.println("-------------------");

  display.print("Temp: ");
  display.print(temperature, 1);
  display.println(" C");

  display.print("Humidity: ");
  display.print(humidity, 0);
  display.println(" %");

  display.print("State: ");

  if (currentSecurityState == STATE_NORMAL) {
    display.println("NORMAL");
  } else if (currentSecurityState == STATE_WARNING) {
    display.println("WARNING");
  } else {
    display.println("ATTACK!");
  }

  display.print("Events: ");
  display.println(eventCount);

  display.print("MQTT: ");

  if (mqttClient.connected()) {
    display.println("ONLINE");
  } else {
    display.println("OFFLINE");
  }

  display.display();
}

// =====================================================
// 04_Buzzer
// =====================================================
void updateBuzzer() {
  unsigned long currentTime = millis();

  if (currentSecurityState == STATE_NORMAL) {
    buzzerState = false;
    digitalWrite(BUZZER_PIN, LOW);
    return;
  }

  if (currentSecurityState == STATE_WARNING) {
    if (buzzerState == true) {
      if (currentTime - lastBuzzerChange >= WARNING_BUZZER_ON_TIME) {
        buzzerState = false;
        digitalWrite(BUZZER_PIN, LOW);
        lastBuzzerChange = currentTime;
      }
    } else {
      if (currentTime - lastBuzzerChange >= WARNING_BUZZER_OFF_TIME) {
        buzzerState = true;
        digitalWrite(BUZZER_PIN, HIGH);
        lastBuzzerChange = currentTime;
      }
    }

    return;
  }

  if (currentSecurityState == STATE_ATTACK) {
    if (buzzerState == true) {
      if (currentTime - lastBuzzerChange >= ATTACK_BUZZER_ON_TIME) {
        buzzerState = false;
        digitalWrite(BUZZER_PIN, LOW);
        lastBuzzerChange = currentTime;
      }
    } else {
      if (currentTime - lastBuzzerChange >= ATTACK_BUZZER_OFF_TIME) {
        buzzerState = true;
        digitalWrite(BUZZER_PIN, HIGH);
        lastBuzzerChange = currentTime;
      }
    }
  }
}

// =====================================================
// 05_Security
// =====================================================
void logSecurityEvent(
  String type,
  String severity,
  String sourceIP,
  int count,
  String details
) {
  SecurityEvent event;

  event.id = nextEventID++;
  event.timestamp = getTimestamp();
  event.sourceIP = sourceIP;
  event.type = type;
  event.severity = severity;
  event.count = count;
  event.details = details;

  securityEvents[eventWriteIndex] = event;
  eventWriteIndex = (eventWriteIndex + 1) % MAX_EVENTS;

  if (eventCount < MAX_EVENTS) {
    eventCount++;
  }

  Serial.println();
  Serial.println("================================");
  Serial.println("SECURITY EVENT CREATED");
  Serial.print("Event ID: ");
  Serial.println(event.id);
  Serial.print("Time: ");
  Serial.println(event.timestamp);
  Serial.print("Source IP: ");
  Serial.println(event.sourceIP);
  Serial.print("Type: ");
  Serial.println(event.type);
  Serial.print("Severity: ");
  Serial.println(event.severity);
  Serial.print("Count: ");
  Serial.println(event.count);
  Serial.print("Details: ");
  Serial.println(event.details);
  Serial.println("================================");

  publishSecurityEvent(event);
  updateOLED();
}

void setSecurityState(SecurityState state) {
  bool changed = (state != currentSecurityState);
  currentSecurityState = state;

  if (changed) {
    buzzerState = false;
    digitalWrite(BUZZER_PIN, LOW);
    lastBuzzerChange = millis();
  }

  digitalWrite(GREEN_LED, LOW);
  digitalWrite(RED_LED, LOW);

  if (state == STATE_NORMAL) {
    digitalWrite(GREEN_LED, HIGH);
  } else {
    digitalWrite(RED_LED, HIGH);
  }

  if (changed) {
    Serial.print("SECURITY STATE CHANGED: ");

    if (state == STATE_NORMAL) {
      Serial.println("NORMAL");
    } else if (state == STATE_WARNING) {
      Serial.println("WARNING");
    } else {
      Serial.println("ATTACK");
    }

    publishStatus();
  }

  updateOLED();
}

void evaluateSecurityState() {
  bool bruteAttack = failedLoginAttempts >= LOGIN_ATTACK_THRESHOLD;
  bool bruteWarning = failedLoginAttempts >= LOGIN_WARNING_THRESHOLD;

  bool reconAttack = suspiciousPathAttempts >= RECON_ATTACK_THRESHOLD;
  bool reconWarning = suspiciousPathAttempts >= RECON_WARNING_THRESHOLD;

  bool floodAttack = requestFloodCount >= FLOOD_ATTACK_THRESHOLD;
  bool floodWarning = requestFloodCount >= FLOOD_WARNING_THRESHOLD;

  if (bruteAttack || reconAttack || floodAttack) {
    setSecurityState(STATE_ATTACK);
  } else if (bruteWarning || reconWarning || floodWarning) {
    setSecurityState(STATE_WARNING);
  } else {
    setSecurityState(STATE_NORMAL);
  }
}

void registerRequestForFlood(String path) {
  if (path == "/favicon.ico") {
    return;
  }

  unsigned long currentTime = millis();
  String sourceIP = server.client().remoteIP().toString();

  if (requestFloodCount == 0 ||
      currentTime - firstFloodRequestTime > FLOOD_WINDOW ||
      floodSourceIP != sourceIP) {

    requestFloodCount = 0;
    firstFloodRequestTime = currentTime;
    floodSourceIP = sourceIP;
  }

  requestFloodCount++;

  if (requestFloodCount == FLOOD_WARNING_THRESHOLD) {
    logSecurityEvent(
      "REQUEST_FLOOD",
      "MEDIUM",
      sourceIP,
      requestFloodCount,
      "High HTTP request rate detected"
    );
  }

  if (requestFloodCount == FLOOD_ATTACK_THRESHOLD) {
    logSecurityEvent(
      "REQUEST_FLOOD",
      "HIGH",
      sourceIP,
      requestFloodCount,
      "Request flood threshold exceeded"
    );
  }

  evaluateSecurityState();
}

void registerSuspiciousPath(String path) {
  unsigned long currentTime = millis();
  String sourceIP = server.client().remoteIP().toString();

  if (suspiciousPathAttempts == 0 ||
      currentTime - firstSuspiciousPathTime > RECON_WINDOW) {

    suspiciousPathAttempts = 0;
    firstSuspiciousPathTime = currentTime;
  }

  suspiciousPathAttempts++;

  Serial.print("Suspicious path: ");
  Serial.print(path);
  Serial.print(" | Count: ");
  Serial.println(suspiciousPathAttempts);

  if (suspiciousPathAttempts == RECON_WARNING_THRESHOLD) {
    logSecurityEvent(
      "RECONNAISSANCE",
      "MEDIUM",
      sourceIP,
      suspiciousPathAttempts,
      "Suspicious path activity detected"
    );
  }

  if (suspiciousPathAttempts == RECON_ATTACK_THRESHOLD) {
    logSecurityEvent(
      "RECONNAISSANCE",
      "HIGH",
      sourceIP,
      suspiciousPathAttempts,
      "Path scanning threshold exceeded"
    );
  }

  evaluateSecurityState();
}

// =====================================================
// 06_WebPages
// =====================================================
String getMainPage() {
  String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Smart Home Gateway</title>
<style>
body {
  font-family: Arial;
  background: #eef2f5;
  text-align: center;
  margin: 0;
}
.header {
  background: #263238;
  color: white;
  padding: 20px;
}
.card {
  background: white;
  margin: 20px auto;
  padding: 20px;
  max-width: 400px;
  border-radius: 10px;
}
.status {
  color: green;
  font-weight: bold;
}
button {
  background: #1976d2;
  color: white;
  border: none;
  padding: 12px 20px;
  border-radius: 5px;
}
</style>
</head>
<body>

<div class="header">
  <h2>Smart Home Gateway</h2>
  <p>IoT Control System</p>
</div>

<div class="card">
  <h3>Device Status</h3>
  <p class="status">SYSTEM ONLINE</p>
  <p>Temperature: <strong>)rawliteral";

  html += String(temperature, 1);

  html += R"rawliteral( C</strong></p>
  <p>Humidity: <strong>)rawliteral";

  html += String(humidity, 0);

  html += R"rawliteral( %</strong></p>
</div>

<div class="card">
  <h3>Connected Devices</h3>
  <p>Door Lock: Online</p>
  <p>Motion Sensor: Active</p>
  <p>Camera: Online</p>
</div>

<div class="card">
  <h3>Administration</h3>
  <a href="/login">
    <button>Administrator Login</button>
  </a>
</div>

</body>
</html>
)rawliteral";

  return html;
}

String getSecurityLogsPage() {
  String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IoT Honeypot Security Logs</title>
<style>
body {
  font-family: Arial;
  background: #101820;
  color: white;
  margin: 20px;
}
h2 {
  color: #4fc3f7;
}
table {
  width: 100%;
  border-collapse: collapse;
  background: #1c2731;
}
th, td {
  border: 1px solid #455a64;
  padding: 8px;
}
th {
  background: #263238;
  color: #4fc3f7;
}
.high {
  color: #ff5252;
  font-weight: bold;
}
.medium {
  color: #ffca28;
  font-weight: bold;
}
</style>
</head>
<body>

<h2>ESP32 IoT Honeypot Security Logs</h2>
<p>Stored Events: )rawliteral";

  html += String(eventCount);
  html += " / 20</p>";

  html += R"rawliteral(
<table>
<tr>
  <th>ID</th>
  <th>Time</th>
  <th>Source</th>
  <th>Type</th>
  <th>Severity</th>
  <th>Count</th>
  <th>Details</th>
</tr>
)rawliteral";

  int startIndex;

  if (eventCount < MAX_EVENTS) {
    startIndex = 0;
  } else {
    startIndex = eventWriteIndex;
  }

  for (int i = 0; i < eventCount; i++) {
    int index = (startIndex + i) % MAX_EVENTS;
    SecurityEvent &event = securityEvents[index];

    html += "<tr>";
    html += "<td>" + String(event.id) + "</td>";
    html += "<td>" + htmlEscape(event.timestamp) + "</td>";
    html += "<td>" + htmlEscape(event.sourceIP) + "</td>";
    html += "<td>" + htmlEscape(event.type) + "</td>";

    if (event.severity == "HIGH") {
      html += "<td class='high'>";
    } else {
      html += "<td class='medium'>";
    }

    html += event.severity + "</td>";
    html += "<td>" + String(event.count) + "</td>";
    html += "<td>" + htmlEscape(event.details) + "</td>";
    html += "</tr>";
  }

  html += R"rawliteral(
</table>
</body>
</html>
)rawliteral";

  return html;
}

// =====================================================
// 07_WebHandlers
// =====================================================
void handleRoot() {
  registerRequestForFlood("/");
  server.send(200, "text/html", getMainPage());
}

void handleLogin() {
  registerRequestForFlood("/login");

  String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gateway Login</title>
<style>
body {
  font-family: Arial;
  background: #eef2f5;
  text-align: center;
}
.login {
  background: white;
  width: 300px;
  margin: 80px auto;
  padding: 25px;
  border-radius: 10px;
}
input {
  margin: 8px;
  padding: 10px;
  width: 80%;
}
button {
  padding: 10px 25px;
}
</style>
</head>
<body>

<div class="login">
  <h2>Administrator Login</h2>
  <form action="/authenticate" method="POST">
    <input type="text" name="username" placeholder="Username">
    <br>
    <input type="password" name="password" placeholder="Password">
    <br>
    <button type="submit">Login</button>
  </form>
</div>

</body>
</html>
)rawliteral";

  server.send(200, "text/html", html);
}

void handleAuthentication() {
  registerRequestForFlood("/authenticate");

  unsigned long currentTime = millis();
  String sourceIP = server.client().remoteIP().toString();

  if (failedLoginAttempts == 0 ||
      currentTime - firstLoginAttemptTime > LOGIN_WINDOW) {

    failedLoginAttempts = 0;
    firstLoginAttemptTime = currentTime;
  }

  failedLoginAttempts++;

  Serial.print("Login attempt from: ");
  Serial.print(sourceIP);
  Serial.print(" | Count: ");
  Serial.println(failedLoginAttempts);

  if (failedLoginAttempts == LOGIN_WARNING_THRESHOLD) {
    logSecurityEvent(
      "BRUTE_FORCE",
      "MEDIUM",
      sourceIP,
      failedLoginAttempts,
      "Multiple failed login attempts"
    );
  }

  if (failedLoginAttempts == LOGIN_ATTACK_THRESHOLD) {
    logSecurityEvent(
      "BRUTE_FORCE",
      "HIGH",
      sourceIP,
      failedLoginAttempts,
      "Brute force threshold exceeded"
    );
  }

  evaluateSecurityState();

  String html = R"rawliteral(
<!DOCTYPE html>
<html>
<body style="font-family:Arial;text-align:center;margin-top:80px;background:#eef2f5;">
<h2>Authentication Failed</h2>
<p>Invalid username or password.</p>
<a href="/login">Try Again</a>
</body>
</html>
)rawliteral";

  server.send(401, "text/html", html);
}

void handleAdmin() {
  registerRequestForFlood("/admin");
  registerSuspiciousPath("/admin");

  server.send(403, "text/plain", "Access Denied");
}

void handleSecurityLogs() {
  server.send(200, "text/html", getSecurityLogsPage());
}

void handleNotFound() {
  String path = server.uri();

  if (path != "/favicon.ico") {
    registerRequestForFlood(path);
    registerSuspiciousPath(path);
  }

  server.send(404, "text/plain", "404 - Resource Not Found");
}
