// #####################################################################################
// #####################################################################################
// ### ESP8266 ESPReadEHZ                                                     ##########
// ### Program to decrypt SML-Protokoll for ISKRA MT681 eHZ                   ##########
// ### Copyright © 2018, Andreas S. Köhler                                    ##########
// ###                                                                        ##########
// ### This program is free software: you can redistribute it and/or modify   ##########
// ### it under the terms of the GNU General Public License as published by   ##########
// ### the Free Software Foundation, either version 3 of the License, or      ##########
// ### (at your option) any later version.                                    ##########
// ###                                                                        ##########
// ### This program is distributed in the hope that it will be useful,        ##########
// ### but WITHOUT ANY WARRANTY; without even the implied warranty of         ##########
// ### MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          ##########
// ### GNU General Public License for more details.                           ##########
// ###                                                                        ##########
// ### You should have received a copy of the GNU General Public License      ##########
// ### along with this program.  If not, see <http://www.gnu.org/licenses/>.  ##########
// #####################################################################################
// #####################################################################################

// #####################################################################################
// ### SML-Message of ISKARA MT681 eHZ:                                              ###
// ###                                                                               ###
// ### 1b 1b 1b 1b 01 01 01 01        Escape + StartMessage                          ###
// ### 76                                                                            ###
// ### 05 00 62 b7 a1                 transactionID (5Byte)                          ###
// ### 62 00                          groupNo                                        ###
// ### 62 00                          abortOnError                                   ###
// ### 72                                                                            ###
// ### 63 01 01                       Message 0101 = SML_PublicOpen.Res              ###
// ### 76                                                                            ###
// ### 01                             codepage                                       ###
// ### 01                             clientID                                       ###
// ### 05 00 20 e7 df                 reqFileID                                      ###
// ### 09 xx xx xx xx xx xx xx xx     ServerID                                       ###
// ### 01                             refTime                                        ###
// ### 01                             smlVersion                                     ###
// ### 63 de c8                       CRC                                            ###
// ### 00                             SMLEndOfMessage                                ###
// ### 76                                                                            ###
// ### 05 00 62 b7 a2                 transactionID (5Byte)                          ###
// ### 62 00                          groupNo                                        ###
// ### 62 00                          abortOnError                                   ###
// ### 72                                                                            ###
// ### 63 07 01                       Message 0701 = SML_GetList.Res                 ###
// ### 77                                                                            ###
// ### 01                                                                            ###
// ### 09 xx xx xx xx xx xx xx xx     Server-ID:                                     ###
// ### 07                                                                            ###
// ### 01                                                                            ###
// ### 00 62 0a ff ff                                                                ###
// ### 72                                                                            ###
// ### 62 01                          secIndex = 1                                   ###
// ### 65 00 33 5e dd 7d              Seconds-Index als unsigned 32                  ###
// ### 77                                                                            ###
// ### 07 81 81 c7 82 03 ff           objName 129-129:199.130.3*255                  ###
// ### ****************************** Supplieridentification                         ###
// ### 01                             status (empty)                                 ###
// ### 01                             valTime (empty)                                ###
// ### 01                             unit(empty)                                    ###
// ### 01                             scaler (empty)                                 ###
// ### 04 49 53 4b                    Value                                          ###
// ### 01                             valueSignature (empty)                         ###
// ### 77                                                                            ###
// ### 07 01 00 00 00 09 ff           objName 1-0:0.0.9*255                          ###
// ### ****************************** Systemidentification                           ###
// ### 01                             status                                         ###
// ### 01                             valTime                                        ###
// ### 01                             unit                                           ###
// ### 01                             scaler                                         ###
// ### 09 xx xx xx xx xx xx xx xx     Server-ID:                                     ###
// ### 01                                                                            ###
// ### 77                                                                            ###
// ### 07 01 00 01 08 00 ff           objName 1-0:1.8.0*255                          ###
// ### ****************************** Positive summe of energy (A+)                  ###                                 
// ### 65 00                                                                         ###
// ### 01                                                                            ###
// ### 01                                                                            ###
// ### 82 0    1                                                                     ###
// ### 62 1e                          unit (unsigned8) 1E = Wh                       ###
// ### 52 ff                          scaler (int8) -1 = *10^-1 = /10                ###
// ### 59 00 00 00 00 00 37 00 e2     value = 3604706 => 360470,6 = 360,47 kWh       ###
// ### 01                                                                            ###
// ### 77                                                                            ###
// ### 07 01 00 01 08 01 ff           objName 1-0:1.8.1*255                          ###
// ### ****************************** Positive energy "Tarif 1" (A+)                 ###
// ### 01                                                                            ###
// ### 01                                                                            ###
// ### 62 1e                          unit (unsigned8) 1E = Wh                       ###
// ### 52 ff                          scaler (int8) -1 = *10^-1 = /10                ###
// ### 59 00 00 00 00 00 37 00 e2 01  value = 3604706 => 360470,6 = 360,47kWh        ###
// ### 77                                                                            ###
// ### 07 01 00 01 08 02 ff           objName 1-0:1.8.2*255                          ###
// ### ****************************** Positive energy "Tarif 2" (A+)                 ###
// ### 01                             status (empty)                                 ###
// ### 01                             valTime (empty)                                ###
// ### 62 1e                          unit (unsigned8) 1E = Wh                       ###
// ### 52 ff                          scaler (int8) -1 = *10^-1 = /10                ###
// ### 59 00 00 00 00 00 00 00 00     value 0                                        ###
// ### 01                                                                            ###
// ### 77                                                                            ###
// ### 07 01 00 02 08 00 ff           objName 1-0:2.8.0*255                          ###
// ### ****************************** Negative summe of energy (A-)                  ###
// ### 65 00                                                                         ###
// ### 01                                                                            ###
// ### 01                                                                            ###
// ### 82 01                                                                         ###
// ### 62 1e                          unit (unsigned8) 1E = Wh                       ###
// ### 52 ff                          scaler (int8) -1 = *10^-1 = /10                ###
// ### 59 00 00 00 00 00 0c 51 37     value 807223 = 380722,3 Wh = 80,7223 kWh       ###
// ### 01                                                                            ###
// ### 77                                                                            ###
// ### 07 01 00 02 08 01 ff           objName 1-0:2.8.1*255                          ###
// ### ****************************** Negative energy "Tarif 1" (A-)                 ###
// ### 01                                                                            ###
// ### 01                                                                            ###
// ### 62 1e                          unit (unsigned8) 1E = Wh                       ###
// ### 52 ff                          scaler (int8) -1 = *10^-    1 = /10            ###
// ### 59 00 00 00 00 00 0c 51 37     value 807223 = 380722,3 Wh = 80,7223 kWh       ###
// ### 01                                                                            ###
// ### 77                                                                            ###
// ### 07 01 00 02 08 02 ff           objName 1-0:2.8.2*255                          ###
// ### ****************************** Negative energy "Tarif" 2(A-)                  ###
// ### 01                                                                            ###
// ### 01                                                                            ###
// ### 62 1e                          unit (unsigned8) 1E = Wh                       ###
// ### 52 ff                          scaler (int8) -1 = *10^-1 = /10                ###
// ### 59 00 00 00 00 00 00 00 00     value = 0                                      ###
// ### 01                                                                            ###
// ### 77                                                                            ###
// ### 07 01 00 10 07 00 ff           objName 1-0:16.7.0*255                         ###
// ### ****************************** Actual summe of power (P+ - P-)                ###
// ### 01                                                                            ###
// ### 01                                                                            ###
// ### 62 1B                          unit (unsigned8) 1B = W                        ###
// ### 52 00                          scaler (int8) = /1                             ###
// ### 55 00 00 08 5e                 value = 2142 W                                 ###
// ### 01                                                                            ###
// ### 77                                                                            ###
// ### 07 01 00 24 07 00 ff           objName 1-0:36.7.0*255                         ###
// ### ****************************** Actual power (P+ - P-) of phase L1             ###
// ### 01                                                                            ###
// ### 01                                                                            ###
// ### 62 1B                          unit (unsigned8) 1B = W                        ###
// ### 52 00                          scaler (int8) = /1                             ###
// ### 55 00 00 08 b6                 value = 2230 W                                 ###
// ### 01                                                                            ###
// ### 77                                                                            ###
// ### 07 01 00 38 07 00 ff           objName 1-0:56.7.0*255                         ###
// ### ****************************** Actual power (P+ - P-) of phase L2             ###
// ### 01                                                                            ###
// ### 01                                                                            ###
// ### 62 1B                          unit (unsigned8) 1B = W                        ###
// ### 52 00                          scaler (int8) = /1                             ###
// ### 55 ff ff ff 9b                                                                ###
// ### 01                                                                            ###
// ### 77                                                                            ###
// ### 07 01 00 4c 07 00 ff           objName 1-0:76.7.0*255                         ###
// ### ****************************** Actual power (P+ - P-) of phase L3             ###
// ### 01                                                                            ###
// ### 01                                                                            ###
// ### 62 1B                          unit (unsigned8) 1B = W                        ###
// ### 52 00                          scaler (int8) = /1                             ###
// ### 55 00 00 00 13                 value = 19 W                                   ###
// ### 01                                                                            ###
// ### 77                                                                            ###
// ### 07 81 81 c7 82 05 ff           objName 129-129:199.130.5*255                  ###
// ### ****************************** Public Key of eHZ                              ###
// ### 01                             status (empty)                                 ###
// ### 01                             valTime (empty)                                ###
// ### 01                             unit(empty)                                    ###
// ### 01                             scaler (empty)                                 ###
// ### 83 xx xx xx xx x    x xx xx                                                   ###
// ### xx xx xx xx x    x xx xx                                                      ###
// ### xx xx xx xx x    x xx xx                                                      ###
// ### xx xx xx xx x    x xx xx                                                      ###
// ### xx xx xx xx x    x xx xx                                                      ###
// ### xx xx xx xx x    x xx xx                                                      ###
// ### xx xx xx xx x    x xx xx                                                      ###
// ### xx xx xx xx x    x xx xx                                                      ###
// ### xx xx xx xx x    x xx xx                                                      ###
// ### xx xx xx xx x    x xx xx                                                      ###
// ### x    x xx                                                                     ###
// ### 63 a2 59                       CRC                                            ###
// ### 00                                                                            ###
// ### 00                                                                            ###
// ### 00                             SMLEndOfMessage                                ###
// ### 1b 1b 1b 1b                    Escape                                         ###
// ### 1a 02 19 49                    EndeMessage + CRC                              ###
// #####################################################################################
// ### Relevant data of SML-Protokoll (Example):                                     ###
// ###                                                                               ###
// ### Address     Value                       Binary                    Decimal     ###
// ### 150 - 157   Summe of positive energy    00 00 00 00 03 60 b0 55   56668245    ###
// ### 174 - 181   Positive energy "Tarif 1"   00 00 00 00 03 60 b0 55   56668245    ###
// ### 198 - 205   Positive energy "Tarif 2"   00 00 00 00 00 00 00 00   0           ###
// ### 226 - 233   Summe of negative energy    00 00 00 00 00 00 00 00   0           ###
// ### 250 - 257   Negative energy "Tarif 1"   00 00 00 00 00 00 00 00   0           ###
// ### 274 - 281   Negative energy "Tarif 2"   00 00 00 00 00 00 00 00   0           ###
// ### 298 - 301   Summe of power              00 00 02 57               599         ###
// ### 218 - 321   Power L1                    00 00 01 3a               314         ###
// ### 338 - 341   Power L2                    00 00 00 74               116         ###
// ### 258 - 361   Power L3                    00 00 00 aa               170         ###
// #####################################################################################
// ### Function of ESPReadEHZ:                                                       ###
// ###                                                                               ###
// ###  - Messages will be read in freely definable intervall                        ###
// ###  - Message will be decrypted and send via MQTT                                ###
// ###  - BuildIn Enduser Setup to configure WiFi                                    ###
// ###  - BuildIn NTP-Client to get actual Time                                      ###
// ###  - Calculating dayly, weekly, monthly and yearly consumption and also         ###
// ###    dayly, weekly, monthly and yearly accrued consumption and send this        ###
// ###    data via MQTT                                                              ###
// #####################################################################################
// ### MQTT-Topics:                                                                  ###
// ###                                                                               ###
// ###   [Topic]                                                                     ###
// ###      |- Energy                                                                ###
// ###      |  |--<< actual positive energy >>                                       ###
// ###      |  |--<< actual negative energy >>                                       ###
// ###      |  |- History                                                            ###
// ###      |     |- Dayly                                                           ###
// ###      |     |  |--<< positive energy of last day >>                            ###
// ###      |     |  |--<< negative energy of last day >>                            ###
// ###      |     |                                                                  ###
// ###      |     |- Weekly                                                          ###
// ###      |     |  |--<< positive energy of last week >>                           ###
// ###      |     |  |--<< negative energy of last week >>                           ###
// ###      |     |  |--<< positive accrued energy of last week >>                   ###
// ###      |     |  |--<< negative accrued energy of last week >>                   ###
// ###      |     |                                                                  ###
// ###      |     |- Monthly                                                         ###
// ###      |     |  |--<< positive energy of last month >>                          ###
// ###      |     |  |--<< negative energy of last month >>                          ###
// ###      |     |  |--<< positive accrued energy of last month >>                  ###
// ###      |     |  |--<< negative accrued energy of last month >>                  ###
// ###      |     |                                                                  ###
// ###      |     |- Yearly                                                          ###
// ###      |        |--<< positive energy of last year >>                           ###
// ###      |        |--<< negative energy of last year >>                           ###
// ###      |        |--<< positive accrued energy of last year >>                   ###
// ###      |        |--<< negative accrued energy of last year >>                   ###
// ###      |                                                                        ###
// ###      |- Power                                                                 ###
// ###         |- Sum                                                                ###
// ###         |  |--<< actual power over all >>                                     ###
// ###         |                                                                     ###
// ###         |- L1                                                                 ###
// ###         |  |--<< actual power L1 >>                                           ###
// ###         |                                                                     ###
// ###         |- L2                                                                 ###
// ###         |  |--<< actual power L2 >>                                           ###
// ###         |                                                                     ###
// ###         |- L3                                                                 ###
// ###            |--<< actual power L3 >>                                           ###
// #####################################################################################

// ##############################################################################################################################################################################
// ### Definitions & Variables ##################################################################################################################################################
// ##############################################################################################################################################################################
// *** Needed Librarys **********************************************************************************************************************************************************
#include <ESP8266WiFi.h>                                                              // Library for ESP8266-Usage
#include <ESP8266mDNS.h>                                                              // Library for mDNS-Usage
#include <WiFiUdp.h>                                                                  // Library for UDP-Communication
#include <WiFiManager.h>                                                              // Library for EndUser-Setup
#include <TimeLib.h>                                                                  // Library to handle Systemtime (Calendar)
#include <NtpClientLib.h>                                                             // Library for NTP-Usage
#include <ArduinoOTA.h>                                                               // Library for OTA-Flash
#include <PubSubClient.h>                                                             // Library for MQTT-Handling
#include <EEPROM.h>                                                                   // Library for EEPROM-Access
extern "C" {
  #include "user_interface.h"
}
// *** Needed Variables *********************************************************************************************************************************************************
static char hostname[] = "ESPReadEHZ";                                                // Networkname of Module                                  *** Hostname of Module        ***
String topic = "/ESPReadEHZ/";                                                        // MQTT-Topic for publishing                              *** MQTT-Topic for publishing ***
int WiFiManagerTimeout = 180;                                                         // Define Timeout for Wifi-Manager and set it to 180s     *** Timeout for WiFi-Manager  ***
int8_t timeZone = 1;                                                                  // Definition of time zone                                *** Actual Time Zone          ***
int NTPUpdateInterval = 28800;                                                        // Updateintervall for NTP                                *** Updateintervall for NTP   ***
unsigned long interval = 10000;                                                       // Variable to store interval of measurement              *** Interval of measurement   ***
const char* MQTT_BROKER = "192.168.43.1";                                             // IP of MQTT-Broker                                      *** IP of MQTT-Broker         ***
String top;                                                                           // Variable to combine Strings for Topic-String
int cf = 0;                                                                           // WiFi Connection flag
int8_t minutesTimeZone = 0;                                                           // Definition of time zone minutes
bool wifiFirstConnected = false;                                                      // Flag for first WiFi connection
byte inByte;                                                                          // Variable to buffer serial data byte-wise
byte smlMessage[459];                                                                 // variable to hold complete SML-Message
int smlIndex = 0;                                                                     // Variable to represent actual position in AML-Message
int startIndex = 0;                                                                   // Variable to store Index of Start-Sequenz
int stopIndex = 0;                                                                    // Variable to store Index of Stop-Sequenz
int state = 0;                                                                        // State of State-Machine
unsigned long LastTime = 0;                                                           // Variable to store last time of meassurement
unsigned long CurrentTime = 0;                                                        // Variable to store current time
String ausgabe;                                                                       // Variable for MQTT-Message
const byte startSequence[] = { 0x1B, 0x1B, 0x1B, 0x1B, 0x01, 0x01, 0x01, 0x01 };      // Escape-Sequenz & Start-Message
const byte stopSequence[]  = { 0x1B, 0x1B, 0x1B, 0x1B, 0x1A };                        // Escape-Sequenz & End-Message
byte SumPositiveActiveEnergy_lower[4];                                                // Lower 4 bytes of summe of positive active energy
byte SumPositiveActiveEnergy_upper[4];                                                // Upper 4 bytes of summe of positive active energy
byte T1_PositiveActiveEnergy_lower[4];                                                // Lower 4 bytes of positive active energy (Tarif 1)
byte T1_PositiveActiveEnergy_upper[4];                                                // Upper 4 bytes of positive active energy (Tarif 1)
byte T2_PositiveActiveEnergy_lower[4];                                                // Lower 4 bytes of positive active energy (Tarif 2)
byte T2_PositiveActiveEnergy_upper[4];                                                // Upper 4 bytes of positive active energy (Tarif 2)
byte SumNegativeActiveEnergy_lower[4];                                                // Lower 4 bytes of summe of negative active energy
byte SumNegativeActiveEnergy_upper[4];                                                // Upper 4 bytes of summe of negative active energy
byte T1_NegativeActiveEnergy_lower[4];                                                // Lower 4 bytes of negative active energy (Tarif 1)
byte T1_NegativeActiveEnergy_upper[4];                                                // Upper 4 bytes of negative active energy (Tarif 1)
byte T2_NegativeActiveEnergy_lower[4];                                                // Lower 4 bytes of negative active energy (Tarif 2)
byte T2_NegativeActiveEnergy_upper[4];                                                // Upper 4 bytes of negative active energy (Tarif 2)
byte SumActivePower[4];                                                               // Summe of active power
byte L1_ActivePower[4];                                                               // Active power of L1
byte L2_ActivePower[4];                                                               // Active power of L2
byte L3_ActivePower[4];                                                               // Active power of L3
double D_SumPositiveActiveEnergy_lower;                                               // Variable to store lower 4 bytes of summe of positive active energy as double
double D_SumPositiveActiveEnergy_upper;                                               // Variable to store upper 4 bytes of summe of positive active energy as double
double D_SumPositiveActiveEnergy_sum;                                                 // Variable to store complete 8 bytes of summe of positive active energy as double
double D_T1_PositiveActiveEnergy_lower;                                               // Variable to store lower 4 bytes of positive active energy (Tarif 1) as double
double D_T1_PositiveActiveEnergy_upper;                                               // Variable to store upper 4 bytes of positive active energy (Tarif 1) as double
double D_T1_PositiveActiveEnergy_sum;                                                 // Variable to store complete 8 bytes of positive active energy (Tarif 1) as double
double D_T2_PositiveActiveEnergy_lower;                                               // Variable to store lower 4 bytes of positive active energy (Tarif 2) as double
double D_T2_PositiveActiveEnergy_upper;                                               // Variable to store upper 4 bytes of positive active energy (Tarif 2) as double
double D_T2_PositiveActiveEnergy_sum;                                                 // Variable to store complete 8 bytes of positive active energy (Tarif 2) as double
double D_SumNegativeActiveEnergy_lower;                                               // Variable to store lower 4 bytes of summe of negative active energy as double
double D_SumNegativeActiveEnergy_upper;                                               // Variable to store upper 4 bytes of summe of negative active energy as double
double D_SumNegativeActiveEnergy_sum;                                                 // Variable to store complete 8 bytes of summe of negative active energy as double
double D_T1_NegativeActiveEnergy_lower;                                               // Variable to store lower 4 bytes of negative active energy (Tarif 1) as double
double D_T1_NegativeActiveEnergy_upper;                                               // Variable to store upper 4 bytes of negative active energy (Tarif 1) as double
double D_T1_NegativeActiveEnergy_sum;                                                 // Variable to store complete 8 bytes of negative active energy (Tarif 1) as double
double D_T2_NegativeActiveEnergy_lower;                                               // Variable to store lower 4 bytes of negative active energy (Tarif 2) as double
double D_T2_NegativeActiveEnergy_upper;                                               // Variable to store upper 4 bytes of negative active energy (Tarif 2) as double
double D_T2_NegativeActiveEnergy_sum;                                                 // Variable to store complete 8 bytes of negative active energy (Tarif 2) as double
double D_SumActivePower;                                                              // Variable to store Summe of active power as double
double D_L1_ActivePower;                                                              // Variable to store Active power of L1 as double
double D_L2_ActivePower;                                                              // Variable to store Active power of L2 as double
double D_L3_ActivePower;                                                              // Variable to store Active power of L3 as double
String Unit_SumPositiveActiveEnergy;                                                  // Variable to store unit of summe of positive active energy
String Unit_T1_PositiveActiveEnergy;                                                  // Variable to store unit of positive active energy (Tarif 1)
String Unit_T2_PositiveActiveEnergy;                                                  // Variable to store unit of positive active energy (Tarif 2)
String Unit_SumNegativeActiveEnergy;                                                  // Variable to store unit of summe of negative active energy
String Unit_T1_NegativeActiveEnergy;                                                  // Variable to store unit of negative active energy (Tarif 1)
String Unit_T2_NegativeActiveEnergy;                                                  // Variable to store unit of negative active energy (Tarif 2)
double D_PositiveEnergy_full;                                                         // Store summe of positive energy without canceling by decimal power
double D_NegativeEnergy_full;                                                         // Store summe of negative energy without canceling by decimal power
double D_PositiveEnergy_full_old_day;                                                 // Variable to store summe of positive energy (old value)  
double D_NegativeEnergy_full_old_day;                                                 // Variable to store summe of negative energy (old value)
double D_PositiveEnergy_full_old_week;                                                // Variable to store summe of positive energy (old value)  
double D_NegativeEnergy_full_old_week;                                                // Variable to store summe of negative energy (old value)
double D_PositiveEnergy_full_old_month;                                               // Variable to store summe of positive energy (old value)  
double D_NegativeEnergy_full_old_month;                                               // Variable to store summe of negative energy (old value)
double D_PositiveEnergy_full_old_year;                                                // Variable to store summe of positive energy (old value)  
double D_NegativeEnergy_full_old_year;                                                // Variable to store summe of negative energy (old value)
bool consumption_calculated = false;                                                  // Flag, if consumption was already calculated
// *** Needed Services **********************************************************************************************************************************************************
WiFiClient espClient;                                                                 // Create a client
PubSubClient client(espClient);                                                       // Create a PubSubClient-Object (MQTT)
boolean syncEventTriggered = false;                                                   // True if a time event has been triggered (NTP)
NTPSyncEvent_t ntpEvent;                                                              // Last triggered event (NTP)

// ##############################################################################################################################################################################
// ### Calback for Wifi got IP ##################################################################################################################################################
// ##############################################################################################################################################################################
void onSTAGotIP (WiFiEventStationModeGotIP ipInfo) {                                  // Callback if WiFi connection is established and IP gotten
  wifiFirstConnected = true;                                                          // Set flag
}

// ##############################################################################################################################################################################
// ### If MCTT-Client isn't connected => reconnect! #############################################################################################################################
// ##############################################################################################################################################################################
void reconnect() {
    while (!client.connected()) {                                                     // While MQTT isn't connected
        Serial.print("Reconnecting...");                                              // Debug print
        if (!client.connect("ESP8266Client")) {                                       // If client couldn't be connected
            Serial.print("failed, rc=");                                              // Debug print
            Serial.print(client.state());
            Serial.println(" retrying in 5 seconds");
            delay(5000);                                                              // Try again in 5s
        }
    }
}

// ##############################################################################################################################################################################
// ### Calback for NTP-Sync Event ###############################################################################################################################################
// ##############################################################################################################################################################################
void processSyncEvent (NTPSyncEvent_t ntpEvent) {                                     // Callback if NTP-Event happens
    if (ntpEvent) {                                                                   // If NTP-Error happens
        Serial.print ("Time Sync error: ");                                           // Debug printing
        if (ntpEvent == noResponse)                                                   // Dependent on kind of Error:
            Serial.println ("NTP server not reachable");                              // Debug printing
        else if (ntpEvent == invalidAddress)
            Serial.println ("Invalid NTP server address");
    } else {                                                                          // If no error occures
        Serial.print ("Got NTP time: ");                                              // Debug print Date/Time
        Serial.println (NTP.getTimeDateString (NTP.getLastNTPSync ()));
    }
}

// ##############################################################################################################################################################################
// ### Calback for Wifi Config Mode #############################################################################################################################################
// ##############################################################################################################################################################################
void configModeCallback (WiFiManager *myWiFiManager) {                                // Callback if WiFi-Manager enters config mode
    Serial.println("Entered config mode");                                            // Debug printing
    Serial.println(WiFi.softAPIP());
    Serial.println(myWiFiManager->getConfigPortalSSID());
}

// ##############################################################################################################################################################################
// ### Roputine to convert 4 Bytes of Hex into Double ###########################################################################################################################
// ##############################################################################################################################################################################
double byte4 (byte arr[]) {
  double out = long(arr[0]) << 24 | long(arr[1]) << 16 | long(arr[2]) << 8 | long(arr[3]);
  return out;
}

// ##############################################################################################################################################################################
// ### Roputine to convert 8 Bytes of Hex into Double ###########################################################################################################################
// ##############################################################################################################################################################################
double byte8 (byte arr_lower[], byte arr_upper[]) {
  double lower = (long(arr_lower[0]) << 24 |long(arr_lower[1]) << 16 | long(arr_lower[2]) << 8 | long(arr_lower[3]));
  double upper = (long(arr_upper[0]) << 24 |long(arr_upper[1]) << 16 | long(arr_upper[2]) << 8 | long(arr_upper[3]));
  lower /= 10000;                                                                     // Given by EHZ, value must be divided by 10000
  upper /= 10000;                                                                     // Given by EHZ, value must be divided by 10000
  double out = lower + (upper * 4294967295);                                          // FF FF FF FF => 4294967295
  return out;
}

// ##############################################################################################################################################################################
// ### Roputine to get the right unit, dependent of decimal power ###############################################################################################################
// ##############################################################################################################################################################################
String unit (double value) {
  String out;                                                                         // Define Variable to store output string
  if (value >= 1000000000000000) {                                                    // If Value >= 10^15
    out = "EWh";                                                                      // Then unit => EWh
    goto ende;
  } 
  if (value >= 1000000000000) {                                                       // If Value >= 10^12
    out = "PWh";                                                                      // Then unit => PWh
    goto ende;
  }
  if (value >= 1000000000) {                                                          // If Value >= 10^9
    out = "TWh";                                                                      // Then unit => TWh
    goto ende;
  }
  if (value >= 1000000) {                                                             // If Value >= 10^6
    out = "GWh";                                                                      // Then unit => GWh
    goto ende;
  }
  if (value >= 1000) {                                                                // If Value >= 10^3
    out = "MWh";                                                                      // Then unit => MWh
    goto ende;
  }
  out = "KWh";                                                                        // Else unit => KWh
  ende:
  return out;                                                                         // Return unit
}

// ##############################################################################################################################################################################
// ### Routine to shrink a kWh value by his decimal powers ######################################################################################################################
// ##############################################################################################################################################################################
double DecimalPower (double value) {
  if (value >= 1000000000000000) {                                                    // If value = Exa Wh
    value = value / 1000000000000000;                                                 // Devide value by decimal power of 15
    goto ende;
  } 
  if (value >= 1000000000000) {                                                       // If value = Peta Wh
    value = value / 1000000000000;                                                    // Devide value by decimal power of 12
    goto ende;
  }
  if (value >= 1000000000) {                                                          // If value = Terra Wh
    value = value / 1000000000;                                                       // Devide value by decimal power of 9
    goto ende;
  }
  if (value >= 1000000) {                                                             // If value = Giga Wh
    value = value / 1000000;                                                          // Devide value by decimal power of 6
    goto ende;
  }
  if (value >= 1000) {                                                                // If value = Mega Wh
    value = value / 1000;                                                             // Devide value by decimal power of 3
    goto ende;
  }
  ende:
  return value;                                                                       // Return value
}

// ##############################################################################################################################################################################
// ### Setup Routine ############################################################################################################################################################
// ##############################################################################################################################################################################
void setup() {
  static WiFiEventHandler e1;                                                         // Define WiFi-Handler
  e1 = WiFi.onStationModeGotIP (onSTAGotIP);                                          // As soon WiFi is connected, start NTP Client
// *** Initialize serial comunication *******************************************************************************************************************************************
  Serial.begin(9600);                                                                 // Begin serial communication
// *** Initialize WiFi **********************************************************************************************************************************************************
  delay(3000);                                                                        // Delay 3s
  wifi_station_set_hostname(hostname);                                                // Set station hostname
  WiFiManager wifiManager;                                                            // Define WiFi Manager
  wifiManager.setAPCallback(configModeCallback);                                      // Definition of callback for AP-Mode
  wifiManager.setConfigPortalTimeout(WiFiManagerTimeout);                             // Definition of timeout for AP-Mode
  if (!wifiManager.autoConnect("ESPReadEHZ")) {                                       // Start WiFi-Manager and check if connection is established, if not:
    Serial.println("Failed to connect and reboot");                                   // Debug printing
    delay(3000);                                                                      // Wait 3s
    ESP.restart();                                                                    // Software reset ESP
    delay(5000);                                                                      // Wait 5s
  }
// *** Serial printing status ***************************************************************************************************************************************************
  Serial.print("\n  Connecting to WiFi ");                                            // Debug printing
  Serial.println("\n\nWiFi connected.");                                              // Debug printing
  cf = 1;                                                                             // Set WiFi Conection Flag
  Serial.print("  IP address: " + WiFi.localIP().toString() + "\n");                  // Debug printing
  Serial.print("  Host name:  " + String(hostname) + "\n");
  Serial.print("- - - - - - - - - - - - - - - - - - -\n\n");
  delay(3000);                                                                        // Wait 3s
// *** NTP-Initialisation *******************************************************************************************************************************************************  
  NTP.onNTPSyncEvent ([](NTPSyncEvent_t event) {                                      // Handler for NTP-Events
    ntpEvent = event;                                                                 // Store NTP-Error Event
    syncEventTriggered = true;                                                        // Set flag for NTP-Sync
  });
// *** OTA-Initialisation *******************************************************************************************************************************************************  
  ArduinoOTA.setHostname("ESPReadEHZ");                                               // Set Hostname for OTA-Mode
  ArduinoOTA.onStart([]() {                                                           // OTA-Event onStart
    String type;                                                                      // Define string "type"
    if (ArduinoOTA.getCommand() == U_FLASH) {                                         // Dependent on flashtype
      type = "sketch";                                                                // Set type "sketch"
    } else { // U_SPIFFS
      type = "filesystem";                                                            // Set type "filesystem"
    }
    Serial.println("Start updating " + type);                                         // Debug print type
  });
  ArduinoOTA.onEnd([]() {                                                             // OTA-Event onEnd
    Serial.println("\nEnd");                                                          // Debug printing
  });
  ArduinoOTA.onProgress([](unsigned int progress, unsigned int total) {               // OTA-Event onProgress
    Serial.printf("Progress: %u%%\r", (progress / (total / 100)));                    // Debug print
  });
  ArduinoOTA.onError([](ota_error_t error) {                                          // OTA-Event onError
    Serial.printf("Error[%u]: ", error);                                              // Debug print errornumber
    if (error == OTA_AUTH_ERROR) {                                                    // Dependent on errornumber
      Serial.println("Auth Failed");                                                  // Print error type
    } else if (error == OTA_BEGIN_ERROR) {
      Serial.println("Begin Failed");
    } else if (error == OTA_CONNECT_ERROR) {
      Serial.println("Connect Failed");
    } else if (error == OTA_RECEIVE_ERROR) {
      Serial.println("Receive Failed");
    } else if (error == OTA_END_ERROR) {
      Serial.println("End Failed");
    }
  });
  ArduinoOTA.begin();                                                                 // Start OTA
// *** Initialize MQTT ********************************************************************************************************************************************************
  client.setServer(MQTT_BROKER, 1883);                                                // Start MQTT
}

// ##############################################################################################################################################################################
// ### Routine to identify Start Sequenz in SML-Message #########################################################################################################################
// ##############################################################################################################################################################################
void FindStartSequenz() {
  while (Serial.available()) {                                                        // As long as serial data is avaliable
    inByte = Serial.read();                                                           // Read byte-wise
    if (inByte == startSequence[startIndex]) {                                        // If bytes of Startsequenz are detected
      smlMessage[startIndex] = inByte;                                                // Write them into SML-Message Byte-Array
      startIndex++;
      if (startIndex == sizeof(startSequence)) {                                      // If complete start sequenz was detected
        state = 1;                                                                    // Set State-Machine to State 1
        smlIndex = startIndex;                                                        // Set Index for message detection
        startIndex = 0;
        Serial.println("Found Start-Sequenz, reading SML-Message...");
        break;
      }
    } else {
      startIndex = 0;                                                                 // Else looping
    }
  }
}

// ##############################################################################################################################################################################
// ### Routine to identify End Sequenz in SML-Message ###########################################################################################################################
// ##############################################################################################################################################################################
void FindEndSequenz() {
  while (Serial.available()) {                                                        // As long as serial data is avaliable
    inByte = Serial.read();                                                           // Read byte-wise
    smlMessage[smlIndex] = inByte;                                                    // Write bytes into SML-Message Byte-Array
    smlIndex++;
    if (inByte == stopSequence[stopIndex]) {                                          // Searching for Stop-Sequenz
      stopIndex++;
      if (stopIndex == sizeof(stopSequence)) {                                        // If complete Stop-Sequenz was found
        state = 2;                                                                    // Set State-Machine to State 2
        stopIndex = 0;                                                                // After the stop sequence, ther are sill 3 bytes to come
        delay(30);                                                                    // Wait for the rest of the message
        for (int c = 0 ; c < 3 ; c++) {                                               // And read, one for the amount of fillbytes plus two bytes for calculating CRC.
          smlMessage[smlIndex++] = Serial.read();
        }
        smlIndex--;
        Serial.println("Found Stop-Sequenz!");
      }
    } else {
      stopIndex = 0;
    }
  }
}

// ##############################################################################################################################################################################
// ### Routine to read data from SML-Message ####################################################################################################################################
// ##############################################################################################################################################################################
void ReadData() {
// **************** ONLY FOR DEBUGING (MANUAL DATA SHIFTED VIA FTDI-USB-MODULE INTO ESP) *********************************************************
//  for(int x = 0; x <= sizeof(smlMessage); x++) {                                      // For debuging only!!                     ***************
//    if (smlMessage[x] == 0x20) {                                                      // Windows detects 0x20 instead of 0x00    ***************
//      smlMessage[x] = 0x00;                                                           // correct this...                         ***************
//    }                                                                                 //                                         ***************
//  }                                                                                   //                                         ***************    
// ***********************************************************************************************************************************************
  smlIndex = 0;
  int count = 0;
  for (int x = 150; x <= 157; x++) {                                                  // Detection and storage of bytes (summe of positive active energy)
    if (count <= 3) {
      SumPositiveActiveEnergy_upper[count] = smlMessage[x];
    } else {
      SumPositiveActiveEnergy_lower[count - 4] = smlMessage[x];
    }
    count++;
  }
  count = 0;
  for (int x = 174; x <= 181; x++) {                                                  // Detection and storage of bytes (positive active energy "Tarif 1")
    if (count <= 3) {
      T1_PositiveActiveEnergy_upper[count] = smlMessage[x];
    } else {
      T1_PositiveActiveEnergy_lower[count - 4] = smlMessage[x];
    }
    count++;
  }
  count = 0;
  for (int x = 198; x <= 205; x++) {                                                  // Detection and storage of bytes (positive active energy "Tarif 2")
    if (count <= 3) {
      T2_PositiveActiveEnergy_upper[count] = smlMessage[x];
    } else {
      T2_PositiveActiveEnergy_lower[count - 4] = smlMessage[x];
    }
    count++;
  }
  count = 0;
  for (int x = 226; x <= 233; x++) {                                                  // Detection and storage of bytes (summe of negative active energy)
    if (count <= 3) {
      SumNegativeActiveEnergy_upper[count] = smlMessage[x];
    } else {
      SumNegativeActiveEnergy_lower[count - 4] = smlMessage[x];
    }
    count++;
  }
  count = 0;
  for (int x = 250; x <= 257; x++) {                                                  // Detection and storage of bytes (negative active energy "Tarif 1")
    if (count <= 3) {
      T1_NegativeActiveEnergy_upper[count] = smlMessage[x];
    } else {
      T1_NegativeActiveEnergy_lower[count - 4] = smlMessage[x];
    }
    count++;
  }
  count = 0;
  for (int x = 274; x <= 281; x++) {                                                  // Detection and storage of bytes (negative active energy "Tarif 2")
    if (count <= 3) {
      T2_NegativeActiveEnergy_upper[count] = smlMessage[x];
    } else {
      T2_NegativeActiveEnergy_lower[count - 4] = smlMessage[x];
    }
    count++;
  }
  count = 0;
  for (int x = 298; x <= 301; x++) {                                                  // Detection and storage of bytes (summe of active power)
    SumActivePower[count] = smlMessage[x];
    count++;
  }
  count = 0;
  for (int x = 318; x <= 321; x++) {                                                  // Detection and storage of bytes (active power at L1)
    L1_ActivePower[count] = smlMessage[x];
    count++;
  }
  count = 0;
  for (int x = 338; x <= 341; x++) {                                                  // Detection and storage of bytes (active power at L2)
    L2_ActivePower[count] = smlMessage[x];
    count++;
  }
  count = 0;
  for (int x = 358; x <= 361; x++) {                                                  // Detection and storage of bytes (active power at L3)
    L3_ActivePower[count] = smlMessage[x];
    count++;
  }
  count = 0;
  D_SumPositiveActiveEnergy_sum = byte8(SumPositiveActiveEnergy_lower, SumPositiveActiveEnergy_upper);  // Build double variable from 2x 4 byte variables
  D_T1_PositiveActiveEnergy_sum = byte8(T1_PositiveActiveEnergy_lower, T1_PositiveActiveEnergy_upper);
  D_T2_PositiveActiveEnergy_sum = byte8(T2_PositiveActiveEnergy_lower, T2_PositiveActiveEnergy_upper);
  D_SumNegativeActiveEnergy_sum = byte8(SumNegativeActiveEnergy_lower, SumNegativeActiveEnergy_upper);
  D_T1_NegativeActiveEnergy_sum = byte8(T1_NegativeActiveEnergy_lower, T1_NegativeActiveEnergy_upper);
  D_T2_NegativeActiveEnergy_sum = byte8(T2_NegativeActiveEnergy_lower, T2_NegativeActiveEnergy_upper);
  D_SumActivePower = byte4(SumActivePower);                                                             // Build double variable from 4 byte variable
  D_L1_ActivePower = byte4(L1_ActivePower);
  D_L2_ActivePower = byte4(L2_ActivePower);
  D_L3_ActivePower = byte4(L3_ActivePower);
  Unit_SumPositiveActiveEnergy = unit(D_SumPositiveActiveEnergy_sum);                                   // Get unit for corespondent value
  Unit_T1_PositiveActiveEnergy = unit(D_T1_PositiveActiveEnergy_sum);
  Unit_T2_PositiveActiveEnergy = unit(D_T2_PositiveActiveEnergy_sum);
  Unit_SumNegativeActiveEnergy = unit(D_SumNegativeActiveEnergy_sum);
  Unit_T1_NegativeActiveEnergy = unit(D_T1_NegativeActiveEnergy_sum);
  Unit_T2_NegativeActiveEnergy = unit(D_T2_NegativeActiveEnergy_sum);
  D_PositiveEnergy_full = D_SumPositiveActiveEnergy_sum;                                                // Store summe of positive energy without canceling by deciam power
  D_NegativeEnergy_full = D_SumNegativeActiveEnergy_sum;                                                // Store summe of negative energy without canceling by deciam power
  D_SumPositiveActiveEnergy_sum = DecimalPower(D_SumPositiveActiveEnergy_sum);                          // Shrink value by his decimal powers
  D_T1_PositiveActiveEnergy_sum = DecimalPower(D_T1_PositiveActiveEnergy_sum);
  D_T2_PositiveActiveEnergy_sum = DecimalPower(D_T2_PositiveActiveEnergy_sum);
  D_SumNegativeActiveEnergy_sum = DecimalPower(D_SumNegativeActiveEnergy_sum);
  D_T1_NegativeActiveEnergy_sum = DecimalPower(D_T1_NegativeActiveEnergy_sum);
  D_T2_NegativeActiveEnergy_sum = DecimalPower(D_T2_NegativeActiveEnergy_sum);
  Serial.println ("");                                                                                  // Debug print
  Serial.println ("Active Power Sum: " + String(D_SumActivePower) + " W");
  Serial.println ("Active Power L1:  " + String(D_L1_ActivePower) + " W");
  Serial.println ("Active Power L2:  " + String(D_L2_ActivePower) + " W");
  Serial.println ("Active Power L3:  " + String(D_L3_ActivePower) + " W");
  Serial.println("");
  Serial.println ("Positive Active Energy Sum: " + String(D_SumPositiveActiveEnergy_sum) + Unit_SumPositiveActiveEnergy);
  Serial.println ("Positive Active Energy T1 : " + String(D_T1_PositiveActiveEnergy_sum) + Unit_T1_PositiveActiveEnergy);
  Serial.println ("Positive Active Energy T2 : " + String(D_T2_PositiveActiveEnergy_sum) + Unit_T2_PositiveActiveEnergy);
  Serial.println ("Negative Active Energy Sum: " + String(D_SumNegativeActiveEnergy_sum) + Unit_SumNegativeActiveEnergy);
  Serial.println ("Negative Active Energy T1 : " + String(D_T1_NegativeActiveEnergy_sum) + Unit_T1_NegativeActiveEnergy);
  Serial.println ("Negative Active Energy T1 : " + String(D_T2_NegativeActiveEnergy_sum) + Unit_T2_NegativeActiveEnergy);
  Serial.println ("");
  ausgabe = "Pos. Energie: " + String(D_SumPositiveActiveEnergy_sum) + Unit_SumPositiveActiveEnergy;  // Build strings to send to MQTT-Broker and send it
  top = topic + "Energy";                                                                             // Built topic to sent message to
  client.publish(top.c_str(), ausgabe.c_str());                                                       // Publish MQTT-Message
  ausgabe = "Neg. Energie: " + String(D_SumNegativeActiveEnergy_sum) + Unit_SumNegativeActiveEnergy;
  top = topic + "Energy";
  client.publish(top.c_str(), ausgabe.c_str());
  ausgabe = "Leistung Gesamt: " + String(D_SumActivePower) + " W";
  top = topic + "Power/Sum";
  client.publish(top.c_str(), ausgabe.c_str());
  ausgabe = "Leistung Gesamt: " + String(D_L1_ActivePower) + " W";
  top = topic + "Power/L1";
  client.publish(top.c_str(), ausgabe.c_str());
  ausgabe = "Leistung Gesamt: " + String(D_L2_ActivePower) + " W";
  top = topic + "Power/L2";
  client.publish(top.c_str(), ausgabe.c_str());
  ausgabe = "Leistung Gesamt: " + String(D_L3_ActivePower) + " W";
  top = topic + "Power/L3";
  client.publish(top.c_str(), ausgabe.c_str());
  state = 3;                                                                          // Set State-Machine to State 3
  Serial.println("SML-Message decrypted, sended, goto sleep...");
  CurrentTime = millis();                                                             // Get actual time
  LastTime = CurrentTime;                                                             // Store actual time as "Last read-time"
}

// ##############################################################################################################################################################################
// ### Routine to wait during two MQTT-Sendings #################################################################################################################################
// ##############################################################################################################################################################################
void WaitSomeTime() {
  CurrentTime = millis();                                                             // Get current time
  if ((CurrentTime - LastTime) >= interval) {                                         // Wait interval-time until seting State-Machine to State 0
    LastTime = CurrentTime;
    state = 0;
    Serial.println("Searching for Start-Sequenz...");
    consumption();
  }
}

// ##############################################################################################################################################################################
// ### Routine to get summe consumption values (day, week, month, year) #########################################################################################################
// ##############################################################################################################################################################################
void consumption() {
  if ((hour() == 0) && (minute() == 0) && (consumption_calculated == false)) {                                                                          // Every Midnight, but only once:
    consumption_calculated = true;                                                                                                                      // Flag for doing only once
    D_PositiveEnergy_full_old_day = eeReadDouble(10);                                                                                                   // Read data from EEProm
    double dayly_consumption_positive = D_PositiveEnergy_full - D_PositiveEnergy_full_old_day;                                                          // Calculate dayly positive consumption for last day
    ausgabe = "Pos. Energie d: " + String(DecimalPower(dayly_consumption_positive)) + String(unit(dayly_consumption_positive));                         // Build string to send via MQTT
    top = topic + "Energy/History/Dayly";
    client.publish(top.c_str(), ausgabe.c_str());                                                                                                       // Publish string to MQTT
    D_NegativeEnergy_full_old_day = eeReadDouble(20);                                                                                                   // Read data from EEProm
    double dayly_consumption_negative = D_NegativeEnergy_full - D_NegativeEnergy_full_old_day;                                                          // Calculate dayly negative consumption for last day
    ausgabe = "Neg. Energie d: " + String(DecimalPower(dayly_consumption_negative)) + String(unit(dayly_consumption_negative));                         // Build string to send via MQTT
    top = topic + "Energy/History/Dayly";
    client.publish(top.c_str(), ausgabe.c_str());                                                                                                       // Publish string to MQTT
    D_PositiveEnergy_full_old_day = D_PositiveEnergy_full;                                                                                              // Store actual values to calculate next value
    eeWriteDouble(10, D_PositiveEnergy_full_old_day);                                                                                                   // Write data to EEPROM
    D_NegativeEnergy_full_old_day = D_NegativeEnergy_full;                                                                                              // Store actual values to calculate next value
    eeWriteDouble(20, D_NegativeEnergy_full_old_day);                                                                                                   // Write data to EEPROM
    D_PositiveEnergy_full_old_week = eeReadDouble(30);                                                                                                  // Read data from EEProm
    double weekly_consumption_positive_accrued = D_PositiveEnergy_full - D_PositiveEnergy_full_old_week;                                                // Calculate accrued weekly positive consumption
    ausgabe = "Pos. Energie w_a: " + String(DecimalPower(weekly_consumption_positive_accrued)) + String(unit(weekly_consumption_positive_accrued));     // Build string to send via MQTT
    top = topic + "Energy/History/Weekly";
    client.publish(top.c_str(), ausgabe.c_str());                                                                                                       // Publish string to MQTT
    D_NegativeEnergy_full_old_week = eeReadDouble(40);                                                                                                  // Read data from EEProm
    double weekly_consumption_negative_accrued = D_NegativeEnergy_full - D_NegativeEnergy_full_old_week;                                                // Calculate accrued weekly negative consumption
    ausgabe = "Neg. Energie w_a: " + String(DecimalPower(weekly_consumption_negative_accrued)) + String(unit(weekly_consumption_negative_accrued));     // Build string to send via MQTT
    top = topic + "Energy/History/Weekly";
    client.publish(top.c_str(), ausgabe.c_str());                                                                                                       // Publish string to MQTT
    D_PositiveEnergy_full_old_month = eeReadDouble(50);                                                                                                 // Read data from EEProm
    double monthly_consumption_positive_accrued = D_PositiveEnergy_full - D_PositiveEnergy_full_old_month;                                              // Calculate accrued monthly positive consumption
    ausgabe = "Pos. Energie m_a: " + String(DecimalPower(monthly_consumption_positive_accrued)) + String(unit(monthly_consumption_positive_accrued));   // Build string to send via MQTT
    top = topic + "Energy/History/Monthly";
    client.publish(top.c_str(), ausgabe.c_str());                                                                                                       // Publish string to MQTT
    D_NegativeEnergy_full_old_month = eeReadDouble(60);                                                                                                 // Read data from EEProm
    double monthly_consumption_negative_accrued = D_NegativeEnergy_full - D_NegativeEnergy_full_old_month;                                              // Calculate accrued monthly negative consumption
    ausgabe = "Neg. Energie m_a: " + String(DecimalPower(monthly_consumption_negative_accrued)) + String(unit(monthly_consumption_negative_accrued));   // Build string to send via MQTT
    top = topic + "Energy/History/Monthly";
    client.publish(top.c_str(), ausgabe.c_str());                                                                                                       // Publish string to MQTT
    D_PositiveEnergy_full_old_year = eeReadDouble(70);                                                                                                  // Read data from EEProm
    double yearly_consumption_positive_accrued = D_PositiveEnergy_full - D_PositiveEnergy_full_old_year;                                                // Calculate accrued yearly positive consumption
    ausgabe = "Pos. Energie a_a: " + String(DecimalPower(yearly_consumption_positive_accrued)) + String(unit(yearly_consumption_positive_accrued));     // Build string to send via MQTT
    top = topic + "Energy/History/Yearly";
    client.publish(top.c_str(), ausgabe.c_str());                                                                                                       // Publish string to MQTT
    D_NegativeEnergy_full_old_year = eeReadDouble(80);                                                                                                  // Read data from EEProm
    double yearly_consumption_negative_accrued = D_NegativeEnergy_full - D_NegativeEnergy_full_old_year;                                                // Calculate accrued yearly negative consumption
    ausgabe = "Neg. Energie a_a: " + String(DecimalPower(yearly_consumption_negative_accrued)) + String(unit(yearly_consumption_negative_accrued));     // Build string to send via MQTT
    top = topic + "Energy/History/Yearly";
    client.publish(top.c_str(), ausgabe.c_str());                                                                                                       // Publish string to MQTT
    if (weekday() == 2) {                                                                                                                               // Every Monday 00:00:
      D_PositiveEnergy_full_old_week = eeReadDouble(30);                                                                                                // Read data from EEProm
      double weekly_consumption_positive = D_PositiveEnergy_full - D_PositiveEnergy_full_old_week;                                                      // Calculate weekly positive consumption for last week
      ausgabe = "Pos. Energie w: " + String(DecimalPower(weekly_consumption_positive)) + String(unit(weekly_consumption_positive));                     // Build string to send via MQTT
      top = topic + "Energy/History/Weekly";
      client.publish(top.c_str(), ausgabe.c_str());                                                                                                     // Publish string to MQTT
      D_NegativeEnergy_full_old_week = eeReadDouble(40);                                                                                                // Read data from EEProm
      double weekly_consumption_negative = D_NegativeEnergy_full - D_NegativeEnergy_full_old_week;                                                      // Calculate weekly negative consumption for last week
      ausgabe = "Neg. Energie w: " + String(DecimalPower(weekly_consumption_negative)) + String(unit(weekly_consumption_negative));                     // Build string to send via MQTT
      top = topic + "Energy/History/Weekly";
      client.publish(top.c_str(), ausgabe.c_str());                                                                                                     // Publish string to MQTT
      D_PositiveEnergy_full_old_week = D_PositiveEnergy_full;                                                                                           // Store actual values to calculate next value
      eeWriteDouble(30, D_PositiveEnergy_full_old_week);                                                                                                // Write data to EEPROM
      D_NegativeEnergy_full_old_week = D_NegativeEnergy_full;                                                                                           // Store actual values to calculate next value
      eeWriteDouble(40, D_NegativeEnergy_full_old_week);                                                                                                // Write data to EEPROM
    }
    if (day() == 1) {                                                                                                                                   // Every 1st of month 00:00:
      D_PositiveEnergy_full_old_month = eeReadDouble(50);                                                                                               // Read data from EEProm
      double monthly_consumption_positive = D_PositiveEnergy_full - D_PositiveEnergy_full_old_month;                                                    // Calculate monthly positive consumption for last month
      ausgabe = "Pos. Energie m: " + String(DecimalPower(monthly_consumption_positive)) + String(unit(monthly_consumption_positive));                   // Build string to send via MQTT
      top = topic + "Energy/History/Monthly";
      client.publish(top.c_str(), ausgabe.c_str());                                                                                                     // Publish string to MQTT
      D_NegativeEnergy_full_old_month = eeReadDouble(60);                                                                                               // Read data from EEProm
      double monthly_consumption_negative = D_NegativeEnergy_full - D_NegativeEnergy_full_old_month;                                                    // Calculate monthly negative consumption for last month
      ausgabe = "Neg. Energie m: " + String(DecimalPower(monthly_consumption_negative)) + String(unit(monthly_consumption_negative));                   // Build string to send via MQTT
      top = topic + "Energy/History/Monthly";
      client.publish(top.c_str(), ausgabe.c_str());                                                                                                     // Publish string to MQTT
      D_PositiveEnergy_full_old_month = D_PositiveEnergy_full;                                                                                          // Store actual values to calculate next value
      eeWriteDouble(50, D_PositiveEnergy_full_old_month);                                                                                               // Write data to EEPROM
      D_NegativeEnergy_full_old_month = D_NegativeEnergy_full;                                                                                          // Store actual values to calculate next value
      eeWriteDouble(60, D_NegativeEnergy_full_old_month);                                                                                               // Write data to EEPROM
      if (month() == 1) {                                                                                                                               // Every 1st January 00:00:
        D_PositiveEnergy_full_old_year = eeReadDouble(70);                                                                                              // Read data from EEProm
        double yearly_consumption_positive = D_PositiveEnergy_full - D_PositiveEnergy_full_old_year;                                                    // Calculate yearly positive consumption for last year
        ausgabe = "Pos. Energie a: " + String(DecimalPower(yearly_consumption_positive)) + String(unit(yearly_consumption_positive));                   // Build string to send via MQTT
        top = topic + "Energy/History/Yearly";
        client.publish(top.c_str(), ausgabe.c_str());                                                                                                   // Publish string to MQTT
        D_NegativeEnergy_full_old_year = eeReadDouble(80);                                                                                              // Read data from EEProm
        double yearly_consumption_negative = D_NegativeEnergy_full - D_NegativeEnergy_full_old_year;                                                    // Calculate yearly negative consumption for last year
        ausgabe = "Neg. Energie a: " + String(DecimalPower(yearly_consumption_negative)) + String(unit(yearly_consumption_negative));                   // Build string to send via MQTT
        top = topic + "Energy/History/Yearly";
        client.publish(top.c_str(), ausgabe.c_str());                                                                                                   // Publish string to MQTT
        D_PositiveEnergy_full_old_year = D_PositiveEnergy_full;                                                                                         // Store actual values to calculate next value
        eeWriteDouble(70, D_PositiveEnergy_full_old_year);                                                                                              // Write data to EEPROM
        D_NegativeEnergy_full_old_year = D_NegativeEnergy_full;                                                                                         // Store actual values to calculate next value
        eeWriteDouble(80, D_NegativeEnergy_full_old_year);                                                                                              // Write data to EEPROM
      }
    }
  } else {                                                                                                                                              // If actual time != 00:00
    consumption_calculated = false;                                                                                                                     // Reset flag => new calculation possible
  }
}

// ##############################################################################################################################################################################
// ### Routine to write a double to EEProm ######################################################################################################################################
// ##############################################################################################################################################################################
void eeWriteDouble(int pos, double val) {
    byte* p = (byte*) &val;
    EEPROM.begin(512);                                                                  // Initialize EEPROM with 512 Bytes size
    EEPROM.write(pos, *p);                                                              // Wirte EEPROM byte-wise
    EEPROM.write(pos + 1, *(p + 1));
    EEPROM.write(pos + 2, *(p + 2));
    EEPROM.write(pos + 3, *(p + 3));
    EEPROM.write(pos + 4, *(p + 4));
    EEPROM.write(pos + 5, *(p + 5));
    EEPROM.write(pos + 6, *(p + 6));
    EEPROM.write(pos + 7, *(p + 7));
    EEPROM.commit();
    EEPROM.end();                                                                       // Free RAM copy of structure
}

// ##############################################################################################################################################################################
// ### Routine to read a double from EEProm #####################################################################################################################################
// ##############################################################################################################################################################################
double eeReadDouble(int pos) {
  double val;
  byte* p = (byte*) &val;
  EEPROM.begin(512);                                                                  // Initialize EEPROM with 512 Bytes size
  *p        = EEPROM.read(pos);                                                       // Read EEPROM byte-wise
  *(p + 1)  = EEPROM.read(pos + 1);
  *(p + 2)  = EEPROM.read(pos + 2);
  *(p + 3)  = EEPROM.read(pos + 3);
  *(p + 4)  = EEPROM.read(pos + 4);
  *(p + 5)  = EEPROM.read(pos + 5);
  *(p + 6)  = EEPROM.read(pos + 6);
  *(p + 7)  = EEPROM.read(pos + 7);
  EEPROM.end();                                                                       // Free RAM copy of structure
  return val;
}

// ##############################################################################################################################################################################
// ### Main programm ############################################################################################################################################################
// ##############################################################################################################################################################################
void loop() {
  if (wifiFirstConnected) {                                                           // Start NTP if IP is gotten
    wifiFirstConnected = false;                                                       // Reset Flag, NTP-Initialisation just 1x
    NTP.begin ("pool.ntp.org", timeZone, true, minutesTimeZone);                      // Start NTP
    NTP.setInterval (NTPUpdateInterval);                                              // Set NTP-Intervall to 63s
  }
  if (syncEventTriggered) {                                                           // If Sync-Event, handle it
    processSyncEvent (ntpEvent);                                                      // Do syncronisation
    syncEventTriggered = false;                                                       // Reset Trigger-Flag
  }
  ArduinoOTA.handle();                                                                // Start OTA-Handle
  switch (state) {                                                                    // State-Machine
    case 0:
      FindStartSequenz();
      break;
    case 1:
      FindEndSequenz();
      break;
    case 2:
      ReadData();
      break;
    case 3:
      WaitSomeTime();
      break;
  }
  if (!client.connected()) {                                                          // If MQTT-Client isn't connected
    reconnect();                                                                      // Reconnect!
  }
  client.loop();
}
