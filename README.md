# ESPReadEHZ
## ESP8266 based eHZ Reader (via optical interface) for ISKRA MT681

**Version History**

- ESPReadEHZ V1.0  12/2018  1st official public Version

**Vision**

Inspired by a collegue wich tryed to read his electric meter via its implemented opical interface, I start to build a ESP-12F based solution to read my own elecric meter. By using OpenHAB as SmartHome platform, I wanted to get all read information via MQTT to my Raspberry Pi to collect, store and visualize it by the OpenHab frontends.

**Optical interface & SML-Protocol**

As mentioned, my electric meter (ISKRA MT681) has a bidirectional optical interface. Via this interface, the enduser can change settings of the MT681 by flashing the sensor with a flashlight and also the electric meter sends its data periodically as serial data (9600/8N1). The data itself is coded as a SML-Protokoll (SmartMessageLanguage).
To receive this data, a simple SFH309 Phototransistor works in a grounded emitter circuit and translate the optical information in the correspondet electrical data to process with ESP-12F.

**Software**

The software works as a statemachine. At firs the program try to find the Start-Sequence (1B 1B 1B 1B 01 01 01 01) of the SML-Data. If this data is detected, the founded and also the following bytes will be stored until the End-Sequence (1B 1B 1B 1B 1A) will be detected. After that, the needed information (e.g. current power, positive/negative energy...) will be extracted, concentrated and sent via MQTT to the MQTT-Broker of my SmartHome-System.

Protokol of SML-Message:

| Data | Information |
|------|-------------|
| 1b 1b 1b 1b 01 01 01 01 | Escape + StartMessage |
| 76 | |
| 05 00 62 b7 a1 | transactionID (5Byte) |
| 62 00 | groupNo |
| 62 00 | abortOnError |
| 72 | |
| 63 01 01 | Message 0101 = SML_PublicOpen.Res |
| 76 | |
| 01 | codepage |
| 01 | clientID |
| 05 00 20 e7 df | reqFileID |
| 09 xx xx xx xx xx xx xx xx | ServerID |
| 01 | refTime |
| 01 | smlVersion |
| 63 de c8 | CRC |
| 00 | SMLEndOfMessage |
| 76 | |
| 05 00 62 b7 a2 | transactionID (5Byte) |
| 62 00 | groupNo |
| 62 00 | abortOnError |
| 72 | |
| 63 07 01 | Message 0701 = SML_GetList.Res |
| 77 | |
| 01 | |
| 09 xx xx xx xx xx xx xx xx | ServerID |
| 07 | |
| 01 | |
| 00 62 0a ff ff | |
| 72 | |
| 62 01 | secIndex = 1 |
| 65 00 33 5e dd 7d | Seconds-Index as unsigned 32 |
| 77 | |
| 07 81 81 c7 82 03 ff | objName 129-129:199.130.3 x 255 |
| 01 | status (empty) |
| 01 | valTime (empty) |
| 01 | unit(empty) |
| 01 | scaler (empty) |
| 04 49 53 4b | Value |
| 01 | valueSignature (empty) |
| 77 | |
| 07 01 00 00 00 09 ff | objName 1-0:0.0.9 x 255 |
| 01 | status (empty) |
| 01 | valTime (empty) |
| 01 | unit(empty) |
| 01 | scaler (empty) |
| 09 xx xx xx xx xx xx xx xx | Server-ID:
| 01 | |
| 77 | |
| 07 01 00 01 08 00 ff | objName 1-0:1.8.0 x 255 |
| Positive summe of energy (A+) |
| 65 00 | |
| 01 | |
| 01 | |
| 82 01 | |
| 62 1e | unit (unsigned8) 1E = Wh |
| 52 ff | scaler (int8) -1 = x 10^-1 = /10 |
| 59 00 00 00 00 00 37 00 e2 | value = 3604706 => 360470,6 = 360,47 kWh |
| 01 | |
| 77 | |

