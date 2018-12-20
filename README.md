# ESPReadEHZ
## ESP8266 based eHZ Reader (via optical interface) for ISKRA MT681

**Version History**

- ESPReadEHZ V1.0  12/2018  1st official public Version

**Vision**

Inspired by a collegue wich tryed to read his electric meter via its implemented opical interface, I start to build a ESP-12F based solution to read my own elecric meter. By using OpenHAB as SmartHome platform, I wanted to get all read information via MQTT to my Raspberry Pi to collect, store and visualize it by the OpenHab frontends.

![Smart Electric Meter](/Pictures/electric_meter.jpg)

**Optical interface & SML-Protocol**

As mentioned, my electric meter (ISKRA MT681) has a bidirectional optical interface. Via this interface, the enduser can change settings of the MT681 by flashing the sensor with a flashlight and also the electric meter sends its data periodically as serial data (9600/8N1). [The data itself is coded as a SML-Protokoll (SmartMessageLanguage).]()
To receive this data, a simple SFH309 Phototransistor works in a grounded emitter circuit and translate the optical information in the correspondet electrical data to process with ESP-12F.

**Software**

The software works as a statemachine. At firs the program try to find the Start-Sequence (1B 1B 1B 1B 01 01 01 01) of the SML-Data. If this data is detected, the founded and also the following bytes will be stored until the End-Sequence (1B 1B 1B 1B 1A) will be detected. After that, the needed information (e.g. current power, positive/negative energy...) will be extracted, concentrated and sent via MQTT to the MQTT-Broker of my SmartHome-System.

**Functions**

- Information will be sent by MQTT-Messages in freely definable intervall
- BuildIn Enduser Setup to configure WiFi
- BuildIn NTP-Client to get actual Time
- Calculating dayly, weekly, monthly and yearly consumption and also dayly, weekly, monthly and yearly accrued consumption and send this data via MQTT       
