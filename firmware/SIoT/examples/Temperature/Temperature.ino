/*
 * A SIoT device, in as little sketch as one takes (roadmap 5.7).
 *
 * Reads the ESP32's internal temperature and uploads it every thirty seconds,
 * encrypted so that the server storing it cannot read it. There is no crypto in
 * this file and there is not meant to be: everything below `addReading` is the
 * library's problem, which is the whole claim design Section 6 makes.
 *
 * ## Before this will run
 *
 * 1. Flash `firmware/esp32-provisioning` once and provision the board from the
 *    SIoT web client. The credentials go into their own NVS partition, so
 *    uploading this sketch over the top leaves them exactly where they are.
 * 2. Copy secrets.example.h to secrets.h and fill it in.
 * 3. Put `partitions.csv` from `firmware/esp32-provisioning` beside this sketch,
 *    or select a partition scheme that includes the `siot` partition. Without
 *    it `begin()` reports NotProvisioned, because the credentials are sitting at
 *    an address this image's partition table does not describe.
 *
 * ## The certificate is not optional
 *
 * `SERVER_CERT` (in secrets.h) pins what this device will talk to. A phone or a laptop has
 * somebody to notice a warning page; a sensor in a greenhouse does not, so an
 * unpinned device is one that hands its records to whatever answers on that
 * address. For the dev server, paste `backend/certs/dev-cert.pem` in whole,
 * which is self-signed and therefore its own root. Regenerating that
 * certificate means reflashing every device that pinned it.
 */

#include <SIoT.h>
#include <WiFi.h>
#include <time.h>

#include "secrets.h"

/* WIFI_SSID, WIFI_PASSWORD, SERVER_URL and SERVER_CERT live in secrets.h, which
   is gitignored. Copy secrets.example.h to secrets.h and fill it in. */
const char *SERVER_CERT_PEM = SERVER_CERT;

static const uint32_t REPORT_INTERVAL_MS = 30000;

SIoTClient siot;

void setup() {
  Serial.begin(115200);
  delay(200);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("wifi");
  /* Bounded, so a wrong password reads as a named failure rather than a hang. */
  const uint32_t wifiStart = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - wifiStart < 20000) {
    delay(400);
    Serial.print(".");
  }
  if (WiFi.status() != WL_CONNECTED) {
    /* 1 = no such network, 4 = connect failed, 6 = disconnected (the generic "never
       associated": a wrong password and an unreachable band both land here). */
    Serial.printf(" failed, WiFi.status() = %d\n", WiFi.status());
    return;
  }
  Serial.printf(" %s -> %s\n", WiFi.localIP().toString().c_str(), SERVER_URL);

  /* The device's own timestamp travels inside the encrypted payload. `seq` is
     the authoritative order, so a device with no route to NTP is still fully
     functional. But the TLS handshake checks the pinned certificate's validity
     dates against this clock, so a board still at 1970 can reject a correct pin;
     waiting here, and saying so, rules that out before the pin is blamed. */
  configTime(0, 0, "pool.ntp.org");
  const uint32_t ntpStart = millis();
  while (time(nullptr) < 1700000000 && millis() - ntpStart < 10000) delay(200);
  if (time(nullptr) < 1700000000) {
    Serial.println("clock: not set (no NTP). A TLS date check may fail.");
  } else {
    Serial.println("clock: set");
  }

  siot.setServer(SERVER_URL, SERVER_CERT_PEM);
  if (!siot.begin()) {
    Serial.printf("SIoT: %s\n", siot.lastError());
    return;
  }

  Serial.printf("SIoT: device %s, boot epoch %u\n", siot.deviceId(), siot.bootEpoch());
}

void loop() {
  if (siot.bootEpoch() == 0) {
    // begin() failed. Nothing to do but say so at a rate nobody has to scroll past.
    delay(10000);
    return;
  }

  siot.addReading("temp_c", temperatureRead());
  siot.addReading("rssi", WiFi.RSSI());
  siot.addReading("heap_free", (long long)ESP.getFreeHeap());

  const SIoTStatus status = siot.send();
  if (status == SIoTStatus::Ok) {
    Serial.printf("sent record %u of boot %u\n", siot.messageCount(), siot.bootEpoch());
  } else {
    Serial.printf("send failed (%s): %s\n", SIoTStatusName(status), siot.lastError());
  }

  /* A deleted device is not a transient failure and never becomes one again.
     Stopping is the correct response: retrying forever is a board flattening
     its battery against a server that will never accept it. */
  if (siot.isDeleted()) {
    Serial.println("this device has been deleted; provision the board for a new one");
    while (true) delay(60000);
  }

  delay(REPORT_INTERVAL_MS);
}
