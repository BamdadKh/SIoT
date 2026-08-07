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
 * 2. Fill in the three values below.
 * 3. Put `partitions.csv` from `firmware/esp32-provisioning` beside this sketch,
 *    or select a partition scheme that includes the `siot` partition. Without
 *    it `begin()` reports NotProvisioned, because the credentials are sitting at
 *    an address this image's partition table does not describe.
 *
 * ## The certificate is not optional
 *
 * `SERVER_CERT` pins what this device will talk to. A phone or a laptop has
 * somebody to notice a warning page; a sensor in a greenhouse does not, so an
 * unpinned device is one that hands its records to whatever answers on that
 * address. For the dev server, paste `backend/certs/dev-cert.pem` in whole,
 * which is self-signed and therefore its own root. Regenerating that
 * certificate means reflashing every device that pinned it.
 */

#include <SIoT.h>
#include <WiFi.h>
#include <time.h>

const char *WIFI_SSID = "your-network";
const char *WIFI_PASSWORD = "your-password";

/* No trailing slash. The dev certificate's SANs cover this machine's LAN
   addresses as well as localhost, so a device can reach it by IP and still
   validate; `npm run gen-cert` in backend/ prints them. */
const char *SERVER_URL = "https://192.168.1.20:3030";

const char *SERVER_CERT = R"CERT(
-----BEGIN CERTIFICATE-----
paste backend/certs/dev-cert.pem here, including these BEGIN and END lines
-----END CERTIFICATE-----
)CERT";

static const uint32_t REPORT_INTERVAL_MS = 30000;

SIoTClient siot;

void setup() {
  Serial.begin(115200);
  delay(200);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("wifi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(400);
    Serial.print(".");
  }
  Serial.printf(" %s\n", WiFi.localIP().toString().c_str());

  /* The device's own timestamp travels inside the encrypted payload. It is
     optional: without it the library sends 0, which a client renders as "this
     device has no clock" rather than as 1970. `seq` is the authoritative order
     either way, so a device with no route to NTP is fully functional. */
  configTime(0, 0, "pool.ntp.org");

  siot.setServer(SERVER_URL, SERVER_CERT);
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
