// Copy to secrets.h and fill in. secrets.h is gitignored: never commit it.
#pragma once

#define WIFI_SSID "your-network"
#define WIFI_PASSWORD "your-password"

// No trailing slash. This machine's LAN address; `npm run gen-cert` in backend/
// prints the ones the dev certificate covers.
#define SERVER_URL "https://192.168.1.20:3030"

// Paste backend/certs/dev-cert.pem in whole, BEGIN and END lines included.
// Regenerating that certificate means reflashing every device that pinned it.
#define SERVER_CERT R"CERT(
-----BEGIN CERTIFICATE-----
paste backend/certs/dev-cert.pem here
-----END CERTIFICATE-----
)CERT"
