# Device Pairing

Goal: bind a desktop device to a user without entering credentials on the device.

## Flow

1. Client `POST /devices/pair/start`
- `{ deviceId, platform, version, deviceName, deviceSigningPublicKey, deviceTlsFingerprint }`

2. User enters the code in the web UI.

3. Web `POST /devices/pair/confirm` (auth)
- `{ code }`

4. Client `POST /devices/pair/finish`
- `{ deviceId, code, deviceName }`

Response (confirmed):
- `deviceToken`
- `userSigningPublicKey`, `userSigningKeyId`
- `deviceGateway` with `wss://` url + server cert/CA PEM

## Notes

- Device token is stored in keychain.
- Client uses mTLS WS when `deviceGateway` is present.
