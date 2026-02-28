# Device Protocol

## Client → Server

- `device.hello` `{ deviceId, platform, version }`
- `device.heartbeat` `{ ts }`
- `job.result` `{ payloadJson, signature }`

## Server → Client

- `job.enqueue` `{ payloadJson, signature, keyId }`

## Rules

- Client verifies `job.enqueue` signature with user public key.
- Client signs `job.result` with device key.
- Nonces are required and must not repeat.
