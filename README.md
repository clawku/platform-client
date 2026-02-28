# Clawku Client

Desktop client that maintains a secure WS connection to the API, receives signed jobs, requires user approval, executes locally, and returns signed results.

## Build

```bash
cd platform-client
cargo tauri build
```

Binary:
`platform-client/src-tauri/target/release/clawku-client`

## Run

```bash
# Development
cargo tauri dev

# Production (after build)
./src-tauri/target/release/clawku-client
```

## Pairing

1. Enter a device name in the client.
2. `Start pairing` to get a 6‑digit code.
3. Confirm in the web UI.
4. `Finish pairing` in the client.

After pairing, the client stores:
- device token (keychain)
- user signing public key
- device gateway certs (for mTLS)

## Logs

Use the app log panel for WS status, pairing, and job approvals.
