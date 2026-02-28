# Client Architecture

## Core Loop

- Pair device
- Connect to device gateway (WSS + mTLS)
- Receive signed jobs
- Require explicit approval
- Execute locally
- Send signed result

## Security

- Device token stored in keychain
- Job payloads are signed by the user key (verified client‑side)
- Job results are signed by device key
- Nonce cache prevents replay
- mTLS device gateway pins server cert/CA

## Components

- Pairing UI + local storage
- WS client (native Tauri + rustls)
- Job queue + approval UI
- Command executor (no shell operators)
