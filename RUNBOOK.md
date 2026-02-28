# Client Runbook

## Dev

```bash
cd platform-client
pnpm install
pnpm tauri dev
```

## Release Build

```bash
cd platform-client
cargo tauri build
```

## Common Issues

- `UnknownIssuer`: re‑pair so the client receives gateway CA PEM.
- `Native WS not available`: ensure Tauri runtime is used, not plain browser.
