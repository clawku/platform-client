#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::Command;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey, SigningKey};
use ed25519_dalek::pkcs8::{EncodePublicKey, DecodePublicKey};
use futures_util::{SinkExt, StreamExt};
use rand_core::{OsRng, RngCore};
use rcgen::{CertificateParams, DistinguishedName, DnType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shell_words;
use tauri::{AppHandle, State, Emitter, Manager};
use tauri::tray::{TrayIconBuilder, MouseButton, MouseButtonState, TrayIconEvent};
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::Connector;
use url;
use rustls::{ClientConfig, RootCertStore};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile;
use ed25519_dalek::Signer;
use pkcs8::LineEnding;

#[derive(serde::Serialize)]
struct CommandResult {
    exit_code: i32,
    output: String,
    error: String,
    summary: String,
}

struct AppState {
    ws_tx: Mutex<Option<mpsc::UnboundedSender<String>>>,
    ws_abort: Mutex<Option<oneshot::Sender<()>>>,
}

fn keyring_entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new("clawku-client", "device-token")
        .map_err(|err| err.to_string())
}

fn signing_key_entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new("clawku-client", "device-signing-private")
        .map_err(|err| err.to_string())
}

fn tls_key_path() -> Result<PathBuf, String> {
    let mut path = dirs::config_dir().ok_or("Missing config dir")?;
    path.push("clawku-client");
    fs::create_dir_all(&path).map_err(|err| err.to_string())?;
    path.push("device-tls-key.pem");
    Ok(path)
}

fn tls_cert_path() -> Result<PathBuf, String> {
    let mut path = dirs::config_dir().ok_or("Missing config dir")?;
    path.push("clawku-client");
    fs::create_dir_all(&path).map_err(|err| err.to_string())?;
    path.push("device-tls-cert.pem");
    Ok(path)
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let base64 = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    B64.decode(base64).map_err(|err| err.to_string())
}

fn load_device_cert_chain() -> Result<Vec<CertificateDer<'static>>, String> {
    let cert_pem = fs::read_to_string(tls_cert_path()?).map_err(|err| err.to_string())?;
    let mut reader = cert_pem.as_bytes();
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Invalid device cert")?;
    let chain = certs.into_iter().map(CertificateDer::from).collect::<Vec<_>>();
    if chain.is_empty() {
        return Err("Device cert missing".to_string());
    }
    Ok(chain)
}

fn load_device_private_key() -> Result<PrivateKeyDer<'static>, String> {
    let key_pem = fs::read_to_string(tls_key_path()?).map_err(|err| err.to_string())?;
    let mut reader = key_pem.as_bytes();
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Invalid device key")?;
    let key = keys.into_iter().next().ok_or("Device key missing")?;
    Ok(PrivateKeyDer::from(key))
}

fn build_tls_config(server_cert_pem: &str, server_ca_pem: &str) -> Result<ClientConfig, String> {
    let mut roots = RootCertStore::empty();
    let mut any_added = false;
    for pem in [server_cert_pem, server_ca_pem] {
        if pem.trim().is_empty() {
            continue;
        }
        let mut reader = pem.as_bytes();
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "Invalid server cert")?;
        for cert in certs {
            roots.add(CertificateDer::from(cert)).map_err(|_| "Invalid server cert")?;
            any_added = true;
        }
    }
    if !any_added {
        return Err("Server cert missing".to_string());
    }
    let cert_chain = load_device_cert_chain()?;
    let key = load_device_private_key()?;
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)
        .map_err(|_| "Invalid client cert/key")?;
    Ok(config)
}

#[tauri::command]
fn store_device_token(token: String) -> Result<(), String> {
    let entry = keyring_entry()?;
    entry.set_password(&token).map_err(|err| err.to_string())
}

#[tauri::command]
fn load_device_token() -> Result<Option<String>, String> {
    let entry = keyring_entry()?;
    match entry.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(err.to_string()),
    }
}

#[tauri::command]
fn clear_device_token() -> Result<(), String> {
    let entry = keyring_entry()?;
    match entry.delete_password() {
        Ok(_) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(err.to_string()),
    }
}

#[tauri::command]
async fn http_probe(url: String) -> Result<bool, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;

    match client.get(&url).send().await {
        Ok(resp) => Ok(resp.status().is_success()),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
async fn http_get(url: String) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| e.to_string())?;

    if status.is_success() {
        Ok(text)
    } else {
        Err(format!("HTTP {}: {}", status.as_u16(), text))
    }
}

#[tauri::command]
async fn http_post(url: String, body: String) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = resp.status();
    let text = resp.text().await.map_err(|e| e.to_string())?;

    if status.is_success() {
        Ok(text)
    } else {
        Err(format!("HTTP {}: {}", status.as_u16(), text))
    }
}

#[tauri::command]
fn enable_autostart(app_path: String) -> Result<(), String> {
    let mut plist_path = dirs::home_dir().ok_or("Missing home dir")?;
    plist_path.push("Library/LaunchAgents");
    fs::create_dir_all(&plist_path).map_err(|err| err.to_string())?;
    plist_path.push("com.clawku.client.plist");

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.clawku.client</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
"#,
        app_path
    );

    fs::write(&plist_path, plist).map_err(|err| err.to_string())?;

    Command::new("launchctl")
        .arg("load")
        .arg(plist_path.to_string_lossy().to_string())
        .status()
        .map_err(|err| err.to_string())?;

    Ok(())
}

#[tauri::command]
fn disable_autostart() -> Result<(), String> {
    let mut plist_path = dirs::home_dir().ok_or("Missing home dir")?;
    plist_path.push("Library/LaunchAgents/com.clawku.client.plist");
    let path_str = plist_path.to_string_lossy().to_string();
    let _ = Command::new("launchctl").arg("unload").arg(&path_str).status();
    let _ = fs::remove_file(plist_path);
    Ok(())
}

#[tauri::command]
fn get_executable_path() -> Result<String, String> {
    std::env::current_exe()
        .map_err(|err| err.to_string())
        .map(|path| path.to_string_lossy().to_string())
}

#[derive(serde::Serialize)]
struct SigningKeyInfo {
    public_key_b64: String,
}

#[tauri::command]
fn start_mtls_ws(
    app: AppHandle,
    state: State<AppState>,
    ws_url: String,
    device_token: String,
    server_cert_pem: String,
    server_ca_pem: String,
) -> Result<(), String> {
    let mut url = url::Url::parse(&ws_url).map_err(|err| err.to_string())?;
    url.query_pairs_mut().append_pair("token", &device_token);

    let tls_config = build_tls_config(&server_cert_pem, &server_ca_pem)?;
    let connector = Connector::Rustls(Arc::new(tls_config));

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let (abort_tx, mut abort_rx) = oneshot::channel::<()>();

    {
        let mut guard = state.ws_tx.lock().map_err(|_| "Lock error")?;
        *guard = Some(tx);
    }
    {
        let mut guard = state.ws_abort.lock().map_err(|_| "Lock error")?;
        *guard = Some(abort_tx);
    }

    tauri::async_runtime::spawn(async move {
        let connect = tokio_tungstenite::connect_async_tls_with_config(
            url.as_str(),
            None,
            false,
            Some(connector),
        ).await;
        let (ws_stream, _) = match connect {
            Ok(v) => v,
            Err(err) => {
                let _ = app.emit("device_ws_error", err.to_string());
                return;
            }
        };

        let (mut write, mut read) = ws_stream.split();

        loop {
            tokio::select! {
                _ = &mut abort_rx => {
                    let _ = write.send(Message::Close(None)).await;
                    break;
                }
                Some(outbound) = rx.recv() => {
                    if write.send(Message::Text(outbound)).await.is_err() {
                        break;
                    }
                }
                inbound = read.next() => {
                    match inbound {
                        Some(Ok(Message::Text(text))) => {
                            let _ = app.emit("device_ws_message", text);
                        }
                        Some(Ok(Message::Binary(bin))) => {
                            if let Ok(text) = String::from_utf8(bin) {
                                let _ = app.emit("device_ws_message", text);
                            }
                        }
                        Some(Ok(Message::Close(_))) => break,
                        Some(Err(err)) => {
                            let _ = app.emit("device_ws_error", err.to_string());
                            break;
                        }
                        _ => break,
                    }
                }
            }
        }
        let _ = app.emit("device_ws_closed", "closed");
    });

    Ok(())
}

#[tauri::command]
fn send_device_ws(state: State<AppState>, message: String) -> Result<(), String> {
    let guard = state.ws_tx.lock().map_err(|_| "Lock error")?;
    if let Some(tx) = guard.as_ref() {
        tx.send(message).map_err(|_| "Send failed")?;
        Ok(())
    } else {
        Err("Device WS not connected".to_string())
    }
}

#[tauri::command]
fn stop_mtls_ws(state: State<AppState>) -> Result<(), String> {
    if let Ok(mut guard) = state.ws_abort.lock() {
        if let Some(tx) = guard.take() {
            let _ = tx.send(());
        }
    }
    if let Ok(mut guard) = state.ws_tx.lock() {
        guard.take();
    }
    Ok(())
}

#[tauri::command]
fn ensure_device_signing_key() -> Result<SigningKeyInfo, String> {
    let entry = signing_key_entry()?;
    let private_b64 = match entry.get_password() {
        Ok(value) => value,
        Err(keyring::Error::NoEntry) => {
            let mut private_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut private_bytes);
            let signing = SigningKey::from_bytes(&private_bytes);
            let private_bytes = signing.to_bytes();
            let private_b64 = B64.encode(private_bytes);
            entry.set_password(&private_b64).map_err(|err| err.to_string())?;
            private_b64
        }
        Err(err) => return Err(err.to_string()),
    };

    let private_bytes = B64.decode(private_b64).map_err(|err| err.to_string())?;
    let signing = SigningKey::from_bytes(&private_bytes.try_into().map_err(|_| "Invalid key")?);
    let public_pem = signing
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|err| err.to_string())?;

    Ok(SigningKeyInfo {
        public_key_b64: public_pem,
    })
}

#[tauri::command]
fn sign_result_payload(payload_json: String) -> Result<String, String> {
    let entry = signing_key_entry()?;
    let private_b64 = entry.get_password().map_err(|err| err.to_string())?;
    let private_bytes = B64.decode(private_b64).map_err(|err| err.to_string())?;
    let signing = SigningKey::from_bytes(&private_bytes.try_into().map_err(|_| "Invalid key")?);
    let signature = signing.sign(payload_json.as_bytes());
    Ok(B64.encode(signature.to_bytes()))
}

#[derive(serde::Serialize)]
struct DeviceTlsInfo {
    cert_pem: String,
    fingerprint_sha256: String,
}

#[tauri::command]
fn ensure_device_tls_cert(device_id: String) -> Result<DeviceTlsInfo, String> {
    let key_path = tls_key_path()?;
    let cert_path = tls_cert_path()?;

    if key_path.exists() && cert_path.exists() {
        let cert_pem = fs::read_to_string(&cert_path).map_err(|err| err.to_string())?;
        let cert_der = pem_to_der(&cert_pem)?;
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let fingerprint = hex::encode(hasher.finalize());
        return Ok(DeviceTlsInfo {
            cert_pem,
            fingerprint_sha256: fingerprint,
        });
    }

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, device_id);
    params.distinguished_name = dn;
    let cert = rcgen::Certificate::from_params(params).map_err(|err| err.to_string())?;
    let cert_pem = cert.serialize_pem().map_err(|err| err.to_string())?;
    let key_pem = cert.serialize_private_key_pem();
    let cert_der = cert.serialize_der().map_err(|err| err.to_string())?;

    fs::write(&key_path, key_pem).map_err(|err| err.to_string())?;
    fs::write(&cert_path, &cert_pem).map_err(|err| err.to_string())?;

    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let fingerprint = hex::encode(hasher.finalize());

    Ok(DeviceTlsInfo {
        cert_pem,
        fingerprint_sha256: fingerprint,
    })
}

#[derive(Deserialize)]
struct SignedJobPayload {
    v: i32,
    jobId: String,
    userId: String,
    deviceId: String,
    command: String,
    args: Option<Vec<String>>,
    cwd: Option<String>,
    envPreview: Option<serde_json::Value>,
    requestedBy: Option<String>,
    issuedAt: i64,
    expiresAt: i64,
    nonce: String,
}

#[derive(Serialize)]
struct VerifiedJobPayload {
    jobId: String,
    command: String,
    args: Option<Vec<String>>,
    cwd: Option<String>,
    requestedBy: Option<String>,
    issuedAt: i64,
    expiresAt: i64,
    nonce: String,
}

#[tauri::command]
fn verify_job_envelope(payload_json: String, signature_b64: String, public_key_pem: String, expected_device_id: String) -> Result<VerifiedJobPayload, String> {
    let verifying_key = VerifyingKey::from_public_key_pem(&public_key_pem).map_err(|err| err.to_string())?;
    let sig_bytes = B64.decode(signature_b64).map_err(|err| err.to_string())?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|err| err.to_string())?;
    verifying_key.verify_strict(payload_json.as_bytes(), &signature).map_err(|err| err.to_string())?;

    let payload: SignedJobPayload = serde_json::from_str(&payload_json).map_err(|err| err.to_string())?;
    if payload.deviceId != expected_device_id {
        return Err("Device mismatch".to_string());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|err| err.to_string())?.as_millis() as i64;
    if payload.expiresAt < now {
        return Err("Command expired".to_string());
    }
    if payload.issuedAt > now + 30_000 {
        return Err("Command issued in the future".to_string());
    }

    Ok(VerifiedJobPayload {
        jobId: payload.jobId,
        command: payload.command,
        args: payload.args,
        cwd: payload.cwd,
        requestedBy: payload.requestedBy,
        issuedAt: payload.issuedAt,
        expiresAt: payload.expiresAt,
        nonce: payload.nonce,
    })
}

#[tauri::command]
fn verify_payload_signature(payload_json: String, signature_b64: String, public_key_pem: String) -> Result<serde_json::Value, String> {
    let verifying_key = VerifyingKey::from_public_key_pem(&public_key_pem).map_err(|err| err.to_string())?;
    let sig_bytes = B64.decode(signature_b64).map_err(|err| err.to_string())?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|err| err.to_string())?;
    let ok = verifying_key.verify_strict(payload_json.as_bytes(), &signature).is_ok();
    Ok(serde_json::json!({ "valid": ok }))
}

#[derive(Serialize)]
struct FileReadResult {
    data_b64: String,
    size_bytes: usize,
    mime_type: String,
}

#[tauri::command]
fn read_file_base64(file_path: String) -> Result<FileReadResult, String> {
    // Expand ~ to home directory
    let expanded_path = if file_path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            home.join(&file_path[2..])
        } else {
            PathBuf::from(&file_path)
        }
    } else {
        PathBuf::from(&file_path)
    };

    // Read file
    let data = fs::read(&expanded_path).map_err(|e| format!("Failed to read file: {}", e))?;
    let size_bytes = data.len();

    // Detect MIME type from extension
    let mime_type = match expanded_path.extension().and_then(|e| e.to_str()) {
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("pdf") => "application/pdf",
        Some("txt") => "text/plain",
        Some("mp3") => "audio/mpeg",
        Some("mp4") => "video/mp4",
        Some("wav") => "audio/wav",
        Some("ogg") => "audio/ogg",
        Some("webm") => "video/webm",
        Some("doc") => "application/msword",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("xls") => "application/vnd.ms-excel",
        Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }.to_string();

    // Encode as base64
    let data_b64 = B64.encode(&data);

    Ok(FileReadResult {
        data_b64,
        size_bytes,
        mime_type,
    })
}

#[tauri::command]
fn run_command(command: String, cwd: Option<String>) -> Result<CommandResult, String> {
    // Strip common shell redirect patterns that don't work in direct execution anyway
    let command = command
        .replace(" 2>/dev/null", "")
        .replace(" 2>&1", "")
        .replace(" >/dev/null", "")
        .replace(" 1>/dev/null", "");

    // Block dangerous injection patterns
    let dangerous = ["$(", "`", "\n", "\r"];
    for token in dangerous {
        if command.contains(token) {
            return Err("Blocked: command substitution not allowed".to_string());
        }
    }

    // Check if command needs shell (contains pipes, shell operators, or tilde for home expansion)
    let needs_shell = command.contains('|') || command.contains("&&") || command.contains("||")
        || command.contains('>') || command.contains('<') || command.contains(';')
        || command.contains('~') || command.contains('$');

    let output = if needs_shell {
        // Run through shell for commands with pipes/redirects
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(&command);
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        cmd.output().map_err(|err| err.to_string())?
    } else {
        // Direct execution for simple commands (safer)
        let argv = shell_words::split(&command).map_err(|err| err.to_string())?;
        if argv.is_empty() {
            return Err("Empty command".to_string());
        }
        let mut cmd = Command::new(&argv[0]);
        if argv.len() > 1 {
            cmd.args(&argv[1..]);
        }
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        cmd.output().map_err(|err| err.to_string())?
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    let summary = if code == 0 { "Completed" } else { "Failed" }.to_string();

    Ok(CommandResult {
        exit_code: code,
        output: stdout,
        error: stderr,
        summary,
    })
}

fn main() {
    let app_state = AppState {
        ws_tx: Mutex::new(None),
        ws_abort: Mutex::new(None),
    };
    tauri::Builder::default()
        .manage(app_state)
        .setup(|app| {
            // Build tray menu
            let show_item = MenuItemBuilder::with_id("show", "Show Clawku").build(app)?;
            let connect_item = MenuItemBuilder::with_id("connect", "Connect").build(app)?;
            let repair_item = MenuItemBuilder::with_id("repair", "Re-pair Device").build(app)?;
            let clear_item = MenuItemBuilder::with_id("clear", "Clear Pairing").build(app)?;
            let auto_approve_item = MenuItemBuilder::with_id("auto_approve", "Toggle Auto-Approve").build(app)?;
            let logout_item = MenuItemBuilder::with_id("logout", "Logout").build(app)?;
            let quit_item = MenuItemBuilder::with_id("quit", "Quit").build(app)?;

            let menu = MenuBuilder::new(app)
                .item(&show_item)
                .separator()
                .item(&connect_item)
                .item(&repair_item)
                .item(&clear_item)
                .separator()
                .item(&auto_approve_item)
                .separator()
                .item(&logout_item)
                .separator()
                .item(&quit_item)
                .build()?;

            // Create tray icon
            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("Clawku Client")
                .menu(&menu)
                .menu_on_left_click(false)
                .on_menu_event(|app, event| {
                    let id = event.id().0.as_str();
                    println!("[Tray] Menu event: {}", id);
                    match id {
                        "show" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        "connect" => {
                            let _ = app.emit("tray_action", "connect");
                        }
                        "repair" => {
                            // Show window and trigger re-pair
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                            let _ = app.emit("tray_action", "repair");
                        }
                        "clear" => {
                            let _ = app.emit("tray_action", "clear");
                        }
                        "auto_approve" => {
                            let _ = app.emit("tray_action", "auto_approve");
                        }
                        "logout" => {
                            let _ = app.emit("tray_action", "logout");
                        }
                        "quit" => {
                            app.exit(0);
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    // Show window on left click
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            // Hide window on close instead of quitting (background mode)
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_http::init())
        .invoke_handler(tauri::generate_handler![
            run_command,
            read_file_base64,
            store_device_token,
            load_device_token,
            clear_device_token,
            http_probe,
            http_get,
            http_post,
            enable_autostart,
            disable_autostart,
            get_executable_path,
            start_mtls_ws,
            send_device_ws,
            stop_mtls_ws,
            ensure_device_signing_key,
            ensure_device_tls_cert,
            verify_job_envelope,
            verify_payload_signature,
            sign_result_payload
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
