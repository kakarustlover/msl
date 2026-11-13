use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768,
};
use rand::RngCore;
use reqwest::Client;
use serde_json::{json, Value};
use sha2::Sha256;
use std::{collections::HashMap, sync::Mutex, time::Duration};

const BOT_TOKEN: &str = "9037237204:AAHt-tcZr1dN5ey-LWfOpE3Kk5bm9DQ9G1o";

const PK: usize = 1184; // ML-KEM-768 public key
const SK: usize = 2400; // ML-KEM-768 private key
const CT: usize = 1088; // KEM ciphertext
const IV: usize = 12;

type Ek = <MlKem768 as KemCore>::EncapsulationKey;
type Dk = <MlKem768 as KemCore>::DecapsulationKey;

#[derive(Clone)]
enum St {
    EncKey,
    EncText(String),
    DecKey,
    DecText(String),
}
type States = Mutex<HashMap<i64, St>>;

// ---------------- crypto ----------------

fn clean(s: &str) -> String {
    s.split_whitespace().collect()
}

fn cipher(secret: &[u8]) -> Aes256Gcm {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, secret)
        .expand(b"pqchat-v1", &mut key)
        .unwrap();
    Aes256Gcm::new_from_slice(&key).unwrap()
}

fn keygen() -> (String, String) {
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng);
    (
        B64.encode(ek.as_bytes().as_slice()),
        B64.encode(dk.as_bytes().as_slice()),
    )
}

fn encrypt(pub_b64: &str, text: &str) -> Result<String, &'static str> {
    let raw = B64.decode(clean(pub_b64)).map_err(|_| "bad base64")?;
    if raw.len() != PK {
        return Err("bad key length");
    }
    let enc = Encoded::<Ek>::try_from(&raw[..]).map_err(|_| "bad key")?;
    let ek = Ek::from_bytes(&enc);

    let mut rng = rand::thread_rng();
    let (ct, shared) = ek.encapsulate(&mut rng).map_err(|_| "encapsulate failed")?;
    let mut iv = [0u8; IV];
    rng.fill_bytes(&mut iv);

    let body = cipher(shared.as_slice())
        .encrypt(Nonce::from_slice(&iv), text.as_bytes())
        .map_err(|_| "encrypt failed")?;

    let mut out = ct.as_slice().to_vec();
    out.extend_from_slice(&iv);
    out.extend_from_slice(&body);
    Ok(B64.encode(out))
}

fn decrypt(priv_b64: &str, payload_b64: &str) -> Result<String, &'static str> {
    let sk = B64.decode(clean(priv_b64)).map_err(|_| "bad base64")?;
    let data = B64.decode(clean(payload_b64)).map_err(|_| "bad base64")?;
    if sk.len() != SK || data.len() < CT + IV + 16 {
        return Err("bad input length");
    }
    let enc = Encoded::<Dk>::try_from(&sk[..]).map_err(|_| "bad key")?;
    let dk = Dk::from_bytes(&enc);
    let ct = Ciphertext::<MlKem768>::try_from(&data[..CT]).map_err(|_| "bad ciphertext")?;
    let shared = dk.decapsulate(&ct).map_err(|_| "decapsulate failed")?;

    let pt = cipher(shared.as_slice())
        .decrypt(Nonce::from_slice(&data[CT..CT + IV]), &data[CT + IV..])
        .map_err(|_| "wrong key or corrupted text")?;
    String::from_utf8(pt).map_err(|_| "not utf8")
}

// ---------------- telegram ----------------

async fn api(c: &Client, method: &str, body: Value) -> Value {
    let url = format!("https://api.telegram.org/bot{}/{}", BOT_TOKEN, method);
    match c.post(url).json(&body).send().await {
        Ok(r) => r.json().await.unwrap_or(Value::Null),
        Err(_) => Value::Null,
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

async fn say(c: &Client, chat: i64, text: &str) {
    api(
        c,
        "sendMessage",
        json!({"chat_id": chat, "text": text, "parse_mode": "HTML"}),
    )
    .await;
}

async fn menu(c: &Client, chat: i64) {
    api(
        c,
        "sendMessage",
        json!({
            "chat_id": chat,
            "text": "یکی را انتخاب کن:",
            "reply_markup": {"inline_keyboard": [
                [{"text": "🔑 تولید کلید", "callback_data": "gen"}],
                [{"text": "🔒 رمزنگاری", "callback_data": "enc"},
                 {"text": "🔓 رمزگشایی", "callback_data": "dec"}]
            ]}
        }),
    )
    .await;
}

async fn send_file(c: &Client, chat: i64, name: &str, content: &str, caption: &str) {
    let part = reqwest::multipart::Part::text(content.to_string()).file_name(name.to_string());
    let form = reqwest::multipart::Form::new()
        .text("chat_id", chat.to_string())
        .text("caption", caption.to_string())
        .part("document", part);
    let url = format!("https://api.telegram.org/bot{}/sendDocument", BOT_TOKEN);
    let _ = c.post(url).multipart(form).send().await;
}

async fn read_input(c: &Client, m: &Value) -> Option<String> {
    if let Some(d) = m.get("document") {
        if d["file_size"].as_i64().unwrap_or(0) > 200_000 {
            return None;
        }
        let r = api(c, "getFile", json!({"file_id": d["file_id"]})).await;
        let path = r["result"]["file_path"].as_str()?;
        let url = format!("https://api.telegram.org/file/bot{}/{}", BOT_TOKEN, path);
        let t = c.get(url).send().await.ok()?.text().await.ok()?;
        return Some(t.trim().to_string());
    }
    Some(m["text"].as_str().unwrap_or("").trim().to_string())
}

// ---------------- flow ----------------

fn set(s: &States, chat: i64, st: St) {
    s.lock().unwrap().insert(chat, st);
}
fn clear(s: &States, chat: i64) {
    s.lock().unwrap().remove(&chat);
}

async fn on_action(c: &Client, s: &States, chat: i64, action: &str) {
    match action {
        "gen" => {
            clear(s, chat);
            let (pubk, privk) = keygen();
            say(
                c,
                chat,
                &format!("🔑 کلید عمومی (برای دوستت بفرست):\n\n<code>{}</code>", pubk),
            )
            .await;
            say(
                c,
                chat,
                &format!(
                    "🔐 کلید خصوصی (پیش خودت نگه دار، به کسی نده):\n\n<code>{}</code>",
                    privk
                ),
            )
            .await;
            menu(c, chat).await;
        }
        "enc" => {
            set(s, chat, St::EncKey);
            say(c, chat, "کلید عمومی دوستت را بفرست.").await;
        }
        "dec" => {
            set(s, chat, St::DecKey);
            say(
                c,
                chat,
                "کلید خصوصی خودت را بفرست (بعد از دریافت، پیامش پاک می‌شود).",
            )
            .await;
        }
        _ => {}
    }
}

fn key_len_ok(input: &str, want: usize) -> bool {
    B64.decode(clean(input)).map(|b| b.len()).ok() == Some(want)
}

async fn on_message(c: &Client, s: &States, m: &Value) {
    if m["chat"]["type"].as_str() != Some("private") {
        return;
    }
    let chat = m["chat"]["id"].as_i64().unwrap_or(0);
    let mid = m["message_id"].as_i64().unwrap_or(0);
    let text = m["text"].as_str().unwrap_or("").trim();

    if text == "/start" || text == "/cancel" {
        clear(s, chat);
        menu(c, chat).await;
        return;
    }

    let st = s.lock().unwrap().get(&chat).cloned();
    let Some(st) = st else {
        menu(c, chat).await;
        return;
    };

    let input = match read_input(c, m).await {
        Some(x) if !x.is_empty() => x,
        _ => {
            say(c, chat, "لطفاً متن یا فایل txt بفرست.").await;
            return;
        }
    };

    match st {
        St::EncKey => {
            if !key_len_ok(&input, PK) {
                say(c, chat, "❌ کلید عمومی نامعتبر است. دوباره بفرست یا /cancel بزن.").await;
                return;
            }
            set(s, chat, St::EncText(clean(&input)));
            say(c, chat, "حالا متنی که می‌خواهی رمز شود را بفرست.").await;
        }
        St::EncText(key) => {
            clear(s, chat);
            match encrypt(&key, &input) {
                Ok(out) => {
                    if out.len() <= 3800 {
                        say(c, chat, &format!("🔒 متن رمزشده:\n\n<code>{}</code>", out)).await;
                    } else {
                        send_file(c, chat, "encrypted.txt", &out, "🔒 متن رمزشده (فایل)").await;
                    }
                }
                Err(_) => say(c, chat, "❌ رمزنگاری ناموفق بود.").await,
            }
            menu(c, chat).await;
        }
        St::DecKey => {
            if !key_len_ok(&input, SK) {
                say(c, chat, "❌ کلید خصوصی نامعتبر است. دوباره بفرست یا /cancel بزن.").await;
                return;
            }
            api(c, "deleteMessage", json!({"chat_id": chat, "message_id": mid})).await;
            set(s, chat, St::DecText(clean(&input)));
            say(c, chat, "حالا متن رمزشده را بفرست (پیام یا فایل txt).").await;
        }
        St::DecText(key) => {
            clear(s, chat);
            match decrypt(&key, &input) {
                Ok(out) => say(c, chat, &format!("✅ متن اصلی:\n\n{}", esc(&out))).await,
                Err(_) => say(c, chat, "❌ رمزگشایی ناموفق بود (کلید یا متن اشتباه است).").await,
            }
            menu(c, chat).await;
        }
    }
}

async fn handle(c: &Client, s: &States, u: &Value) {
    if let Some(q) = u.get("callback_query") {
        api(c, "answerCallbackQuery", json!({"callback_query_id": q["id"]})).await;
        let chat = q["message"]["chat"]["id"].as_i64().unwrap_or(0);
        on_action(c, s, chat, q["data"].as_str().unwrap_or("")).await;
    } else if let Some(m) = u.get("message") {
        on_message(c, s, m).await;
    }
}

#[tokio::main]
async fn main() {
    let c = Client::builder()
        .timeout(Duration::from_secs(70))
        .build()
        .unwrap();
    let states: States = Mutex::new(HashMap::new());

    // getUpdates needs the webhook to be off
    api(&c, "deleteWebhook", json!({})).await;
    println!("bot started");

    let mut offset: i64 = 0;
    loop {
        let r = api(
            &c,
            "getUpdates",
            json!({"offset": offset, "timeout": 50, "allowed_updates": ["message", "callback_query"]}),
        )
        .await;
        match r["result"].as_array() {
            Some(arr) => {
                for u in arr {
                    offset = u["update_id"].as_i64().unwrap_or(0) + 1;
                    handle(&c, &states, u).await;
                }
            }
            None => tokio::time::sleep(Duration::from_secs(3)).await,
        }
    }
}
