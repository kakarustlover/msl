use std::process::Stdio;

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use teloxide::prelude::*;
use tokio::process::Command;

const NOBITEX_URL: &str = "https://apiv2.nobitex.ir/market/stats?srcCurrency=usdt&dstCurrency=rls";
const GRAM_URL: &str = "https://api.coinpaprika.com/v1/tickers/toncoin-the-open-network";

/// اجرای curl بدون shell؛ آرگومان‌ها جدا جدا داده می‌شوند.
async fn curl_json(url: &str, headers: &[&str]) -> Result<Value> {
    let mut cmd = Command::new("curl");
    cmd.args(["-s", "-f", "--max-time", "5"]);
    for &h in headers {
        cmd.args(["-H", h]);
    }
    cmd.arg(url).stdin(Stdio::null()).kill_on_drop(true);

    let out = cmd.output().await.context("اجرای curl ممکن نشد")?;
    if !out.status.success() {
        return Err(anyhow!("curl با کد {:?} شکست خورد", out.status.code()));
    }
    serde_json::from_slice(&out.stdout).context("پاسخ JSON معتبر نبود")
}

/// نرخ تتر به ریال از نوبیتکس
async fn usdt_rls() -> Result<f64> {
    let v = curl_json(NOBITEX_URL, &["User-Agent: TraderBot/MyBot-1.0.0"]).await?;
    v["stats"]["usdt-rls"]["latest"]
        .as_str()
        .ok_or_else(|| anyhow!("فیلد latest پیدا نشد"))?
        .parse::<f64>()
        .context("عدد نرخ تتر نامعتبر بود")
}

/// قیمت دلاری گرام از coinpaprika
async fn gram_usd() -> Result<f64> {
    let v = curl_json(GRAM_URL, &[]).await?;
    v["quotes"]["USD"]["price"]
        .as_f64()
        .ok_or_else(|| anyhow!("فیلد price پیدا نشد"))
}

fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

async fn price_message() -> String {
    // هر دو درخواست همزمان اجرا می‌شوند
    let (rls, usd) = tokio::join!(usdt_rls(), gram_usd());

    match (rls, usd) {
        (Ok(rls), Ok(usd)) => {
            let usdt_toman = rls / 10.0;
            let gram_toman = usd * usdt_toman;
            format!(
                "💎 قیمت گرام (GRAM)\n\n\
                 💵 دلار: ${:.4}\n\
                 🇮🇷 تومان: {}\n\n\
                 📌 نرخ تتر: {} تومان",
                usd,
                group(gram_toman.round() as u64),
                group(usdt_toman.round() as u64),
            )
        }
        (rls, usd) => {
            let mut errs = Vec::new();
            if let Err(e) = rls {
                errs.push(format!("نوبیتکس: {e:#}"));
            }
            if let Err(e) = usd {
                errs.push(format!("قیمت گرام: {e:#}"));
            }
            format!("❌ خطا در دریافت قیمت\n\n{}", errs.join("\n"))
        }
    }
}

fn normalize(s: &str) -> String {
    s.trim().to_lowercase().replace('ي', "ی").replace('ك', "ک")
}

#[tokio::main]
async fn main() -> Result<()> {
    let curl_ok = Command::new("curl")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success());
    if !curl_ok {
        return Err(anyhow!("curl روی سیستم نصب نیست"));
    }

    let bot = Bot::from_env(); // توکن از TELOXIDE_TOKEN

    teloxide::repl(bot, |bot: Bot, msg: Message| async move {
        if !msg.chat.is_private() {
            return respond(());
        }
        if let Some(text) = msg.text() {
            let t = normalize(text);
            if t == "/start" {
                bot.send_message(msg.chat.id, "سلام 👋\nکلمه‌ی «گرام» را بفرست تا قیمت لحظه‌ای را بدهم.")
                    .await?;
            } else if t == "گرام" || t == "gram" {
                let reply = price_message().await;
                bot.send_message(msg.chat.id, reply).await?;
            }
        }
        respond(())
    })
    .await;

    Ok(())
}
