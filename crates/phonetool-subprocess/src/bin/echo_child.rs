//! Reference echo-child for Tier-B conformance testing.
//!
//! Reads length-prefixed JSON command frames from stdin, writes back Event
//! frames (or error frames when verb == "error"). Exits on EOF/error.
#![allow(clippy::expect_used, clippy::unwrap_used)]

fn main() {
    use std::io::{Read, Write};

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    loop {
        let mut len_buf = [0u8; 4];
        if reader.read_exact(&mut len_buf).is_err() {
            break;
        }
        let len = u32::from_be_bytes(len_buf);
        if len > 1_048_576 {
            break;
        }

        let mut body = vec![0u8; len as usize];
        if reader.read_exact(&mut body).is_err() {
            break;
        }

        let request: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => break,
        };

        let verb = request.get("verb").and_then(|v| v.as_str()).unwrap_or("?");
        let arg = request.get("arg").and_then(|v| v.as_str()).unwrap_or("");

        let response = if verb == "error" {
            serde_json::json!({
                "error": {
                    "kind": "backend",
                    "message": arg
                }
            })
        } else {
            serde_json::json!({
                "source": "echo-child",
                "summary": format!("echoed {verb}({arg})"),
                "data": {
                    "verb": verb,
                    "arg": arg,
                    "echo": true
                }
            })
        };

        let response_bytes = serde_json::to_vec(&response).unwrap();
        let response_len = (response_bytes.len() as u32).to_be_bytes();
        let _ = writer.write_all(&response_len);
        let _ = writer.write_all(&response_bytes);
        let _ = writer.flush();
    }
}
