//! Length-prefixed JSON framing over byte streams.
//!
//! Wire format: `[4-byte big-endian u32 length][length bytes of UTF-8 JSON]`.
//! A length prefix exceeding `MAX_FRAME` is rejected before reading the body —
//! the fail-closed allocation guard against a hostile or buggy child.

use std::io::{Read, Write};

use phonetool_core::PluginError;

/// Maximum frame size (1 MB). A child that declares a larger frame is
/// fail-closed rejected.
pub const MAX_FRAME: u32 = 1_048_576;

/// Write a JSON value as a length-prefixed frame.
pub fn write_frame(writer: &mut dyn Write, payload: &[u8]) -> Result<(), PluginError> {
    let len = payload.len();
    if len > MAX_FRAME as usize {
        return Err(PluginError::Backend(format!(
            "frame too large to send: {len} bytes (max {MAX_FRAME})"
        )));
    }
    let len_bytes = (len as u32).to_be_bytes();
    writer
        .write_all(&len_bytes)
        .map_err(|e| PluginError::Backend(format!("write frame length: {e}")))?;
    writer
        .write_all(payload)
        .map_err(|e| PluginError::Backend(format!("write frame body: {e}")))?;
    writer
        .flush()
        .map_err(|e| PluginError::Backend(format!("flush frame: {e}")))?;
    Ok(())
}

/// Read one length-prefixed frame. Returns the body bytes.
/// Enforces `MAX_FRAME` before allocating.
pub fn read_frame(reader: &mut dyn Read) -> Result<Vec<u8>, PluginError> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .map_err(|e| PluginError::Backend(format!("read frame length: {e}")))?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(PluginError::Backend(format!(
            "frame too large: {len} bytes (max {MAX_FRAME})"
        )));
    }
    let mut body = vec![0u8; len as usize];
    reader
        .read_exact(&mut body)
        .map_err(|e| PluginError::Backend(format!("read frame body ({len} bytes): {e}")))?;
    Ok(body)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_frame() {
        let payload = b"{\"verb\":\"test\",\"arg\":\"hello\"}";
        let mut buf = Vec::new();
        write_frame(&mut buf, payload).expect("write");

        let mut cursor = std::io::Cursor::new(buf);
        let got = read_frame(&mut cursor).expect("read");
        assert_eq!(got, payload);
    }

    #[test]
    fn rejects_oversized_frame_on_read() {
        let len = (MAX_FRAME + 1).to_be_bytes();
        let mut cursor = std::io::Cursor::new(len.to_vec());
        let err = read_frame(&mut cursor).expect_err("oversized");
        assert!(matches!(err, PluginError::Backend(_)));
    }

    #[test]
    fn rejects_oversized_frame_on_write() {
        let big = vec![0u8; MAX_FRAME as usize + 1];
        let mut buf = Vec::new();
        let err = write_frame(&mut buf, &big).expect_err("oversized write");
        assert!(matches!(err, PluginError::Backend(_)));
    }
}
