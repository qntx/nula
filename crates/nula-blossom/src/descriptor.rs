//! The Blossom [`BlobDescriptor`] returned by `PUT /upload`, `GET /list`,
//! and `HEAD /<sha256>`.

use serde::{Deserialize, Serialize};

/// Metadata describing a stored blob (BUD-02 §"Blob Descriptor").
///
/// Unknown server-specific fields (`magnet`, `infohash`, `ipfs`, …) are
/// preserved in [`BlobDescriptor::extra`] so they survive a round trip.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(
    clippy::derive_partial_eq_without_eq,
    reason = "the flattened `extra` map holds serde_json::Value, which is not Eq"
)]
pub struct BlobDescriptor {
    /// Publicly accessible `GET /<sha256>` URL (with a file extension).
    pub url: String,
    /// The blob's sha256 digest (lowercase hex).
    pub sha256: String,
    /// Blob size in bytes.
    pub size: u64,
    /// MIME type (`application/octet-stream` when unknown).
    #[serde(rename = "type", skip_serializing_if = "Option::is_none", default)]
    pub mime_type: Option<String>,
    /// Unix timestamp (seconds) of when the blob was uploaded.
    pub uploaded: u64,
    /// Any additional server-specific fields, preserved verbatim.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_with_extra_fields() {
        let json = r#"{"url":"https://cdn.example.com/b16.pdf","sha256":"b16","size":184292,"type":"application/pdf","uploaded":1725105921,"magnet":"magnet:?xt=urn:btih:abc"}"#;
        let descriptor: BlobDescriptor = serde_json::from_str(json).unwrap();
        assert_eq!(descriptor.sha256, "b16");
        assert_eq!(descriptor.size, 184_292);
        assert_eq!(descriptor.mime_type.as_deref(), Some("application/pdf"));
        assert_eq!(
            descriptor
                .extra
                .get("magnet")
                .and_then(serde_json::Value::as_str),
            Some("magnet:?xt=urn:btih:abc")
        );
        let reserialized = serde_json::to_string(&descriptor).unwrap();
        assert!(reserialized.contains("magnet"));
    }

    #[test]
    fn omits_absent_mime_type() {
        let descriptor = BlobDescriptor {
            url: "https://s/x".to_owned(),
            sha256: "x".to_owned(),
            size: 1,
            mime_type: None,
            uploaded: 0,
            extra: serde_json::Map::new(),
        };
        let json = serde_json::to_string(&descriptor).unwrap();
        assert!(!json.contains("\"type\""));
    }
}
