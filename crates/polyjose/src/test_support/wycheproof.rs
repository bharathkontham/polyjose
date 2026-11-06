//! Loader for the vendored Wycheproof vectors (ADR 0008 layer 1).
#![cfg(test)]

use sha2::{Digest, Sha256};

/// The vendored directory, `tests/third_party/wycheproof`.
const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/third_party/wycheproof");

/// One row of the README's checksum table.
struct ManifestEntry {
    file: String,
    size: usize,
    sha256: String,
}

/// Parses the `| `file` | bytes | `sha256` |` rows of the vendored README.
fn manifest() -> Vec<ManifestEntry> {
    let path = format!("{DIR}/README.md");
    let readme =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    parse_manifest(&readme).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn parse_manifest(readme: &str) -> Result<Vec<ManifestEntry>, String> {
    let mut entries: Vec<ManifestEntry> = Vec::new();
    for line in readme.lines().filter(|l| l.starts_with("| `")) {
        let cells: Vec<&str> = line
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().trim_matches('`'))
            .collect();
        let [file, size, sha256] = cells[..] else {
            return Err(format!("row needs 3 cells: {line}"));
        };
        let size = size.parse().map_err(|_| format!("bad size: {line}"))?;
        let is_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
        if sha256.len() != 64 || !sha256.bytes().all(is_hex) {
            return Err(format!("bad SHA-256 (64 lowercase hex digits): {line}"));
        }
        if entries.iter().any(|e| e.file == file) {
            return Err(format!("{file} is listed twice"));
        }
        entries.push(ManifestEntry {
            file: file.to_owned(),
            size,
            sha256: sha256.to_owned(),
        });
    }
    if entries.is_empty() {
        return Err("no checksum rows".to_owned());
    }
    Ok(entries)
}

/// Lowercase hex of `bytes`.
fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Checks `bytes` against the README row for its file.
fn verify_entry(entry: &ManifestEntry, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() != entry.size {
        return Err(format!(
            "{}: {} bytes, README says {}",
            entry.file,
            bytes.len(),
            entry.size
        ));
    }
    let actual = to_hex(&Sha256::digest(bytes));
    if actual != entry.sha256 {
        return Err(format!(
            "{}: SHA-256 {actual}, README says {}",
            entry.file, entry.sha256
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendored_files_match_the_readme() {
        let entries = manifest();
        let mut on_disk: Vec<String> = std::fs::read_dir(DIR)
            .unwrap_or_else(|e| panic!("cannot list {DIR}: {e}"))
            .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<Result<_, _>>()
            .unwrap_or_else(|e| panic!("cannot list {DIR}: {e}"));
        on_disk.retain(|f| f != "README.md");
        on_disk.sort();
        let mut listed: Vec<String> = entries.iter().map(|e| e.file.clone()).collect();
        listed.sort();
        assert_eq!(
            on_disk, listed,
            "files on disk vs. files in the README table"
        );

        let failures: Vec<String> = entries
            .iter()
            .filter_map(|entry| {
                let path = format!("{DIR}/{}", entry.file);
                let bytes =
                    std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
                verify_entry(entry, &bytes).err()
            })
            .collect();
        assert!(
            failures.is_empty(),
            "checksum mismatches:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn a_one_byte_change_fails_the_checksum() {
        let entries = manifest();
        let entry = entries
            .iter()
            .find(|e| e.file == "hmac_sha256_test.json")
            .unwrap_or_else(|| panic!("hmac_sha256_test.json is not in the README"));
        let mut bytes = std::fs::read(format!("{DIR}/{}", entry.file)).unwrap_or_default();
        assert_eq!(verify_entry(entry, &bytes), Ok(()));
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x01;
        let err = verify_entry(entry, &bytes).err().unwrap_or_default();
        assert!(err.contains("SHA-256"), "{err}");
        bytes.push(b'\n');
        let err = verify_entry(entry, &bytes).err().unwrap_or_default();
        assert!(err.contains("bytes"), "{err}");
    }

    #[test]
    fn manifest_rows_are_strict() {
        let good = "| `a.json` | 3 | `".to_owned() + &"0".repeat(64) + "` |";
        assert_eq!(parse_manifest(&good).map(|e| e[0].size), Ok(3));
        for bad in [
            "| `a.json` | x | `".to_owned() + &"0".repeat(64) + "` |",
            "| `a.json` | 3 | `".to_owned() + &"A".repeat(64) + "` |",
            "| `a.json` | 3 | `".to_owned() + &"0".repeat(63) + "` |",
            "| `a.json` | 3 |".to_owned(),
            format!("{good}\n{good}"),
            String::new(),
        ] {
            assert!(parse_manifest(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }
}
