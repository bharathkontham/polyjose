//! Strict DER (ITU-T X.690 §8, §10, §11) for exactly the tags the key
//! structures use: INTEGER, BIT STRING, OCTET STRING, NULL, OBJECT IDENTIFIER,
//! SEQUENCE, and the context tags `[0]`/`[1]` in their explicit (0xA0/0xA1) and
//! implicit primitive (0x81) forms (ADR 0018 §1).
//!
//! Definite lengths in the fewest octets (X.690 §10.1, §8.1.3), minimal
//! INTEGERs (§8.3.2), primitive strings only (§10.2), minimal OID
//! subidentifiers (§8.19.2), low-tag-number form only (§8.1.2.4) and no data
//! after the outermost element (§8.1.1). BER is rejected (ADR 0018 §2).
//!
//! Filled in by task T02 of the keys feature.
