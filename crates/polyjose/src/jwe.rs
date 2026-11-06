//! JSON Web Encryption (RFC 7516).

// The internal modules below are wired together by the JWE tasks of
// feature 0003; until the pipeline (T09) calls them, most of their items
// have no caller. `allow`, not `expect`: each task fills in its own file
// and must not edit this one, and an `expect` would become an error as
// soon as everything is used. Remove these attributes once the feature's
// last task (T16) has landed.
#[allow(
    dead_code,
    reason = "the JWE skeleton (0003 T01): called once the pipeline (T09) lands"
)]
mod random;
