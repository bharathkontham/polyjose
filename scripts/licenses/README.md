# Standard license texts

`scripts/third-party-notices.sh` embeds one of these files for a crate that ships **no** license
file of its own and whose `license` expression is exactly that one license (ADR 0020 §4). A crate
that ships its own `LICENSE*`, `COPYING*` or `NOTICE*` files always gets those instead.

| File | License | Source (unmodified) | MD5 |
|---|---|---|---|
| `MIT.txt` | `MIT` | the MIT text of polyjose's own `LICENSE`, without its copyright line (the notices file names the crate's authors in its place) | `7ae2be7fb1637141840314b51970a9f7` |
| `Apache-2.0.txt` | `Apache-2.0` | <https://www.apache.org/licenses/LICENSE-2.0.txt> | `3b83ef96387f14655fc854ddc3c6bd57` |
| `MPL-2.0.txt` | `MPL-2.0` | <https://www.mozilla.org/media/MPL/2.0/index.txt> | `f75d2927d3c1ed2414ef72048f5ad640` |

The texts are the licenses themselves, not code: never edit them. MPL-2.0 is here because UniFFI
(`uniffi`, `uniffi_core`, …), which the Kotlin and Swift bindings link, is MPL-2.0 and ships no
license file in its crates; `deny.toml` allows MPL-2.0 for the same reason.
